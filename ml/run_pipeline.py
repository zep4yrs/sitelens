"""5.0 ML 全流水线编排（P1-P10 一条命令，可重复执行）。

用法：
  python -m ml.run_pipeline --data-root <主仓 data/> \
      --out-root <本仓 data/ml> --matrix-dir <tmp_matrix_out>

步骤：Dataset → Feature → Label → Leakage Check → Split 检查 → 数据 gate
      → Baseline → Training（gate 放行任务）→ Evaluation → Explain/Calibration
      → Model Versioning。产物全部落 data/ml/（git 忽略），报告/manifest 可入仓。
"""

from __future__ import annotations

import argparse
import json

import pandas as pd

from . import (
    baselines, config, dataset, explain, features, labels, leakage,
    manifest, quality, registry, splits, train,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="SiteLens 5.0 ML pipeline (P1-P10)")
    ap.add_argument("--data-root", default=None)
    ap.add_argument("--out-root", default=None)
    ap.add_argument("--matrix-dir", default=None)
    ap.add_argument("--seed", type=int, default=20260914)
    args = ap.parse_args()

    paths = config.resolve_paths(args.data_root, args.out_root, args.matrix_dir)
    out_metrics = paths.out_root / "metrics"
    out_metrics.mkdir(parents=True, exist_ok=True)

    # ---- P2 Dataset ----
    tables, stats, inputs = dataset.build_tables(paths)
    ds_manifest = dataset.write_dataset(paths, tables, stats, inputs)
    scans = tables["scans"]
    print(f"[P2] dataset: scans={len(scans)} hosts={stats['hosts']} "
          f"intel={stats['counts']['intel']} verified={stats['counts']['verified']} "
          f"candidates={stats['counts']['candidates']}")

    # ---- P3 Feature ----
    scan_feat, scan_cols = features.build_scan_features(
        scans, tables["techs"], tables["verified"], tables["intel"])
    intel_base = tables["intel"]
    l3_df, l3_pole = labels.build_l3(intel_base)
    intel_feat, intel_cols = features.build_intel_features(
        intel_base, tables["cve_features"])
    # sanity 标签按行索引对齐并入（避免键合并造成行扇出）
    intel_feat = intel_feat.join(l3_df[["label"]])
    cand_feat, cand_cols = features.build_candidate_features(
        tables["candidates"], tables["verified"], scans)
    print(f"[P3] features: scan={len(scan_cols)} intel={len(intel_cols)} "
          f"candidate={len(cand_cols)}")

    # ---- P4 Label ----
    l1_rows, l1_pole = labels.build_l1(tables["verified"], tables["candidates"])
    l5 = labels.build_l5(tables["verified"])
    print(f"[P4] L1 positive={l1_pole['counts']['positive']} "
          f"unknown={l1_pole['counts']['unknown']} negative={l1_pole['negative_count']}; "
          f"L3 rows={len(l3_df)}; L5={l5['status']}")

    # ---- P5 Leakage / Data Quality / gate ----
    for cols in (scan_cols, intel_cols, cand_cols):
        features.check_blacklist(cols)
    inj = leakage.assert_asof_injection(
        scans, tables["verified"], tables["intel"], [],
        prior_cols=["prior_scan_count", "prior_verified_count",
                    "prior_intel_count", "prior_sec_score_last"])
    ub = leakage.assert_prior_upper_bound(scan_feat)
    equiv = splits.split_equivalence_report(scans)
    leak_report = {
        "blacklist": leakage.leakage_report({}, {
            "scan_features": scan_cols, "intel_features": intel_cols,
            "candidate_features": cand_cols}),
        "asof_injection": inj,
        "prior_upper_bound": ub,
        "split_equivalence": equiv,
    }
    (out_metrics / "leakage_report.json").write_text(
        json.dumps(leak_report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    qrep = quality.quality_report(scans, tables["techs"], tables["intel"],
                                  tables["verified"], tables["candidates"])
    (out_metrics / "data_quality_report.json").write_text(
        json.dumps(qrep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    grep_ = quality.gate_report(scans, tables["intel"], tables["verified"],
                                tables["candidates"])
    (out_metrics / "gate_report.json").write_text(
        json.dumps(grep_, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"[P5] leakage passed={leak_report['blacklist']['passed'] and inj['passed']} "
          f"| equivalence: {equiv['conclusion'][:30]}…")

    # ---- P6 Baseline（T2 候选排序）----
    base_rep = baselines.evaluate_baselines(cand_feat, tables["verified"])
    (out_metrics / "baseline_report.json").write_text(
        json.dumps(base_rep, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    print(f"[P6] baseline queries={base_rep['queries_detail']['n_queries']} "
          f"positives={base_rep['queries_detail']['positives_total']} "
          f"rule_based P@5={base_rep['rule_based'].get('P@5')}")

    # ---- P7/P8 训练与评估（gate 放行：L3 sanity + T3 sanity）----
    s1 = train.train_s1_l3_sanity(intel_feat, intel_cols, seed=args.seed)
    s2 = train.train_s2_score_sanity(scan_feat, scan_cols, seed=args.seed)

    # ---- P9 Explain / Calibration ----
    oof = s1.pop("_oof")
    s1_models = s1.pop("_models")
    s2.pop("_oof")
    s2_models = s2.pop("_models")
    lr_oof = oof.dropna(subset=["logistic_regression"])
    calib = explain.calibrate_verdict(
        lr_oof["y"].to_numpy(), lr_oof["logistic_regression"].to_numpy(),
        auc=s1["logistic_regression"]["roc_auc"])
    # 逐样本解释（OOF 折内模型近似说明：用全量重拟合模型解释真实样本行）
    sample_entries = []
    lr_model = s1_models["logistic_regression"]
    lin = lr_model.named_steps["logisticregression"]
    scaler = lr_model.named_steps["standardscaler"]
    Xs = scaler.transform(intel_feat[intel_cols].astype(float))
    coef = lin.coef_[0]
    for i in range(min(3, len(intel_feat))):
        row = intel_feat.iloc[i]
        z = pd.Series(Xs[i], index=intel_cols)
        tops = [{"feature": n, "contribution": round(float(c * z[n]), 4)}
                for n, c in zip(intel_cols, coef)]
        tops.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        sample_entries.append(explain.prediction_entry(
            "S1-L3-sanity", float(lin.decision_function(Xs[i:i+1])[0]),
            None, tops[:5], calibrated=False))
    calib_report = {
        "logistic_regression_OOF": calib,
        "decision": "probability=null（校准不可靠）" if calib["verdict"] != "reliable"
        else "probability=允许输出",
        "confidence": "第一阶段恒 null",
        "sample_predictions": sample_entries,
    }
    (out_metrics / "calibration_report.json").write_text(
        json.dumps(calib_report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    print(f"[P9] calibration={calib['verdict']} (n={calib['n']}, "
          f"brier={calib.get('brier')})")

    # ---- P10 Model Versioning ----
    exp_specs = [
        ("EXP-0001", "S1-L3-sanity", "logistic_regression",
         {"C": 1.0, "class_weight": "balanced"}, s1["logistic_regression"],
         l3_pole),
        ("EXP-0002", "S1-L3-sanity", "gradient_boosting",
         {"n_estimators": 150, "max_depth": 2}, s1_models["gradient_boosting"], l3_pole),
        ("EXP-0003", "S2-score-sanity", "ridge", {"alpha": 1.0},
         s2_models["ridge"], None),
        ("EXP-0004", "S2-score-sanity", "gradient_boosting",
         {"n_estimators": 150, "max_depth": 2}, s2_models["gradient_boosting"], None),
    ]
    upstream = [ds_manifest]
    for exp_id, task, mname, params, model, pole in exp_specs:
        met = {"S1": s1, "S2": s2}[task.split("-")[0]]
        metrics_task = {k: v for k, v in met.items() if not k.startswith("_")}
        registry.create_experiment(
            paths.out_root, exp_id, task, mname, params,
            {"task_metrics": metrics_task, "gate": grep_},
            model, intel_cols if task.startswith("S1") else scan_cols,
            upstream, gate_note="gate 放行任务（sanity）；T1/T2 训练 BLOCKED 见 gate_report",
            repo_dir=paths.out_root.parent.parent)
        registry.append_summary(paths.out_root, {
            "exp_id": exp_id, "task": task, "model": mname,
            "dataset_version": "ds-5.0.0", "git_rev": manifest.git_rev(),
        })
    # 注册表自检
    exp_dirs = sorted((paths.out_root / "experiments").glob("EXP-*"))
    ver = [registry.verify_experiment(d) for d in exp_dirs]
    ok = all(v["ok"] for v in ver)
    print(f"[P10] experiments={len(exp_dirs)} registry_ok={ok}")

    # ---- 汇总报告（真实数字，供最终输出引用）----
    summary = {
        "dataset": {"counts": stats["counts"], "hosts": stats["hosts"],
                    "era": stats["era"],
                    "manifest": str(ds_manifest)},
        "labels": {"L1": l1_pole["counts"], "L1_negative": l1_pole["negative_count"],
                   "L3_rows": len(l3_df), "L5": l5["status"]},
        "features": {"scan": len(scan_cols), "intel": len(intel_cols),
                     "candidate": len(cand_cols)},
        "leakage": {"asof_injection": inj["passed"],
                    "prior_upper_bound": ub["passed"],
                    "blacklist": leak_report["blacklist"]["passed"]},
        "split_equivalence": equiv,
        "gate": grep_,
        "baselines": {k: v for k, v in base_rep.items()
                      if k in ("severity", "rule_based", "prior_hits", "random",
                               "queries_detail")},
        "S1": {k: v for k, v in s1.items() if not k.startswith("_")},
        "S2": {k: v for k, v in s2.items() if not k.startswith("_")},
        "calibration": calib,
        "experiments": [v["experiment"] for v in ver],
        "registry_ok": ok,
    }
    (out_metrics / "pipeline_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    print("[DONE] summary ->", out_metrics / "pipeline_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
