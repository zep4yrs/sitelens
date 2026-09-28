"""T1/T2 首次监督训练（EXP-1101/1102）——执行日志解锁后的第一批真实标签。

数据：本机靶场 farm 扫描（build/farm-state/state/history.json，引擎
check_runs 执行日志），经 build_from_records 原样构表（origin=matrix，
可复现、不入 git）。

EXP-1101（T1 验证目标优先级）：内置 check 候选 × 扫描，标签=check_runs
  executed∧hit / executed∧未命中；特征=候选四特征（sev/lv/cms/prior）；
  模型 LR + HistGB；LOHO 按宿主切分（单类折如实记 skipped）。
EXP-1102（T2 候选排序）：同一特征的模型分 vs 规则基线（severity/rule/
  prior/random，同 baselines.evaluate_baselines 协议）。

纪律：样本量如实报告；正例稀疏时明确"管线实证、非能力声明"；unknown/
not_executed 绝不作负样本。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score

from . import baselines, config, dataset, features, labels, manifest, metrics


def load_farm_records(farm_history: Path) -> list[dict]:
    raw = json.loads(farm_history.read_text(encoding="utf-8"))
    recs = raw["scans"] if isinstance(raw, dict) else raw
    out = []
    for r in recs:
        if not isinstance(r, dict) or not isinstance(r.get("result"), dict):
            continue
        if not (r["result"].get("check_runs")):
            continue  # 无执行日志的记录不进本实验（如实跳过）
        r = dict(r)
        r["origin"] = config.ORIGIN_MATRIX
        r["scan_uid"] = f"{config.ORIGIN_MATRIX}:{r.get('id')}:farm"
        out.append(r)
    return out


def _labeled_rows(tables: dict[str, pd.DataFrame]) -> tuple[pd.DataFrame, list[str]]:
    """executed 执行行 × 候选特征 → 监督样本（label=hit）。"""
    cand_feat, _ = features.build_candidate_features(
        tables["candidates"], tables["verified"], tables["scans"])
    ex = tables["executions"]
    ex = ex[ex["execution_status"] == config.EXEC_EXECUTED]
    feat_cols = ["check_lv", "sev_ord", "cms_linked_flag", "prior_hits_this_check"]
    key = cand_feat.set_index(["scan_uid", "check_id"])
    rows = []
    for _, e in ex.iterrows():
        k = (e["scan_uid"], e["check_id"])
        if k not in key.index:
            continue  # 非 builtin 候选（如 nuclei 模板）：不在 T1 宇宙，如实排除
        f = key.loc[k]
        if isinstance(f, pd.DataFrame):  # 同键多行取首（候选构造按 scan×check 唯一）
            f = f.iloc[0]
        rows.append({**{c: f[c] for c in feat_cols},
                     "scan_uid": e["scan_uid"], "host": e["host"],
                     "check_id": e["check_id"], "label": int(bool(e["hit"]))})
    return pd.DataFrame(rows), feat_cols


def _loho_rows(rows: pd.DataFrame, feat_cols: list[str], models: dict):
    """留一分组切分：宿主可分时按 host（LOHO）；靶场同 IP 多目标时退化为
    按目标（scan_uid，LOS-targetO）——与 5.0 host/target 等价性结论一致。
    单类折如实记 skipped。返回 pooled 预测与折记录。"""
    group_col = "host" if rows["host"].nunique() > 1 else "scan_uid"
    split_name = ("LOHO 留一宿主" if group_col == "host"
                  else "留一目标（同 host 多端口靶场，退化为 scan_uid 分组）")
    pooled = []
    folds = []
    for h in rows[group_col].unique().tolist():
        tr, te = rows[rows[group_col] != h], rows[rows[group_col] == h]
        if tr["label"].nunique() < 2:
            folds.append({"heldout": str(h), "status": "skipped",
                          "reason": "训练折单类（正例不足）"})
            continue
        for name, mdl in models.items():
            mdl.fit(tr[feat_cols], tr["label"])
            p = mdl.predict(te[feat_cols])
            try:
                s = mdl.predict_proba(te[feat_cols])[:, 1]
            except Exception:
                s = p
            for (uid, cid, y, score, pred) in zip(
                    te["scan_uid"], te["check_id"], te["label"], s, p):
                pooled.append({"group": str(h), "scan_uid": uid, "check_id": cid,
                               "y": int(y), "score": float(score),
                               "pred": int(pred), "model": name})
            folds.append({"heldout": str(h), "model": name,
                          "rows": int(len(te)),
                          "positives": int(te["label"].sum())})
    return pd.DataFrame(pooled), folds, split_name


def _cls_metrics(pooled: pd.DataFrame, name: str) -> dict:
    if not len(pooled) or "model" not in pooled.columns:
        return {"model": name, "status": "insufficient_labels",
                "rows": 0, "positives": 0,
                "note": "LOHO 全折跳过（训练折正例不足）——如实记录，不造指标"}
    g = pooled[pooled["model"] == name]
    if not len(g) or g["y"].nunique() < 2:
        return {"model": name, "status": "insufficient_labels",
                "rows": int(len(g)), "positives": int(g["y"].sum()),
                "note": "留出集正例不足，指标不可定义"}
    out = {"model": name, "rows": int(len(g)),
           "positives": int(g["y"].sum()),
           "accuracy": round(float((g["pred"] == g["y"]).mean()), 4),
           "f1_positive": round(float(f1_score(g["y"], g["pred"], zero_division=0)), 4)}
    if g["score"].nunique() > 1:
        out["roc_auc"] = round(float(roc_auc_score(g["y"], g["score"])), 4)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--farm-history",
                    default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\build\farm-state\state\history.json")
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--out-root", default=None)
    ap.add_argument("--seed", type=int, default=20260928)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    farm_records = load_farm_records(Path(args.farm_history))
    catalog = dataset.load_catalog()
    tables, stats = dataset.build_from_records(farm_records, catalog)
    rows, feat_cols = _labeled_rows(tables)
    if not len(rows):
        print("[EXP-1101] 无 executed 监督样本（check_runs 缺失？）——如实退出")
        return 1
    pos, neg = int(rows["label"].sum()), int((1 - rows["label"]).sum())
    print(f"[data] farm scans={len(farm_records)} rows={len(rows)} "
          f"positive={pos} negative={neg}")

    l1_rows, l1_pole = labels.build_l1(
        tables["verified"], tables["candidates"], tables["executions"])

    models = {
        "logistic_regression": LogisticRegression(
            max_iter=500, class_weight="balanced", random_state=args.seed),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=150, random_state=args.seed),
    }
    pooled, folds, split_name = _loho_rows(rows, feat_cols, models)
    skipped = [f for f in folds if f.get("status") == "skipped"]
    exp1101 = {
        "task": "T1 验证目标优先级（首次监督训练：check_runs 执行日志标签）",
        "data": {"farm_scans": len(farm_records), "rows": int(len(rows)),
                 "positive": pos, "negative": neg,
                 "universe": "内置 check 候选（catalog join）；nuclei 模板行如实排除"},
        "split": split_name + "；单类折 skipped 如实记录",
        "skipped_folds": skipped,
        "models": {m: _cls_metrics(pooled, m) for m in models},
        "label_provenance": {**l1_pole,
                             "note": "标签=check_runs 执行证据；靶场数据正例天然稀疏"
                                     "（内置 check 探部署卫生项），首批为管线实证"
                                     "而非能力声明"},
    }

    # ---- EXP-1102：模型分 vs 规则基线（同协议排序评估）----
    cand_feat, _ = features.build_candidate_features(
        tables["candidates"], tables["verified"], tables["scans"])
    pos_frame = tables["verified"]
    base_rep = baselines.evaluate_baselines(cand_feat, pos_frame) \
        if len(cand_feat) else {}
    rank_cmp = {}
    if len(pooled):
        lr_pooled = pooled[pooled["model"] == "logistic_regression"]
        by_query: dict[str, list[tuple[float, str]]] = {}
        for _, r in lr_pooled.iterrows():
            by_query.setdefault(r["scan_uid"], []).append((r["score"], r["check_id"]))
        ranked = {uid: [c for _, c in sorted(v, key=lambda t: (-t[0], t[1]))]
                  for uid, v in by_query.items()}
        pos_keys = set(zip(pos_frame[pos_frame["src"] == "check"]["scan_uid"],
                           pos_frame[pos_frame["src"] == "check"]["check"])) \
            if len(pos_frame) else set()
        rel = {}
        for uid, cid in pos_keys:
            if uid in ranked:
                rel.setdefault(uid, set()).add(cid)
        rel = {u: s for u, s in rel.items() if s & set(ranked[u])}
        if rel:
            rank_cmp["model_lr"] = metrics.eval_ranking(ranked, rel, ks=(5, 10))
            rank_cmp["note"] = ("查询/正例数见各 verdict；首批数据正例极少，"
                                "排序数字仅作管线实证")

    exp1102 = {"task": "T2 候选排序（模型分 vs 规则基线，同 evaluate_baselines 协议）",
               "baselines": {k: base_rep[k] for k in
                             ("severity", "rule_based", "prior_hits", "random")
                             if k in base_rep},
               "queries_detail": base_rep.get("queries_detail", {}),
               "model_ranking": rank_cmp}

    # ---- 持久化 + 登记 ----
    out_metrics = paths.out_root / "metrics"
    for name, rep in (("EXP-1101-T1-supervised", exp1101),
                      ("EXP-1102-T2-supervised-ranking", exp1102)):
        (out_metrics / f"{name}.json").write_text(
            json.dumps(rep, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8")

    d = paths.out_root / "experiments" / "EXP-1101-T1-supervised-model"
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump({"models": models, "feat_cols": feat_cols,
                 "rows": int(len(rows)), "positive": pos, "negative": neg},
                d / "model.joblib")
    man = manifest.make_manifest(
        kind="model", version="EXP-1101-T1-supervised-model",
        inputs=[manifest.file_input(d / "model.joblib", role="output:model"),
                manifest.file_input(Path(args.farm_history), role="source:farm_history")],
        params={"task": "T1", "seed": args.seed, "split": "LOHO"},
        producer="ml/train_supervised.py",
        scope={"data_version": "exec-log-5.0"},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    summary = out_metrics / "summary.jsonl"
    with open(summary, "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": "EXP-1101-T1-supervised-model",
                            "task": "T1 首次监督训练（执行日志标签）",
                            "data_version": "exec-log-5.0",
                            "git_rev": manifest.git_rev()}) + "\n")
        f.write(json.dumps({"exp_id": "EXP-1102-T2-supervised-ranking",
                            "task": "T2 首次监督排序对比",
                            "data_version": "exec-log-5.0",
                            "git_rev": manifest.git_rev()}) + "\n")

    print(json.dumps({"EXP-1101": exp1101["models"],
                      "skipped_folds": len(skipped),
                      "rows": len(rows), "positive": pos, "negative": neg},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
