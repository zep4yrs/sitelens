"""学习阶段实验（主仓库大规模知识数据）。

EXP-1001  CVE 严重度学习（NVD 291k 有标签 CVE；TF-IDF 文本 + LR/SGD；
          时间切分 train=pub<2024 / test>=2024；跨源验证=cve_ms、CVSS 分带）
EXP-1002  CVE→受影响产品/技术 关系预测（top-200 产品类，OvR 排序，
          时间切分，P@5/P@10/MRR；对 SiteLens 技术名的覆盖率报告）
EXP-1003  模板命中先验（216 条历史 nuclei 命中 → yaml id → 模板特征 lift
          分析；label_type=ranking_signal，来源=真实扫描历史）

每个实验落 metrics + manifest（kind=experiment），样本级字段含
source/source_type/label_type/label_confidence/sample_id/data_version。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.multiclass import OneVsRestClassifier
from sklearn.naive_bayes import MultinomialNB

from . import config, dataset, knowledge, manifest

DATA_VERSION = "kb-5.0.0"
MS_SEV_MAP = {"critical": "critical", "important": "medium",
              "moderate": "medium", "low": "low"}


def _cvss_band(score: float) -> str | None:
    if score is None or (isinstance(score, float) and np.isnan(score)):
        return None
    s = float(score)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s >= 0.1:
        return "low"
    return "none"


def _save(paths: config.Paths, name: str, payload: dict,
          upstream: list[Path], params: dict) -> Path:
    out = paths.out_root / "metrics" / f"{name}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    man = manifest.make_manifest(
        kind="experiment", version=name,
        inputs=[manifest.file_input(p, role="upstream") for p in upstream]
               + [manifest.file_input(out, role="output")],
        params=params, producer="ml/train_kb.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, paths.out_root / "metrics" / f"{name}_MANIFEST.json")
    return out


def _year_split(df: pd.DataFrame, cut: str = "2024-01-01"):
    t = pd.to_datetime(df["pub"], errors="coerce")
    return df[t < cut], df[t >= cut]


def exp1001_severity(kb: dict[str, pd.DataFrame], paths: config.Paths,
                     seed: int = 20260914) -> dict:
    """K1：CVE 严重度分类（文本 → 四类），时间切分 + 双跨源验证 + 消融。"""
    cve = kb["kb_cve"].dropna(subset=["sev"])
    cve = cve[cve["sev"].isin(["critical", "high", "medium", "low"])].copy()
    cve["sample_id"] = cve["cve"]
    cve["source"], cve["source_type"] = "nvd", "supervised"
    cve["label_type"], cve["label_confidence"] = "severity", "high"
    cve["data_version"] = DATA_VERSION
    train, test = _year_split(cve)

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                          sublinear_tf=True)
    Xtr = vec.fit_transform(train["descr"])
    Xte = vec.transform(test["descr"])
    ytr, yte = train["sev"].to_numpy(), test["sev"].to_numpy()

    models = {
        "logistic_regression_sgd": SGDClassifier(loss="log_loss", alpha=1e-6,
                                                 max_iter=30, class_weight="balanced",
                                                 random_state=seed),
        "multinomial_nb": MultinomialNB(),
    }
    res: dict = {"task": "K1 CVE severity classification",
                 "train_rows": int(len(train)), "test_rows": int(len(test)),
                 "split": "train pub<2024-01-01 / test>=2024-01-01",
                 "train_dist": {k: int(v) for k, v in pd.Series(ytr).value_counts().items()},
                 "test_dist": {k: int(v) for k, v in pd.Series(yte).value_counts().items()},
                 "models": {}, "label_provenance": {
                     "source": "NVD base severity (update-nvd 镜像)",
                     "label_type": "supervised", "label_confidence": "high"}}
    preds = {}
    for name, mdl in models.items():
        mdl.fit(Xtr, ytr)
        pred = mdl.predict(Xte)
        preds[name] = (mdl, pred)
        rep = classification_report(yte, pred, output_dict=True, zero_division=0)
        res["models"][name] = {
            "accuracy": round(float((pred == yte).mean()), 4),
            "macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
            "per_class_f1": {k: round(float(v["f1-score"]), 4)
                             for k, v in rep.items() if k in
                             ("critical", "high", "medium", "low")},
        }
        if hasattr(mdl, "predict_proba"):
            proba = mdl.predict_proba(Xte)
            classes = mdl.classes_
            auc_rows, auc_classes = [], []
            for i, c in enumerate(classes):
                mask = np.isin(yte, [c])
                others = yte != c
                bin_y = (yte == c).astype(int)
                if bin_y.sum() > 0 and (1 - bin_y).sum() > 0:
                    auc_rows.append(roc_auc_score(bin_y, proba[:, i]))
                    auc_classes.append(c)
            res["models"][name]["roc_auc_ovr"] = {
                c: round(float(a), 4) for c, a in zip(auc_classes, auc_rows)}

    # 消融：仅元数据（年份/描述长度/产品数）——HistGB，无文本
    meta_cols = ["descr_len", "n_prods"]
    tr_year = pd.to_datetime(train["pub"], errors="coerce").dt.year.fillna(0)
    te_year = pd.to_datetime(test["pub"], errors="coerce").dt.year.fillna(0)
    Xmtr = np.column_stack([tr_year, train[meta_cols].to_numpy()])
    Xmte = np.column_stack([te_year, test[meta_cols].to_numpy()])
    hgb = HistGradientBoostingClassifier(max_iter=200, random_state=seed)
    hgb.fit(Xmtr, ytr)
    predm = hgb.predict(Xmte)
    res["models"]["histgb_metadata_only"] = {
        "accuracy": round(float((predm == yte).mean()), 4),
        "macro_f1": round(float(f1_score(yte, predm, average="macro")), 4),
        "ablation_note": "仅元数据（无文本）：证明文本承载主要信号",
    }

    # 跨源验证 1：cve_ms（微软公告，独立来源）
    intel_dump = _load_dump_tables(paths)
    cms = intel_dump.get("cve_ms")
    cve_descr = cve[["cve", "descr"]].rename(columns={"descr": "cve_descr"})
    if cms:
        cms_df = pd.DataFrame(cms)
        cms_df = cms_df[cms_df["severity"].notna()]
        cms_df["sev_ms"] = cms_df["severity"].str.strip().str.lower().map(MS_SEV_MAP)
        cms_df = cms_df.dropna(subset=["sev_ms"])
        j = cms_df[["cve", "sev_ms"]].drop_duplicates("cve").merge(
            cve_descr, on="cve", how="inner")
        if len(j):
            Xj = vec.transform(j["cve_descr"])
            predj = models["logistic_regression_sgd"].predict(Xj)
            res["cross_source_cve_ms"] = {
                "rows": int(len(j)),
                "agreement": round(float((predj == j["sev_ms"].to_numpy()).mean()), 4),
                "note": "模型只在 NVD 上训练；对微软公告严重度的一致率"}

    # 跨源验证 2：vuln_kb（CVSS 分带为规则标签）
    vkb = intel_dump.get("vuln_kb")
    if vkb:
        vdf = pd.DataFrame(vkb)
        vdf = vdf[vdf["cvss_score"].notna()]
        vdf["sev_band"] = vdf["cvss_score"].map(_cvss_band)
        vdf = vdf[vdf["sev_band"].isin(["critical", "high", "medium", "low"])]
        vdf["cve"] = vdf["cve"].fillna("").str.upper()
        j2 = vdf[vdf["cve"] != ""][["cve", "sev_band"]].drop_duplicates("cve").merge(
            cve_descr, on="cve", how="inner")
        if len(j2):
            Xj2 = vec.transform(j2["cve_descr"])
            predj2 = models["logistic_regression_sgd"].predict(Xj2)
            res["cross_source_vulnkb_cvss_band"] = {
                "rows": int(len(j2)),
                "agreement": round(float((predj2 == j2["sev_band"].to_numpy()).mean()), 4),
                "note": "对 vuln_kb 的 CVSS 分带（0.1-3.9/4-6.9/7-8.9/9-10 规则）一致率"}

    res["feature_ablation_conclusion"] = (
        "text vs metadata-only 的准确率差即文本信号的实证；"
        "两者差异见 models 各条目")
    res["_art"] = {"vectorizer": vec, "model": models["logistic_regression_sgd"],
                   "classes": list(models["logistic_regression_sgd"].classes_),
                   "feature": "tfidf(descr) word 1-2gram"}
    return res


def _load_dump_tables(paths: config.Paths) -> dict:
    import gzip
    p = paths.intel_dump
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return json.load(f)["tables"]


def exp1002_product_relation(kb: dict[str, pd.DataFrame], paths: config.Paths,
                             seed: int = 20260914, top_n: int = 200) -> dict:
    """K2：新 CVE → 受影响产品/技术 Top-K 关系预测（时间切分，P@5/P@10/MRR）。"""
    edges = kb["kb_cve_product"].copy()
    edges["vendor_product"] = edges["vendor"] + "/" + edges["product"]
    stats = kb["kb_product_stats"]
    classes = stats.head(top_n)["vendor_product"].tolist()
    class_set = set(classes)
    e = edges[edges["vendor_product"].isin(class_set)].copy()
    cve_descr = kb["kb_cve"].set_index("cve")["descr"]
    e["descr"] = e["cve"].map(cve_descr)
    e = e.dropna(subset=["descr"])
    e["pub"] = e["cve"].map(kb["kb_cve"].set_index("cve")["pub"])
    e = e.dropna(subset=["pub"])
    train = e[pd.to_datetime(e["pub"]) < pd.Timestamp("2024-01-01")]
    test = e[pd.to_datetime(e["pub"]) >= pd.Timestamp("2024-01-01")]

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                          sublinear_tf=True)
    # 训练样本：类内去重（同 cve 同类一条）；多类 CVE 在 OvR 中天然处理
    tr = train.drop_duplicates(subset=["cve", "vendor_product"])
    Xtr = vec.fit_transform(tr["descr"])
    ytr = tr["vendor_product"].to_numpy()
    clf = OneVsRestClassifier(
        SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=20,
                      random_state=seed), n_jobs=8)
    clf.fit(Xtr, ytr)
    proba = clf.predict_proba(Xtr)  # 仅为对齐 classes

    # 测试：每个 CVE 的真实类集合（可能多个）
    te_groups = test.groupby("cve").agg(
        true_set=("vendor_product", lambda s: set(s)),
        descr=("descr", "first"), pub=("pub", "first")).reset_index()
    Xte = vec.transform(te_groups["descr"])
    pr = clf.predict_proba(Xte)
    order = np.argsort(-pr, axis=1)
    classes_arr = np.array(clf.classes_)

    def pk(k):
        hits = 0
        for i, ts in enumerate(te_groups["true_set"]):
            top = set(classes_arr[order[i][:k]].tolist())
            if top & ts:
                hits += 1
        return round(hits / max(1, len(te_groups)), 4)

    def mrr():
        total = 0.0
        for i, ts in enumerate(te_groups["true_set"]):
            top = classes_arr[order[i]].tolist()
            for rank, c in enumerate(top, start=1):
                if c in ts:
                    total += 1.0 / rank
                    break
        return round(total / max(1, len(te_groups)), 4)

    # 技术覆盖率：类名与 SiteLens 技术名（小写归一）的交集
    techs = dataset.build_tech_catalog(paths)
    tech_names = {n.lower() for n in techs["name"]} if len(techs) else set()
    covered = [c for c in classes if c.split("/", 1)[1].replace("_", " ") in tech_names
               or c.split("/", 1)[1] in tech_names]

    res = {
        "task": "K2 CVE→product/technology relation prediction",
        "n_classes": len(classes), "train_edges": int(len(train)),
        "test_cves": int(len(te_groups)),
        "split": "train pub<2024 / test>=2024",
        "P@5": pk(5), "P@10": pk(10), "MRR": mrr(),
        "random_P@5": round(5 / len(classes), 4),
        "classes_matching_sitelens_techs": len(covered),
        "classes_sample": classes[:15],
        "label_provenance": {
            "source": "NVD CPE product constraints (vendor/product)",
            "label_type": "weak / relation", "label_confidence": "medium",
            "note": "类=高频产品；新 CVE 的产品预测=关系学习，不是监督攻击标签"},
        "_art": {"vectorizer": vec, "clf": clf, "classes": list(clf.classes_),
                 "feature": "tfidf(descr) word 1-2gram"},
    }
    return res


def exp1003_template_prior(paths: config.Paths, kb: dict[str, pd.DataFrame],
                           verified: pd.DataFrame) -> dict:
    """T2 模板级先验：历史 nuclei 命中 → check id → yaml id → 模板特征 lift。"""
    nv = verified[verified["src"] == "nuclei"].copy() if len(verified) else verified
    tpl = kb["kb_template"]
    hit_ids = []
    for chk in nv["check"]:
        cid = str(chk)
        if cid.startswith("nuclei-"):
            yid = cid[len("nuclei-"):].split("~")[0]
            hit_ids.append(yid)
    hits = Counter_t(hit_ids)
    tpl["hits"] = tpl["yaml_id"].map(hits).fillna(0).astype(int)
    hit_rows = tpl[tpl["hits"] > 0]
    overall = float((tpl["hits"] > 0).mean())
    lift_by_sev = {}
    for sev, g in tpl.groupby("sev_norm"):
        rate = float((g["hits"] > 0).mean())
        lift_by_sev[str(sev)] = {"n_templates": int(len(g)),
                                 "hit_templates": int((g["hits"] > 0).sum()),
                                 "hit_rate": round(rate, 6),
                                 "lift": round(rate / overall, 3) if overall else None}
    lift_by_source = {}
    for src, g in tpl.groupby("source"):
        rate = float((g["hits"] > 0).mean())
        lift_by_source[src] = {"n_templates": int(len(g)),
                               "hit_templates": int((g["hits"] > 0).sum()),
                               "hit_rate": round(rate, 6),
                               "lift": round(rate / overall, 3) if overall else None}
    return {
        "task": "T2 template-level ranking prior（弱信号）",
        "history_nuclei_hit_rows": int(len(nv)),
        "distinct_hit_yaml_ids": len(hits),
        "templates_matched": int(len(hit_rows)),
        "corpus_hit_rate": round(overall, 6),
        "lift_by_severity": lift_by_sev,
        "lift_by_source": lift_by_source,
        "top_hit_templates": hit_rows.sort_values("hits", ascending=False)
        .head(20)[["yaml_id", "name", "sev_norm", "source", "n_cves", "hits"]]
        .to_dict("records"),
        "label_provenance": {
            "source": "119 次真实扫描的 nuclei verified 命中",
            "label_type": "ranking_signal / weak",
            "label_confidence": "low（正例少、候选宇宙不含未执行信息）"},
    }


def Counter_t(items):
    from collections import Counter
    return Counter(items)


def _persist_model(paths: config.Paths, exp_name: str, art: dict,
                   upstream: list[Path], task: str, feature_note: str) -> Path:
    """按 P10 纪律持久化模型 + EXPERIMENT manifest + summary 登记。"""
    import joblib

    d = paths.out_root / "experiments" / exp_name
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(art, d / "model.joblib")
    man = manifest.make_manifest(
        kind="model", version=exp_name,
        inputs=[manifest.file_input(d / "model.joblib", role="output:model")]
               + [manifest.file_input(p, role=f"upstream:{p.name}") for p in upstream],
        params={"task": task, "feature_note": feature_note},
        producer="ml/train_kb.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    summary = paths.out_root / "metrics" / "summary.jsonl"
    summary.parent.mkdir(parents=True, exist_ok=True)
    with open(summary, "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": exp_name, "task": task,
                            "data_version": DATA_VERSION,
                            "git_rev": manifest.git_rev()}) + "\n")
    return d


def run_kb_experiments(paths: config.Paths, seed: int = 20260914) -> dict:
    kb = knowledge.build_kb_tables(paths)
    st = knowledge.kb_stats(kb, paths)
    kb_man = knowledge.write_kb(paths, kb, st)

    tables, _, _ = dataset.build_tables(paths)
    r1 = exp1001_severity(kb, paths, seed=seed)
    art1 = r1.pop("_art")
    _save(paths, "EXP-1001-severity", r1, [kb_man], {"task": "K1"})
    _persist_model(paths, "EXP-1001-severity-model", art1, [kb_man], "K1",
                   art1["feature"])
    r2 = exp1002_product_relation(kb, paths, seed=seed)
    art2 = r2.pop("_art")
    _save(paths, "EXP-1002-product-relation", r2, [kb_man], {"task": "K2"})
    _persist_model(paths, "EXP-1002-product-relation-model", art2, [kb_man], "K2",
                   art2["feature"])
    r3 = exp1003_template_prior(paths, kb, tables["verified"])
    _save(paths, "EXP-1003-template-prior", r3, [kb_man], {"task": "T2-prior"})
    return {"kb_manifest": str(kb_man), "kb_stats": st,
            "EXP-1001": r1, "EXP-1002": r2, "EXP-1003": r3}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=None)
    ap.add_argument("--out-root", default=None)
    ap.add_argument("--matrix-dir", default=None)
    ap.add_argument("--seed", type=int, default=20260914)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root, args.matrix_dir)
    res = run_kb_experiments(paths, seed=args.seed)
    print(json.dumps({k: v for k, v in res.items() if k != "kb_stats"},
                     ensure_ascii=False, indent=1, default=str)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
