"""sev-prior v2.2（EXP-1009）：大模型 + 大数据 三路实测。

用户假设：模型太小 / 数据太小。本轮逐一实测（口径与 v2.1 完全一致，
test=NVD pub>=2024 的 4 类标注行）：
  base  v2.1 现役（LR alpha=1e-5，148k 训练）——参照点
  A     容量升级：TruncatedSVD(300) + HistGradientBoosting（目标书优先模型）
  B     数据扩充：80,496 条无标注描述自训练（伪标注最大概率>=0.8 入训）
  C     base+A+B 软投票集成
promoted 条件：test acc 与 macro-F1 均不低于 base 且至少一项提升。
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from . import config, manifest

DATA_VERSION = "kb-5.0.2"
ALIAS = "sev-prior"
VERSION = "v2.2"
SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]
PSEUDO_CONF = 0.8


def load_kb(path: str) -> pd.DataFrame:
    rows = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            rows.append({"cve": r["cve"], "sev": r.get("sev"),
                         "pub": r.get("pub"), "descr": r.get("descr") or ""})
    df = pd.DataFrame(rows)
    df["pub_dt"] = pd.to_datetime(df["pub"], errors="coerce")
    return df.dropna(subset=["pub_dt"])


def _proba(model, X) -> np.ndarray:
    """统一概率矩阵：列序恒为 CLASSES。模型 classes_ 是字母序，必须重排——
    否则 argmax 映射错位，全部指标报废（首轮运行即栽在这里）。"""
    if hasattr(model, "predict_proba"):
        p = model.predict_proba(X)
        cls = list(getattr(model, "classes_", CLASSES))
        out = np.zeros((p.shape[0], len(CLASSES)), dtype=np.float64)
        for j, c in enumerate(cls):
            if c in CLASSES:
                out[:, CLASSES.index(c)] = p[:, j]
        return out
    p = model.predict(X)
    return np.array([[1.0 if c == y else 0.0 for c in CLASSES] for y in p])


def _metrics(y_true, proba: np.ndarray) -> dict:
    pred = np.array(CLASSES)[proba.argmax(axis=1)]
    tr_r = np.array([CLASSES.index(y) for y in y_true])
    pr_r = np.array([CLASSES.index(y) for y in pred])
    out = {"accuracy": round(float(accuracy_score(y_true, pred)), 4),
           "macro_f1": round(float(f1_score(y_true, pred, average="macro",
                                            zero_division=0)), 4),
           "adjacent_acc": round(float((np.abs(tr_r - pr_r) <= 1).mean()), 4)}
    try:
        ybin = np.array([[1.0 if c == y else 0.0 for c in CLASSES]
                         for y in y_true]).ravel()
        if len(np.unique(y_true)) > 1:
            out["macro_auc"] = round(float(roc_auc_score(ybin, proba.ravel())), 4)
    except ValueError:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)
    kb_path = paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz"

    df = load_kb(str(kb_path))
    tr = df[(df["pub_dt"] < pd.Timestamp("2024-01-01"))
            & df["sev"].isin(CLASSES)]
    te = df[(df["pub_dt"] >= pd.Timestamp("2024-01-01"))
            & df["sev"].isin(CLASSES)]
    pool = df[~df["sev"].isin(CLASSES) & (df["descr"].str.len() > 30)]
    yte = te["sev"].to_numpy()
    print(f"[data] train={len(tr)} test={len(te)} pseudo_pool={len(pool)}")

    # ---- 特征（与 v2.1 同配方）----
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                          sublinear_tf=True)
    Xtr = vec.fit_transform(tr["descr"])
    Xte = vec.transform(te["descr"])
    Xpl = vec.transform(pool["descr"])

    results: dict = {}

    # ---- base：v2.1 现役配方 ----
    lr = SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=30,
                       class_weight="balanced", random_state=SEED)
    lr.fit(Xtr, tr["sev"])
    proba_base = _proba(lr, Xte)
    results["base_v2.1_lr"] = _metrics(yte, proba_base)
    print(f"[base] {results['base_v2.1_lr']}")

    # ---- A：SVD + HistGB（容量升级）----
    svd = TruncatedSVD(n_components=300, random_state=SEED)
    Xtr_svd = svd.fit_transform(Xtr)
    Xte_svd = svd.transform(Xte)
    hgb = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1,
                                         random_state=SEED)
    hgb.fit(Xtr_svd, tr["sev"])
    proba_a = _proba(hgb, Xte_svd)
    results["A_svd300_histgb"] = _metrics(yte, proba_a)
    print(f"[A svd+histgb] {results['A_svd300_histgb']}")

    # ---- B：自训练（伪标注 80k，置信度 >=0.8 入训）----
    pl_proba = _proba(lr, Xpl)
    conf = pl_proba.max(axis=1)
    pred_pl = np.array(CLASSES)[pl_proba.argmax(axis=1)]
    keep = conf >= PSEUDO_CONF
    Xpl_keep = Xpl[keep]
    ypl_keep = pred_pl[keep]
    n_pl = int(keep.sum())
    Xtr2 = sparse.vstack([Xtr, Xpl_keep], format="csr")
    ytr2 = np.concatenate([tr["sev"].to_numpy(), ypl_keep])
    lr2 = SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=30,
                        class_weight="balanced", random_state=SEED)
    lr2.fit(Xtr2, ytr2)
    proba_b = _proba(lr2, Xte)
    results["B_selftrain"] = {
        **_metrics(yte, proba_b),
        "pseudo_used": n_pl, "pseudo_pool": int(len(pool)),
        "pseudo_conf": PSEUDO_CONF}
    print(f"[B self-train] {results['B_selftrain']}")

    # ---- C：软投票集成 ----
    proba_c = (proba_base + proba_a + proba_b) / 3.0
    results["C_ensemble"] = _metrics(yte, proba_c)
    print(f"[C ensemble] {results['C_ensemble']}")

    base = results["base_v2.1_lr"]
    promoted = {k: v for k, v in results.items() if k != "base_v2.1_lr"
                and v["accuracy"] >= base["accuracy"]
                and v["macro_f1"] >= base["macro_f1"]
                and (v["accuracy"] > base["accuracy"]
                     or v["macro_f1"] > base["macro_f1"])}

    out = {
        "experiment": "EXP-1009", "alias": ALIAS, "version": VERSION,
        "task": "sev-prior v2.2：大模型（SVD+HistGB）/ 大数据（自训练 80k）/ 集成 三路实测",
        "data": {"train": int(len(tr)), "test": int(len(te)),
                 "pseudo_pool": int(len(pool)), "pseudo_used": n_pl,
                 "pseudo_conf": PSEUDO_CONF,
                 "note": "伪标注行来自无标注 NVD 记录（与 test 无交集 CVE）"},
        "results": results,
        "promoted": {"winner": max(promoted, key=lambda k: promoted[k]["accuracy"])
                     if promoted else None,
                     "note": "promoted 条件：acc 与 macro-F1 均不低于 base 且至少一项提升"},
        "verdict": ("已有晋升" if promoted else
                    "三路均未晋升——容量与数据扩充在当前协议下无增益，"
                    "描述文本信息上限结论获得进一步证据"),
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1009-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    if promoted:
        winner = out["promoted"]["winner"]
        d = paths.out_root / "experiments" / f"EXP-1009-{ALIAS}-{VERSION}"
        d.mkdir(parents=True, exist_ok=True)
        joblib.dump({"vec": vec, "winner": winner, "base": lr,
                     "svd": svd, "hgb": hgb, "selftrain": lr2,
                     "classes": CLASSES}, d / "model.joblib")
        man = manifest.make_manifest(
            kind="model", version=f"EXP-1009-{ALIAS}-{VERSION}",
            inputs=[manifest.file_input(d / "model.joblib", role="output:model"),
                    manifest.file_input(kb_path, role="upstream:kb_cve")],
            params={"task": "sev-prior", "seed": SEED, "winner": winner},
            producer="ml/train_sev_big.py",
            scope={"data_version": DATA_VERSION},
        )
        manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
        with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"exp_id": f"EXP-1009-{ALIAS}-{VERSION}",
                                "alias": ALIAS, "winner": winner,
                                "data_version": DATA_VERSION}) + "\n")

    print(f"[verdict] {out['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
