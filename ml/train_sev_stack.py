"""sev-prior-v3（EXP-1007）：严重度先验堆叠版——冲 0.75 的合法手段全上。

堆叠特征（无泄漏：CWE 栈只在训练段内拟合，测试段预测来自仅见过训练段
的栈模型）：
  - 描述 word(1,2) + char_wb(3,5) TF-IDF 联合
  - cwe_pred：EXP-1005 协议的 CWE 分类器（25 类 one-hot）
  - meta：描述长度（标准化）、发布年份（归一）
模型族：SGD（alpha 扫描）、LinearSVC（C 扫描）；验证段选型、测试段一次。

口径：严格三段切分同 EXP-1006（train<2022 / val 22-23 / test>=2024），
指标 acc / macro-F1 / 相邻带容忍 acc。
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from . import config, manifest

DATA_VERSION = "kb-5.0.1"
ALIAS = "sev-prior-v3"
SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]


def band(score: float) -> str | None:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    if s >= 0.1:
        return "low"
    return None


def load(paths: config.Paths) -> tuple[pd.DataFrame, pd.DataFrame]:
    def _load_kb(path: Path) -> pd.DataFrame:
        rows = []
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                rows.append({"cve": r["cve"], "sev": r.get("sev"),
                             "score": r.get("score"), "pub": r.get("pub"),
                             "descr": r.get("descr") or ""})
        df = pd.DataFrame(rows)
        df["pub_dt"] = pd.to_datetime(df["pub"], errors="coerce")
        return df.dropna(subset=["pub_dt"])

    df = _load_kb(paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz")
    df = df[df["sev"].isin(CLASSES)]

    edges = pd.DataFrame(json.loads(line) for line in gzip.open(
        paths.out_root / "dataset" / DATA_VERSION / "kb_cve_cwe.jsonl.gz",
        "rt", encoding="utf-8"))
    primary = edges.drop_duplicates("cve", keep="first")
    return df, primary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    df, cwe_edges = load(paths)
    tr = df[df["pub_dt"] < pd.Timestamp("2022-01-01")]
    va = df[(df["pub_dt"] >= pd.Timestamp("2022-01-01"))
            & (df["pub_dt"] < pd.Timestamp("2024-01-01"))]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    print(f"[data] train={len(tr)} val={len(va)} test={len(te)}")

    # ---- CWE 栈：仅训练段拟合（EXP-1005 协议），预测 val/test ----
    cwe_tr_keys = set(cwe_edges["cve"])
    cwe_primary = cwe_edges.drop_duplicates("cve", keep="first")
    cwe_meta = cwe_primary.set_index("cve")["cwe"]
    tr_cwe = tr[tr["cve"].isin(cwe_tr_keys)].copy()
    tr_cwe["cwe"] = tr_cwe["cve"].map(cwe_meta)
    cw_classes = tr_cwe["cwe"].value_counts().head(25).index.tolist()
    cw_set = set(cw_classes)
    tr_cwe = tr_cwe[tr_cwe["cwe"].isin(cw_set)]
    cw_vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                             sublinear_tf=True)
    cwe_clf = SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=20,
                            class_weight="balanced", random_state=SEED)
    cwe_clf.fit(cw_vec.fit_transform(tr_cwe["descr"]), tr_cwe["cwe"])

    def cwe_onehot(texts) -> sparse.csr_matrix:
        pred = cwe_clf.predict(cw_vec.transform(texts))
        col = {c: i for i, c in enumerate(cw_classes)}
        mat = sparse.lil_matrix((len(pred), len(cw_classes)), dtype=np.float32)
        for i, c in enumerate(pred):
            if c in col:
                mat[i, col[c]] = 1.0
        return mat.tocsr()

    def meta_dense(texts, pubs) -> np.ndarray:
        ln = np.array([len(t) for t in texts], dtype=np.float32).reshape(-1, 1)
        yr = pd.to_datetime(pd.Series(pubs), errors="coerce").dt.year.fillna(
            2020).to_numpy(dtype=np.float32).reshape(-1, 1)
        yr = (yr - 2015.0) / 10.0
        return StandardScaler().fit_transform(np.hstack([ln, yr]))

    # ---- 特征装配 ----
    word = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                           sublinear_tf=True)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                           max_features=200000, sublinear_tf=True)
    Xw_tr = word.fit_transform(tr["descr"])
    Xc_tr = char.fit_transform(tr["descr"])
    Xtr = sparse.hstack([Xw_tr, Xc_tr, cwe_onehot(tr["descr"]),
                         sparse.csr_matrix(meta_dense(tr["descr"], tr["pub"]))],
                        format="csr")
    Xva = sparse.hstack([word.transform(va["descr"]), char.transform(va["descr"]),
                         cwe_onehot(va["descr"]),
                         sparse.csr_matrix(meta_dense(va["descr"], va["pub"]))],
                        format="csr")
    Xte = sparse.hstack([word.transform(te["descr"]), char.transform(te["descr"]),
                         cwe_onehot(te["descr"]),
                         sparse.csr_matrix(meta_dense(te["descr"], te["pub"]))],
                        format="csr")

    def _eval(y_true, y_pred) -> dict:
        rank = {c: i for i, c in enumerate(CLASSES)}
        tr_r = np.array([rank[y] for y in y_true])
        pr_r = np.array([rank[y] for y in y_pred])
        return {"accuracy": round(float((y_true == y_pred).mean()), 4),
                "macro_f1": round(float(f1_score(y_true, y_pred, average="macro",
                                                 zero_division=0)), 4),
                "adjacent_acc": round(float((np.abs(tr_r - pr_r) <= 1).mean()), 4),
                "rows": int(len(y_true))}

    sweep = [
        ("sgd_a3e-5", SGDClassifier(loss="log_loss", alpha=3e-5, max_iter=30,
                                    class_weight="balanced", random_state=SEED)),
        ("sgd_a1e-4", SGDClassifier(loss="log_loss", alpha=1e-4, max_iter=30,
                                    class_weight="balanced", random_state=SEED)),
        ("svc_c0.5", LinearSVC(C=0.5, class_weight="balanced",
                               random_state=SEED)),
        ("svc_c1", LinearSVC(C=1.0, class_weight="balanced", random_state=SEED)),
    ]
    results, best, best_name, best_val = [], None, None, -1.0
    for name, clf in sweep:
        clf.fit(Xtr, tr["sev"])
        pv = clf.predict(Xva)
        pt = clf.predict(Xte)
        va_e, te_e = _eval(va["sev"].to_numpy(), pv), _eval(te["sev"].to_numpy(), pt)
        results.append({"model": name, "val": va_e, "test": te_e})
        print(f"[{name}] val_f1={va_e['macro_f1']} test_acc={te_e['accuracy']} "
              f"test_f1={te_e['macro_f1']} adjacent={te_e['adjacent_acc']}")
        if va_e["macro_f1"] > best_val:
            best_val, best_name, best = va_e["macro_f1"], name, clf

    out = {
        "experiment": "EXP-1007",
        "alias": ALIAS,
        "task": "严重度先验 v3：堆叠特征（描述词字 TF-IDF + CWE 预测栈 + 元数据）",
        "data": {"labeled": int(len(df)), "train": int(len(tr)),
                 "val": int(len(va)), "test": int(len(te))},
        "stack": {"cwe_classes": len(cw_classes),
                  "note": "CWE 栈仅训练段拟合；测试段预测不含测试信息"},
        "split": "train<2022 / val 2022-23（选型）/ test>=2024（一次）",
        "results": results,
        "selected": {"model": best_name, "val_macro_f1": round(best_val, 4)},
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1007-{ALIAS}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    d = paths.out_root / "experiments" / f"EXP-1007-{ALIAS}"
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump({"word": word, "char": char, "cwe_vec": cw_vec,
                 "cwe_clf": cwe_clf, "clf": best, "classes": CLASSES,
                 "cwe_classes": cw_classes, "alias": ALIAS},
                d / "model.joblib")
    man = manifest.make_manifest(
        kind="model", version=f"EXP-1007-{ALIAS}",
        inputs=[manifest.file_input(d / "model.joblib", role="output:model"),
                manifest.file_input(
                    paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                    role="upstream:kb_cve")],
        params={"task": "sev-prior", "seed": SEED, "selected": best_name},
        producer="ml/train_sev_stack.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": f"EXP-1007-{ALIAS}", "alias": ALIAS,
                            "task": "严重度先验 v3（堆叠）",
                            "data_version": DATA_VERSION,
                            "git_rev": manifest.git_rev()}) + "\n")
    print(f"[selected] {best_name} (val_f1={best_val:.4f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
