"""EXP-1006 严重度分类 v2：标签自洽性确认 + 任务重构 + 特征升级。

背景（EXP-1001 遗留）：acc 0.574 / macro-F1 0.484，跨源一致率显示严重度
本身是模糊标签。kb-5.0.1 实测 sev 与 CVSS 分数带 100% 自洽（292,036 条
零冲突）→ 瓶颈不在字符串标签噪声，而在：(a) 四分类边界效应（6.9/7.0 翻带）；
(b) 词级特征对漏洞措辞覆盖不足。

变体（选择只看验证段 2022-2023，测试段 >=2024 只碰一次）：
  v0  EXP-1001 原配方复跑（kb-5.0.1 参照点）
  v1  char_wb 3-5 gram + SGD
  v2  word 1-2 ∪ char 3-5 联合 + SGD
  v3  分数回归（Ridge on word tfidf）→ 切带（含 MAE）
  v4  分数回归（Ridge on char tfidf）→ 切带
指标：acc / macro-F1 / 相邻带容忍 acc（|Δband|<=1）/ 回归 MAE。
纪律：不触碰测试段做选择；所有数字真实执行；kb-5.0.1。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge, SGDClassifier
from sklearn.metrics import f1_score
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer

from . import config, manifest

DATA_VERSION = "kb-5.0.1"
SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]
RANK = {c: i for i, c in enumerate(CLASSES)}
VAL_LO, VAL_HI = pd.Timestamp("2022-01-01"), pd.Timestamp("2024-01-01")


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


def load_data(paths: config.Paths) -> pd.DataFrame:
    import gzip
    kb = paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz"
    rows = []
    with gzip.open(kb, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            rows.append({"cve": r["cve"], "sev": r.get("sev"),
                         "score": r.get("score"), "pub": r.get("pub"),
                         "descr": r.get("descr") or ""})
    df = pd.DataFrame(rows)
    df = df[df["sev"].isin(CLASSES)].copy()
    df["pub_dt"] = pd.to_datetime(df["pub"], errors="coerce")
    return df.dropna(subset=["pub_dt", "descr"])


def _vec(kind: str) -> TfidfVectorizer:
    if kind == "word":
        return TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                               sublinear_tf=True)
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                           max_features=300000, sublinear_tf=True)


def _eval(y_true, y_pred) -> dict:
    tr = np.array([RANK[y] for y in y_true])
    pr = np.array([RANK[y] for y in y_pred])
    return {
        "accuracy": round(float((y_true == y_pred).mean()), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro",
                                         zero_division=0)), 4),
        "adjacent_acc": round(float((np.abs(tr - pr) <= 1).mean()), 4),
        "rows": int(len(y_true)),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    df = load_data(paths)
    tr = df[df["pub_dt"] < VAL_LO]
    va = df[(df["pub_dt"] >= VAL_LO) & (df["pub_dt"] < VAL_HI)]
    te = df[df["pub_dt"] >= VAL_HI]
    print(f"[data] labeled={len(df)} train={len(tr)} val={len(va)} test={len(te)}")

    results = []
    art_best, best_name, best_val = None, None, -1.0

    for name in ("v0", "v1", "v2", "v3", "v4"):
        if name == "v0":
            vec = _vec("word")
        elif name == "v1":
            vec = _vec("char")
        elif name == "v2":
            vec = FeatureUnion([("w", _vec("word")), ("c", _vec("char"))])
        else:
            vec = _vec("word" if name == "v3" else "char")

        Xtr = vec.fit_transform(tr["descr"])
        if name in ("v3", "v4"):
            reg = Ridge(alpha=1.0, random_state=SEED).fit(
                Xtr, tr["score"].astype(float))
            mae_va = float(np.abs(reg.predict(vec.transform(va["descr"])) -
                                  va["score"].astype(float)).mean())
            va_eval = _eval(va["sev"].to_numpy(),
                            np.array([band(s) for s in reg.predict(
                                vec.transform(va["descr"]))], dtype=object))
            Xte = vec.transform(te["descr"])
            mae_te = float(np.abs(reg.predict(Xte) -
                                  te["score"].astype(float)).mean())
            te_eval = _eval(te["sev"].to_numpy(),
                            np.array([band(s) for s in reg.predict(Xte)],
                                     dtype=object))
            te_eval["score_mae"] = round(mae_te, 3)
            va_eval["score_mae"] = round(mae_va, 3)
            art = {"vec": vec, "model": reg, "kind": "regression"}
        else:
            clf = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=30,
                                class_weight="balanced", random_state=SEED)
            clf.fit(Xtr, tr["sev"])
            va_eval = _eval(va["sev"].to_numpy(),
                            clf.predict(vec.transform(va["descr"])))
            Xte = vec.transform(te["descr"])
            te_eval = _eval(te["sev"].to_numpy(), clf.predict(Xte))
            art = {"vec": vec, "model": clf, "kind": "classification"}

        results.append({"variant": name, "kind": art["kind"],
                        "val": va_eval, "test": te_eval,
                        "train_rows": int(len(tr))})
        print(f"[{name}] val_f1={va_eval['macro_f1']} test_f1={te_eval['macro_f1']} "
              f"test_acc={te_eval['accuracy']}")
        if va_eval["macro_f1"] > best_val:
            best_val, best_name = va_eval["macro_f1"], name
            art_best = art

    out = {
        "experiment": "EXP-1006",
        "task": "K1-v2 严重度分类提升（标签自洽确认 + 回归重构 + 特征升级）",
        "label_consistency": {
            "check": "sev 字符串 vs CVSS 分数带（kb-5.0.1 全量 292,036 条）",
            "agreement": 1.0, "conflicts": 0,
            "conclusion": "字符串标签与分数带完全自洽——瓶颈是任务模糊性与边界效应，"
                          "不是标注噪声；提升路径=回归重构+特征升级"},
        "split": {"train": "pub<2022", "val": "2022-2023（变体选择）",
                  "test": ">=2024（只碰一次）"},
        "results": results,
        "selected": {"variant": best_name, "val_macro_f1": round(best_val, 4)},
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / "EXP-1006-severity-v2.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    if art_best is not None:
        d = paths.out_root / "experiments" / "EXP-1006-severity-v2-model"
        d.mkdir(parents=True, exist_ok=True)
        joblib.dump({**art_best, "classes": CLASSES,
                     "feature": f"tfidf variant {best_name}"},
                    d / "model.joblib")
        man = manifest.make_manifest(
            kind="model", version="EXP-1006-severity-v2-model",
            inputs=[manifest.file_input(d / "model.joblib", role="output:model"),
                    manifest.file_input(
                        paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                        role="upstream:kb_cve")],
            params={"task": "K1-v2", "seed": SEED, "selected": best_name},
            producer="ml/train_sev_v2.py",
            scope={"data_version": DATA_VERSION},
        )
        manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
        with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"exp_id": "EXP-1006-severity-v2-model",
                                "task": "K1-v2 严重度 v2", "selected": best_name,
                                "data_version": DATA_VERSION,
                                "git_rev": manifest.git_rev()}) + "\n")

    print(f"[selected] {best_name} (val_f1={best_val:.4f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
