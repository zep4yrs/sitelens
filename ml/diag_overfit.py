"""过拟合诊断（严重度 EXP-1006 数据 + CWE EXP-1005 协议）。

回答两个问题：
  1. 严重度模型 0.50 的测试分是过拟合还是信息上限？→ 看训练/测试差距、
     alpha 扫描（强正则是否提分）、学习曲线（加数据是否提分）。
  2. EXP-1005 CWE 0.7586 还有没有正路可提？→ class_weight / char n-gram /
     alpha 扫描，协议与 EXP-1005 完全一致（top-25 主弱点，pub<2024 切分）。
"""

from __future__ import annotations

import gzip
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score

SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]


def load_kb(path: str) -> pd.DataFrame:
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


def gap_report(name: str, ytr, ptr, yte, pte, yva=None, pva=None) -> dict:
    out = {"name": name,
           "train_acc": round(float(accuracy_score(ytr, ptr)), 4),
           "train_f1": round(float(f1_score(ytr, ptr, average="macro",
                                            zero_division=0)), 4)}
    if yva is not None:
        out["val_f1"] = round(float(f1_score(yva, pva, average="macro",
                                             zero_division=0)), 4)
    out["test_acc"] = round(float(accuracy_score(yte, pte)), 4)
    out["test_f1"] = round(float(f1_score(yte, pte, average="macro",
                                          zero_division=0)), 4)
    out["gap_train_minus_test_f1"] = round(out["train_f1"] - out["test_f1"], 4)
    return out


def severity_diag(df: pd.DataFrame) -> dict:
    tr = df[df["pub_dt"] < "2022-01-01"]
    va = df[(df["pub_dt"] >= "2022-01-01") & (df["pub_dt"] < "2024-01-01")]
    te = df[df["pub_dt"] >= "2024-01-01"]
    out: dict = {"train_rows": len(tr), "val_rows": len(va), "test_rows": len(te)}

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                          sublinear_tf=True)
    Xtr = vec.fit_transform(tr["descr"])
    Xva = vec.transform(va["descr"])
    Xte = vec.transform(te["descr"])

    # 1) 训练/测试差距 + alpha 扫描
    sweeps = []
    for alpha in (1e-4, 1e-5, 1e-6):
        clf = SGDClassifier(loss="log_loss", alpha=alpha, max_iter=30,
                            class_weight="balanced", random_state=SEED)
        clf.fit(Xtr, tr["sev"])
        sweeps.append(gap_report(f"alpha={alpha:g}", tr["sev"], clf.predict(Xtr),
                                 te["sev"], clf.predict(Xte),
                                 va["sev"], clf.predict(Xva)))
    out["alpha_sweep"] = sweeps

    # 2) 学习曲线（同 alpha=1e-6）
    curve = []
    for frac in (0.25, 0.5, 1.0):
        sub = tr.sample(frac=frac, random_state=SEED)
        clf = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=30,
                            class_weight="balanced", random_state=SEED)
        clf.fit(vec.transform(sub["descr"]), sub["sev"])
        curve.append({"frac": frac, "rows": int(len(sub)),
                      "train_f1": round(float(f1_score(
                          sub["sev"], clf.predict(vec.transform(sub["descr"])),
                          average="macro", zero_division=0)), 4),
                      "val_f1": round(float(f1_score(
                          va["sev"], clf.predict(Xva), average="macro",
                          zero_division=0)), 4)})
    out["learning_curve"] = curve
    return out


def cwe_diag(kb_cve: pd.DataFrame, edges_path: str) -> dict:
    edges = pd.DataFrame(json.loads(line) for line in
                         gzip.open(edges_path, "rt", encoding="utf-8"))
    primary = edges.drop_duplicates("cve", keep="first")
    meta = kb_cve.set_index("cve")[["descr", "pub"]]
    df = primary.merge(meta, left_on="cve", right_index=True, how="inner").dropna(
        subset=["descr", "pub"])
    df["pub_dt"] = pd.to_datetime(df["pub"], errors="coerce")
    tr = df[df["pub_dt"] < pd.Timestamp("2024-01-01")]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    classes = tr["cwe"].value_counts().head(25).index.tolist()
    tr = tr[tr["cwe"].isin(classes)]
    te = te[te["cwe"].isin(classes)]
    out: dict = {"train_rows": len(tr), "test_rows": len(te),
                 "n_classes": len(classes)}

    configs = []
    for feat, cw, alpha in (("word", None, 1e-5), ("word", "balanced", 1e-5),
                            ("char", "balanced", 1e-5),
                            ("word", "balanced", 1e-4),
                            ("word", "balanced", 1e-6)):
        vec = (TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                               sublinear_tf=True) if feat == "word" else
               TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                               max_features=300000, sublinear_tf=True))
        Xtr = vec.fit_transform(tr["descr"])
        clf = SGDClassifier(loss="log_loss", alpha=alpha, max_iter=20,
                            random_state=SEED,
                            **({"class_weight": cw} if cw else {}))
        clf.fit(Xtr, tr["cwe"])
        Xte = vec.transform(te["descr"])
        configs.append(gap_report(
            f"feat={feat} cw={cw} alpha={alpha:g}",
            tr["cwe"], clf.predict(Xtr), te["cwe"], clf.predict(Xte)))
    out["configs"] = configs
    return out


def main() -> int:
    kb = load_kb(r"data/ml/dataset/kb-5.0.1/kb_cve.jsonl.gz")
    sev = kb[kb["sev"].isin(CLASSES)]
    print("=== 严重度过拟合诊断 ===")
    sev_out = severity_diag(sev)
    print(json.dumps(sev_out, ensure_ascii=False, indent=1))

    print("=== CWE 提升尝试（EXP-1005 协议）===")
    cwe_out = cwe_diag(kb, r"data/ml/dataset/kb-5.0.1/kb_cve_cwe.jsonl.gz")
    print(json.dumps(cwe_out, ensure_ascii=False, indent=1))

    payload = {"severity_overfit_diag": sev_out, "cwe_improve_attempt": cwe_out}
    with open("data/ml/metrics/DIAG-overfit-and-cwe.json", "w",
              encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    print("[saved] data/ml/metrics/DIAG-overfit-and-cwe.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
