"""导出 5.0 线性模型为 Go 引擎可嵌入资产（EXP-1017 附带工程）。

导出物（data/go/ml_assets/，随引擎数据分发）：
  cve-tech.vocab.txt     词表（行号=特征 id，120k 行）
  cve-tech.idf.f32       idf 权重（120k float32 LE）
  cve-tech.coef.f32      OvR 系数（196×120k float32 LE，行=类）
  cve-tech.meta.json     类别表/intercept/维度
  cwe-type.*             同构（25 类）
  fixtures.json          parity 夹具：500 条描述 + Python 侧预测结果
用途：internal/ml 的 Go 移植必须与 Python 侧预测对拍一致（>=99.5%）。

自包含：BASE 取本文件位置（sitelens-ml5 仓库根），与 cwd 无关。
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np

BASE = Path(__file__).resolve().parents[1]
OUT = Path(r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data\go\ml_assets")
MODELS = {
    "cve-tech": BASE / "data" / "ml" / "experiments"
    / "EXP-1002-product-relation-model" / "model.joblib",
    "cwe-type": BASE / "data" / "ml" / "experiments"
    / "EXP-1005-cwe-model" / "model.joblib",
}
DATASET = BASE / "data" / "ml" / "dataset" / "kb-5.0.2" / "kb_cve.jsonl.gz"


def _clf(art: dict):
    """cve-tech 存 OneVsRestClassifier 于 'clf'；cwe-type 存单个多类 SGD 于 'model'。"""
    return art["clf"] if "clf" in art else art["model"]


def dump_linear(name: str, art: dict, out: Path) -> dict:
    vec, clf = art["vectorizer"], _clf(art)
    classes = [str(c) for c in clf.classes_]
    if hasattr(clf, "estimators_"):
        coefs = np.stack([e.coef_.toarray().ravel() if hasattr(e.coef_, "toarray")
                          else np.asarray(e.coef_).ravel() for e in clf.estimators_])
    else:
        coefs = (clf.coef_.toarray() if hasattr(clf.coef_, "toarray")
                 else np.asarray(clf.coef_)).reshape(len(classes), -1)
    intercept = (np.asarray(clf.intercept_).ravel()
                 if hasattr(clf, "intercept_")
                 else np.asarray([np.asarray(e.intercept_).ravel()[0]
                                  for e in clf.estimators_]))
    n_f = coefs.shape[1]

    vocab = sorted(vec.vocabulary_.items(), key=lambda kv: kv[1])
    (out / f"{name}.vocab.txt").write_text(
        "\n".join(t for t, _ in vocab), encoding="utf-8")
    idf = vec.idf_.astype("<f4")
    (out / f"{name}.idf.f32").write_bytes(idf.tobytes())
    (out / f"{name}.coef.f32").write_bytes(
        coefs.astype("<f4").tobytes())
    meta = {"name": name, "classes": classes, "n_features": int(n_f),
            "n_classes": len(classes),
            "intercept": [float(x) for x in intercept],
            "sublinear_tf": bool(vec.sublinear_tf), "lowercase": True,
            "token_pattern": vec.token_pattern, "l2_norm": True,
            "format": "vocab.txt line=id; idf.f32; coef.f32 rows=classes"}
    (out / f"{name}.meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[{name}] classes={len(classes)} features={n_f} "
          f"coef_mb={coefs.nbytes/1e6:.1f}")
    return meta


def dump_fixtures(out: Path) -> None:
    """500 条真实描述 + Python 侧预测（Go 对拍基准）。"""
    import gzip
    import pandas as pd

    art_tech = joblib.load(MODELS["cve-tech"])
    art_cwe = joblib.load(MODELS["cwe-type"])
    clf_tech, clf_cwe = _clf(art_tech), _clf(art_cwe)

    rows = []
    with gzip.open(DATASET, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if len(r.get("descr") or "") > 40:
                rows.append({"cve": r["cve"], "descr": r["descr"]})
            if len(rows) >= 500:
                break
    df = pd.DataFrame(rows)
    X = art_tech["vectorizer"].transform(df["descr"])
    proba = clf_tech.predict_proba(X)
    classes_t = [str(c) for c in clf_tech.classes_]
    order = proba.argsort(axis=1)[:, ::-1]
    top5 = [[{"product": classes_t[j], "prob": round(float(proba[i, j]), 5)}
             for j in order[i][:5]] for i in range(len(df))]
    Xc = art_cwe["vectorizer"].transform(df["descr"])
    cwe_proba = clf_cwe.predict_proba(Xc)
    cwe_classes = [str(c) for c in clf_cwe.classes_]
    cwe_pred = [cwe_classes[j] for j in cwe_proba.argmax(axis=1)]
    fixtures = [{"cve": df.iloc[i]["cve"], "descr": df.iloc[i]["descr"],
                 "tech_top5": top5[i],
                 "cwe_pred": cwe_pred[i],
                 "cwe_prob": round(float(cwe_proba[i].max()), 5)}
                for i in range(len(df))]
    (out / "fixtures.json").write_text(
        json.dumps(fixtures, ensure_ascii=False), encoding="utf-8")
    print(f"[fixtures] {len(fixtures)} 条")


def main() -> int:
    out = OUT
    out.mkdir(parents=True, exist_ok=True)
    for name, path in MODELS.items():
        art = joblib.load(path)
        dump_linear(name, art, out)
    dump_fixtures(out)
    print(f"[done] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
