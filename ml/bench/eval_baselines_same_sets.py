"""EXP-1004 基线侧：持久化基线模型在 EXP-1004 抽样集上重算。

E1/E2 用 EXP-1001/1002 的 model.joblib（vectorizer+模型）在同一评测行上
重新预测、用 metrics_shared 同一实现计分；E3 用 baselines.evaluate_baselines
同一函数在同一候选表上重算。产出 data/ml/bench/results/baseline_on_same_sets.json。
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import joblib
import pandas as pd

from .. import baselines
from . import metrics_shared


def _load_jsonl(path: Path) -> pd.DataFrame:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return pd.DataFrame(json.loads(line) for line in f)


def run_e1(eval_dir: Path) -> dict:
    art = joblib.load(Path("data/ml/experiments/EXP-1001-severity-model/model.joblib"))
    rows = _load_jsonl(eval_dir / "e1_severity.jsonl.gz")
    X = art["vectorizer"].transform(rows["descr"])
    pred = art["model"].predict(X)
    m = metrics_shared.e1_class_metrics(rows["sev"].tolist(), list(pred))
    return {"system": "EXP-1001-severity-model (TF-IDF+SGD, persisted)",
            **m}


def run_e2(eval_dir: Path) -> dict:
    art = joblib.load(Path("data/ml/experiments/EXP-1002-product-relation-model/model.joblib"))
    rows = _load_jsonl(eval_dir / "e2_product.jsonl.gz")
    X = art["vectorizer"].transform(rows["descr"])
    proba = art["clf"].predict_proba(X)
    classes = list(art["clf"].classes_)
    order = proba.argsort(axis=1)[:, ::-1]
    ranked5 = [[classes[j] for j in order[i][:5]] for i in range(len(rows))]
    true_sets = [set(t) for t in rows["true_set"]]
    m = metrics_shared.pk5_mrr5(ranked5, true_sets)
    m["class_universe"] = len(classes)
    m["note"] = ("基线类宇宙=clf.classes_（训练期出现过的产品类）；"
                 "与 LM 的 200 类字母序宇宙同源于 top-200，集合差异如实记录")
    return {"system": "EXP-1002-product-relation-model (OvR SGD, persisted)", **m}


def run_e3(eval_dir: Path) -> dict:
    cand = _load_jsonl(eval_dir / "e3_candidates.jsonl.gz")
    pos = _load_jsonl(eval_dir / "e3_positives.jsonl.gz")
    rep = baselines.evaluate_baselines(cand, pos)
    keep = {k: rep[k] for k in ("severity", "rule_based", "prior_hits", "random")}
    keep["queries_detail"] = rep["queries_detail"]
    return {"system": "P6 baselines (same code path)",
            "baselines": keep}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-root", default="data/ml")
    args = ap.parse_args()
    out_root = Path(args.out_root)
    eval_dir = out_root / "bench" / "eval_sets"
    res_dir = out_root / "bench" / "results"
    res_dir.mkdir(parents=True, exist_ok=True)

    res = {
        "experiment": "EXP-1004",
        "side": "baseline",
        "note": "全部指标在同一抽样评测行上用同一指标代码重算（预注册 §三）",
        "e1_severity": run_e1(eval_dir),
        "e2_product": run_e2(eval_dir),
        "e3_candidates": run_e3(eval_dir),
    }
    out = res_dir / "baseline_on_same_sets.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=1)[:2000])
    print(f"[saved] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
