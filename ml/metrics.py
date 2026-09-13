"""排序与分类指标（P6/P8）。全部从真实预测计算，无任何手填数值。"""

from __future__ import annotations

import numpy as np


def precision_at_k(ranked: list[str], relevant: set[str], k: int) -> float | None:
    if len(ranked) < k:
        return None  # 候选不足 K 的查询不参与该指标（诚实口径，不凑分母）
    return len(set(ranked[:k]) & relevant) / k


def recall_at_k(ranked: list[str], relevant: set[str], k: int) -> float | None:
    if not relevant or len(ranked) < k:
        return None
    return len(set(ranked[:k]) & relevant) / len(relevant)


def ndcg_at_k(ranked: list[str], relevant: set[str], k: int) -> float | None:
    if len(ranked) < k or not relevant:
        return None
    dcg = sum(1.0 / np.log2(i + 2) for i, x in enumerate(ranked[:k]) if x in relevant)
    ideal = sum(1.0 / np.log2(i + 2) for i in range(min(k, len(relevant))))
    return float(dcg / ideal) if ideal > 0 else None


def mean_of(values) -> float | None:
    vals = [v for v in values if v is not None]
    return round(float(np.mean(vals)), 4) if vals else None


def eval_ranking(per_query: dict[str, list[str]], per_query_relevant: dict[str, set[str]],
                 ks=(5, 10)) -> dict:
    """逐查询算 P@K / R@K / nDCG@K，再宏平均；候选不足 K 的查询不计入该指标。"""
    out: dict = {"queries": len(per_query),
                 "queries_with_positive": len(per_query_relevant)}
    for k in ks:
        p, r, n = [], [], []
        for q, ranked in per_query.items():
            rel = per_query_relevant.get(q, set())
            if not rel:
                continue
            p.append(precision_at_k(ranked, rel, k))
            r.append(recall_at_k(ranked, rel, k))
            n.append(ndcg_at_k(ranked, rel, k))
        out[f"P@{k}"] = mean_of(p)
        out[f"R@{k}"] = mean_of(r)
        out[f"nDCG@{k}"] = mean_of(n)
        out[f"queries_counted_P@{k}"] = len([v for v in p if v is not None])
    return out
