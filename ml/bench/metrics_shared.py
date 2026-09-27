"""基线与 LM 共用的同一指标实现（EXP-1004 公平性锚点）。

E2 截断协议：两系统都只在自己给出的 Top-5 内计分——
  P@5  = 任一命中（top5 ∩ true_set 非空）的行占比
  MRR@5 = 首个命中的 1/rank，5 名内无命中计 0
"""

from __future__ import annotations


def pk5_mrr5(ranked5: list[list[str]], true_sets: list[set[str]]) -> dict:
    assert len(ranked5) == len(true_sets)
    hits, mrr = 0, 0.0
    for ranked, ts in zip(ranked5, true_sets):
        for rank, c in enumerate(ranked[:5], start=1):
            if c in ts:
                hits += 1
                mrr += 1.0 / rank
                break
    n = max(1, len(ranked5))
    return {"P@5": round(hits / n, 4), "MRR@5": round(mrr / n, 4),
            "rows": len(ranked5)}


def e1_class_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    """E1 的 accuracy / macro_f1（与 EXP-1001 同定义，独立实现避免持久化依赖）。"""
    from sklearn.metrics import f1_score
    assert len(y_true) == len(y_pred) and len(y_true) > 0
    return {
        "accuracy": round(float(sum(a == b for a, b in zip(y_true, y_pred)) / len(y_true)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "rows": len(y_true),
    }
