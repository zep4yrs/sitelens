"""P6 Baseline：T2 候选排序的规则基线（severity / rule-based / random /
prior-hits），以及 CVSS / KEV 排序（intel 候选，无可观测结局 → 只出定义，
不评指标——如实记录，不编造）。

T2 evaluation target：内置 check 候选集（开发文档 §5）。
正例 = 该扫描中实际命中的 check（verified src=check）；
未见命中候选 = unknown，只作为排序队列成员，绝不作为"负类正确答案"，
指标仅在观测正例上定义（P@K/R@K/nDCG@K）。
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from . import metrics
from .features import SEV_ORD


def _rank_candidates(group: pd.DataFrame, score_col: str, tie_col: str) -> list[str]:
    g = group.sort_values([score_col, tie_col], ascending=[False, True])
    return g["check_id"].tolist()


def severity_baseline(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["score"] = df["sev_ord"]
    return df


def rule_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """现行引擎哲学的可计算近似：核心集(Lv0)优先 → severity 高优先 → id 稳定序。"""
    df = df.copy()
    df["score"] = df["sev_ord"] + 10 * (1 - df["check_lv"]) + df["cms_linked_flag"]
    return df


def prior_hits_baseline(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["score"] = df["prior_hits_this_check"].astype(float)
    return df


def random_baseline(df: pd.DataFrame, seed: int = 20260914) -> pd.DataFrame:
    rng = np.random.default_rng(seed + len(df))
    df = df.copy()
    df["score"] = rng.random(len(df))
    return df


def evaluate_baselines(cand_feat: pd.DataFrame,
                       positives: pd.DataFrame) -> dict:
    """候选特征表 × 观测正例 → 各基线排序指标。

    正例只取 src=check 的 verified 行（候选集是内置 check；
    nuclei/passive/dast 不在候选宇宙内，如实排除）。
    指标只在"该扫描候选数 ≥ K 且观测正例 ≥ 1"的查询上计算（诚实分母）。
    """
    if len(positives):
        positives = positives[positives["src"] == "check"]
    pos_keys = set(zip(positives["scan_uid"], positives["check"])) \
        if len(positives) else set()
    per_query: dict[str, list[str]] = {}
    per_query_rel: dict[str, set[str]] = {}
    for uid, g in cand_feat.groupby("scan_uid"):
        cid_set = set(g["check_id"])
        rel = {cid for (u, cid) in pos_keys if u == uid} & cid_set
        if rel:
            per_query[uid] = g["check_id"].tolist()
            per_query_rel[uid] = rel

    out: dict = {"definition": {
        "severity": "sev_ord 降序（critical>high>medium>low>info，id 稳定并列）",
        "rule_based": "Lv0 核心 + CMS 联动优先，再 severity 降序（对齐引擎选择哲学）",
        "prior_hits": "该 (host,check) 历史 as-of 命中次数降序（严格时间截断）",
        "random": "均匀随机（seed 固定可复现）",
        "cvss_order": "intel 候选按 CVSS 降序——无可观测结局（verified 与 intel "
                      "候选无可靠联接），不评指标，仅定义",
        "kev_first": "同上（KEV 红标优先），不评指标",
    }}
    queries = {}
    for uid in per_query:
        g = cand_feat[cand_feat["scan_uid"] == uid]
        queries[uid] = g
    baselines = {
        "severity": severity_baseline,
        "rule_based": rule_baseline,
        "prior_hits": prior_hits_baseline,
        "random": random_baseline,
    }
    for name, fn in baselines.items():
        ranked = {uid: _rank_candidates(fn(g), "score", "check_id")
                  for uid, g in queries.items()}
        out[name] = metrics.eval_ranking(ranked, per_query_rel, ks=(5, 10))
    out["queries_detail"] = {
        "n_queries": len(queries),
        "positives_total": int(sum(len(v) for v in per_query_rel.values())),
    }
    return out
