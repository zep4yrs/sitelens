"""数据质量报告与 P5 数据 gate（真实统计，决定任务可训练性）。

gate 结论只从真实计数推导（开发文档 Phase 5）：
  - T1 训练：需要 executed∧未命中 的实证负样本；无执行日志 → BLOCKED；
  - T2 训练（监督二分类）：同上 BLOCKED；T2 基线排序评估：候选集与
    观测正例皆非空才 ALLOWED；
  - L3 / T3（sanity）：样本非空即 ALLOWED（仅管线验证，不作能力声明）。
"""

from __future__ import annotations

import pandas as pd

from . import config, labels


def quality_report(scans: pd.DataFrame, techs: pd.DataFrame, intel: pd.DataFrame,
                   verified: pd.DataFrame, candidates: pd.DataFrame) -> dict:
    rep: dict = {}

    # 重复样本（同一 host+check+url 的命中行多次出现 = 重扫时间序列）
    if len(verified):
        dup = verified.groupby(["host", "check", "url"]).size()
        rep["verified_dup_groups"] = {
            "distinct_keys": int(len(dup)),
            "keys_with_multiple_hits": int((dup > 1).sum()),
            "max_repeats": int(dup.max()) if len(dup) else 0,
        }
    # 类别不平衡
    if len(verified):
        rep["verified_by_src"] = {k: int(v) for k, v in verified["src"].value_counts().items()}
    if len(intel):
        rep["intel_by_verdict"] = {k: int(v) for k, v in
                                   intel["verdict"].value_counts(dropna=False).items()}
        rep["intel_severity_norm"] = {k: int(v) for k, v in
                                      intel["severity_norm"].value_counts(dropna=False).items()}
    # 稀疏性
    if len(techs):
        rep["tech_rows"] = int(len(techs))
        rep["tech_unique"] = int(techs["name"].nunique())
        rep["tech_with_version"] = int(techs["has_version"].sum())
    # execution unknown 占比（T1/T2 的关键约束）
    if len(candidates):
        rep["candidates_execution"] = {
            k: int(v) for k, v in candidates["execution_status"].value_counts().items()}
    if len(scans):
        rep["scans_per_host"] = {k: int(v) for k, v in scans["host"].value_counts().items()}
        rep["per_host_first_last"] = {
            h: [str(g["scanned_at_dt"].min()), str(g["scanned_at_dt"].max())]
            for h, g in scans.dropna(subset=["scanned_at_dt"]).groupby("host")}
    # 情报截断偏差提示（engine maxPerTech=20 / 单 CVE 模板≤6，审计报告 §9.7）
    rep["known_truncations"] = [
        "单技术最多 20 条情报（intel.go maxPerTech）",
        "单 CVE 最多挂 6 条模板（engine.go attachTemplates）",
        "微软公告每扫描 20 条封顶（engine.go MatchCVEMs limit）",
    ]
    return rep


def gate_report(scans: pd.DataFrame, intel: pd.DataFrame, verified: pd.DataFrame,
                candidates: pd.DataFrame) -> dict:
    l1_rows, l1_pole = labels.build_l1(verified, candidates)
    n_neg = l1_pole["negative_count"]
    n_pos = l1_pole["counts"]["positive"]
    cand_n = int(len(candidates))
    hit_in_candidates = 0
    if len(verified) and cand_n:
        hit_keys = set(zip(verified[verified["src"] == "check"]["scan_uid"],
                           verified[verified["src"] == "check"]["check"]))
        hit_in_candidates = int(sum(
            1 for uid, cid in zip(candidates["scan_uid"], candidates["check_id"])
            if (uid, cid) in hit_keys))
    l3_df, _ = labels.build_l3(intel)
    n_scored = int(scans["security_score"].notna().sum()) if len(scans) else 0

    return {
        "T1_train": {"verdict": "BLOCKED",
                     "reason": f"可靠负样本（executed∧未命中实证）={n_neg}；"
                               f"无执行日志，unknown={cand_n - hit_in_candidates} 不得作负样本",
                     "positive": n_pos},
        "T2_train_supervised": {"verdict": "BLOCKED",
                                "reason": "同 T1：无 executed 证据不得构造负样本；"
                                          "正例排序训练亦需不可伪造的反例校准"},
        "T2_baseline_ranking_eval": {
            "verdict": "ALLOWED" if hit_in_candidates > 0 and cand_n > 0 else "BLOCKED",
            "candidates": cand_n,
            "observed_positives_in_candidates": hit_in_candidates,
            "note": "T2 evaluation target=内置 check 候选集；nuclei 候选不可复原"
                    "（LRU 选取无日志）、CVE 候选联接不可行（nuclei_index 无模板"
                    " yaml id 字段），均如实排除"},
        "L3_sanity": {"verdict": "ALLOWED" if len(l3_df) > 0 else "BLOCKED",
                      "rows": int(len(l3_df)),
                      "note": "仅 sanity / pipeline validation"},
        "T3_sanity": {"verdict": "ALLOWED" if n_scored > 0 else "BLOCKED",
                      "rows": n_scored,
                      "note": "安全评分回归仅 sanity；特征不含响应头评分项"},
        "L5": labels.build_l5(verified),
    }
