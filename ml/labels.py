"""标签构建（P4）。

纪律（开发文档 §4 / 执行原则 4-5）：
  - L1 三分：executed∧命中=positive；executed∧未命中=negative（负样本唯一
    合法来源=引擎 check_runs 执行日志； executions 为空时可靠 negative=0，
    结构上不可能出现其它来源）；未执行/不可判定=unknown，绝不作为 negative；
  - L3 confirmed-verdict：sanity / pipeline validation 任务（规则蒸馏）；
  - L5 exploit：当前 0 样本，显式 disabled；
  - 每个标签附 POLE（口径与可靠性声明）。
"""

from __future__ import annotations

import pandas as pd

from . import config


def build_l1(verified: pd.DataFrame, candidates: pd.DataFrame,
             executions: pd.DataFrame | None = None) -> tuple[pd.DataFrame, dict]:
    """L1 verified-hit：返回 (rows, pole)。

    rows：positive 行（verified）+ negative 行（executions 的 executed∧未命中）
    + unknown 行（候选集中既无命中也无执行证据者），role 列显式区分。
    executions=None 或为空时 negative 恒为空（旧数据兼容，纪律不变）。
    """
    if len(verified):
        pos = verified[verified["execution_status"] == config.EXEC_EXECUTED].copy()
        pos["role"] = "positive"
        pos["item_id"] = pos["check"]
    else:
        pos = verified.assign(role="positive", item_id="")

    hit_keys = set(zip(pos.get("scan_uid", []), pos.get("item_id", [])))

    # negative：唯一合法来源 = check_runs 的 executed ∧ 未命中
    if executions is not None and len(executions):
        exec_neg = executions[
            (executions["execution_status"] == config.EXEC_EXECUTED)
            & (~executions["hit"].astype(bool))].copy()
        # 结构复核：与 verified 命中冲突的键以 verified 为准（防御性排除）
        exec_neg = exec_neg[~exec_neg.apply(
            lambda r: (r["scan_uid"], r["check_id"]) in hit_keys, axis=1)]
    else:
        exec_neg = pd.DataFrame(columns=["scan_uid", "host", "scanned_at_dt",
                                         "check_id", "execution_status"])
    neg = exec_neg.copy()
    neg["role"] = "negative"
    neg["item_id"] = neg["check_id"]
    neg["execution_basis"] = "引擎 check_runs：executed ∧ 未命中（可靠负样本）"

    # unknown：候选集中既无命中也无 executed 执行证据者
    exec_keys = set()
    if executions is not None and len(executions):
        exec_done = executions[executions["execution_status"] == config.EXEC_EXECUTED]
        exec_keys = set(zip(exec_done["scan_uid"], exec_done["check_id"]))
    if len(candidates):
        mask = ~candidates.apply(
            lambda r: (r["scan_uid"], r["check_id"]) in hit_keys
            or (r["scan_uid"], r["check_id"]) in exec_keys, axis=1)
        unk = candidates[mask].copy()
    else:
        unk = candidates.copy()
    unk["role"] = "unknown"
    unk["item_id"] = unk["check_id"]

    cols = ["scan_uid", "host", "scanned_at_dt", "item_id", "role",
            "execution_status", "execution_basis"]

    def _take(df: pd.DataFrame) -> pd.DataFrame:
        return df[cols] if len(df) else pd.DataFrame(columns=cols)

    rows = pd.concat([_take(pos), _take(neg), _take(unk)], ignore_index=True)

    # 结构断言：negative 必须全部来自 executions 的 executed∧未命中；
    # verified/executions 之外的任何来源出现在 negative 里即为程序错误。
    assert len(neg) == 0 or (neg["execution_status"] == config.EXEC_EXECUTED).all(), \
        "negative 计数只能来自 executed∧未命中事件的实证"
    pole = {
        "label_id": "L1",
        "name": "verified-hit",
        "positive_def": "executed ∧ 命中（verified 落库行）",
        "negative_def": "executed ∧ 未命中（check_runs 执行日志实证；"
                        "无执行日志时恒为 0）",
        "unknown_policy": "候选集中无命中且无执行证据者为 unknown；不得作为 "
                          "negative 训练或计入负类指标分母",
        "negative_count": int(len(neg)),
        "counts": {"positive": int((rows["role"] == "positive").sum()),
                   "negative": int((rows["role"] == "negative").sum()),
                   "unknown": int((rows["role"] == "unknown").sum())},
        "reliability": "positive 高（判定即规则）；negative 高（执行证据即规则）；"
                       "unknown 不可用",
        "notes": "T1/T2 训练受 P5 数据 gate 约束（开发文档 §5）；"
                 "negative>0 时 gate 方可放行",
    }
    return rows, pole


def build_l3(intel: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """L3 confirmed-verdict（sanity）：confirmed=1 / possible=0；
    verdict 缺失行排除并计数；空表/无 verdict 列时安全返回空。"""
    if len(intel) == 0 or "verdict" not in intel.columns:
        empty = intel.copy()
        empty["label"] = pd.Series(dtype=int)
        return empty, {
            "label_id": "L3", "name": "confirmed-verdict",
            "definition": "引擎三级判定的 confirmed（版本落受影响区间）",
            "role": "sanity / pipeline validation task（规则蒸馏），"
                    "不是 5.0 核心智能能力，不投入主要资源",
            "counts": {"rows": 0, "positive": 0,
                       "excluded_missing_verdict": 0},
            "reliability": "标签由 versioncmp/区间规则确定，模型学它仅验证管线正确性",
        }
    df = intel[intel["verdict"].isin(["confirmed", "possible"])].copy()
    df["label"] = (df["verdict"] == "confirmed").astype(int)
    excluded = int(len(intel) - len(df))
    pole = {
        "label_id": "L3",
        "name": "confirmed-verdict",
        "definition": "引擎三级判定的 confirmed（版本落受影响区间）",
        "role": "sanity / pipeline validation task（规则蒸馏），"
                "不是 5.0 核心智能能力，不投入主要资源",
        "counts": {"rows": int(len(df)),
                   "positive": int(df["label"].sum()),
                   "excluded_missing_verdict": excluded},
        "reliability": "标签由 versioncmp/区间规则确定，模型学它仅验证管线正确性",
    }
    return df, pole


def build_l5(verified: pd.DataFrame) -> dict:
    """L5 exploit-proven：当前 0 样本 → 显式 disabled（绝不伪造）。"""
    n = int(verified["impact"].notna().sum()) if len(verified) else 0
    return {
        "label_id": "L5",
        "name": "exploit-proven",
        "samples": n,
        "status": "disabled" if n == 0 else "enabled",
        "reason": "历史 119 次扫描全部未开利用级总闸（impact 全空）；"
                  "样本为 0 时不得训练，也不得以 Severity 顶替",
    }
