"""标签构建（P4）。

纪律（开发文档 §4 / 执行原则 4-5）：
  - L1 三分：executed∧命中=positive；executed∧未命中=negative（当前历史
    无执行日志，可靠 negative=0，函数内断言）；未执行/不可判定=unknown，
    绝不作为 negative；
  - L3 confirmed-verdict：sanity / pipeline validation 任务（规则蒸馏）；
  - L5 exploit：当前 0 样本，显式 disabled；
  - 每个标签附 POLE（口径与可靠性声明）。
"""

from __future__ import annotations

import pandas as pd

from . import config


def build_l1(verified: pd.DataFrame, candidates: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """L1 verified-hit：返回 (rows, pole)。

    rows：positive 行（来自 verified）+ unknown 行（候选集中未见命中者），
    role 列显式区分；negative 恒为空集并断言。
    """
    if len(verified):
        pos = verified[verified["execution_status"] == config.EXEC_EXECUTED].copy()
        pos["role"] = "positive"
        pos["item_id"] = pos["check"]
    else:
        pos = verified.assign(role="positive", item_id="")

    hit_keys = set(zip(pos.get("scan_uid", []), pos.get("item_id", [])))
    if len(candidates):
        unk = candidates[~candidates.apply(
            lambda r: (r["scan_uid"], r["check_id"]) in hit_keys, axis=1)].copy()
    else:
        unk = candidates.copy()
    unk["role"] = "unknown"
    unk["item_id"] = unk["check_id"]

    cols = ["scan_uid", "host", "scanned_at_dt", "item_id", "role",
            "execution_status", "execution_basis"]
    rows = pd.concat([pos[cols], unk[cols]], ignore_index=True)

    n_neg = 0  # 唯一合法来源是 executed∧未命中；历史无执行日志，恒 0 并断言
    assert n_neg == 0, "negative 计数只能来自 executed∧未命中事件的实证"
    pole = {
        "label_id": "L1",
        "name": "verified-hit",
        "positive_def": "executed ∧ 命中（verified 落库行）",
        "negative_def": "executed ∧ 未命中（需执行日志实证；当前历史无此记录）",
        "unknown_policy": "候选集中未见命中者全部为 unknown；不得作为 negative "
                          "训练或计入负类指标分母",
        "negative_count": n_neg,
        "counts": {"positive": int((rows["role"] == "positive").sum()),
                   "unknown": int((rows["role"] == "unknown").sum())},
        "reliability": "positive 高（判定即规则）；negative 不可用",
        "notes": "T1 训练受 P5 数据 gate 约束（开发文档 §5）",
    }
    return rows, pole


def build_l3(intel: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """L3 confirmed-verdict（sanity）：confirmed=1 / possible=0；
    verdict 缺失行排除并计数。"""
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
