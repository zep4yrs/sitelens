"""切分构建（P5/P8）：host-aware / time-aware，含 target≡host 等价性检查。

纪律（开发文档 Phase 5/8）：
  - 同一 host 任何情况下不得跨 train/test（host 组是隔离原子）；
  - 当前数据 target≡host（一扫一主机），target split 与 host split 重合，
    不得伪造两个独立实验；仅当等价性检查发现独立 target group 时才分别统计。
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def split_equivalence_report(scans: pd.DataFrame) -> dict:
    """target 与 host 的对应关系。

    若每 host 恰一个目标 URL → target split ≡ host split，二者不可分，
    只保留 host split。若某 host 有多个目标 URL（如同机多端口应用），
    也不做 target split：按 URL 切分会把同一 host 的目标分进两侧，
    引入 host 级交叉泄漏——host split 是更严口径，一律以它为准。
    """
    if not len(scans):
        return {"independent_target_groups": False, "targets_per_host": {},
                "conclusion": "空表"}
    per_host = scans.groupby("host")["url"].nunique()
    multi = {k: int(v) for k, v in per_host.items() if v > 1}
    conclusion = (
        "target 与 host 一一等价：只保留 host split，target split 不单独统计"
        if not multi else
        f"存在一 host 多目标（{multi}），但同 host 多目标属同一资产族；"
        "按 URL 切分会引入 host 级交叉，故只保留更严的 host split，"
        "target split 不单独统计")
    return {
        "independent_target_groups": False,
        "targets_per_host": {k: int(v) for k, v in per_host.items()},
        "hosts_with_multiple_targets": multi,
        "conclusion": conclusion,
    }


def leave_one_host_out(scans: pd.DataFrame):
    """LOHO：每次留出一个 host 作 test。返回 [(test_host, train_df, test_df)]。"""
    folds = []
    for host in sorted(scans["host"].dropna().unique()):
        test = scans[scans["host"] == host]
        train = scans[scans["host"] != host]
        assert_host_disjoint(train["host"], test["host"])
        folds.append((host, train, test))
    return folds


def time_split(scans: pd.DataFrame, train_frac: float = 0.8):
    """全局时间切分：早段 train / 晚段 test（边界按 scanned_at 排序）。

    说明：该口径下同一 host 可能同时出现在 train/test——检验的是时间泛化，
    不是资产泛化；先验特征仍严格 as-of（不使用任何晚于样本自身时点的记录）。
    """
    df = scans.dropna(subset=["scanned_at_dt"]).sort_values("scanned_at_dt")
    k = int(len(df) * train_frac)
    train = df.iloc[:k]
    test = df.iloc[k:]
    if len(train) and len(test):
        assert train["scanned_at_dt"].max() <= test["scanned_at_dt"].min(), \
            "time split 边界重叠"
    return train, test


def assert_host_disjoint(train_hosts, test_hosts) -> None:
    overlap = set(train_hosts) & set(test_hosts)
    if overlap:
        raise AssertionError(f"host 泄漏：以下 host 同时出现在 train/test：{sorted(overlap)}")


def assign_folds(scans: pd.DataFrame) -> pd.Series:
    """给每行一个 LOHO fold 号（= 其 host 的序号），便于 OOF 汇总。"""
    hosts = sorted(scans["host"].dropna().unique())
    return scans["host"].map({h: i for i, h in enumerate(hosts)})


def check_split_leakage(split_name: str, train_df: pd.DataFrame,
                        test_df: pd.DataFrame) -> dict:
    assert_host_disjoint(train_df.get("host", []), test_df.get("host", []))
    return {"split": split_name, "train_rows": int(len(train_df)),
            "test_rows": int(len(test_df)),
            "train_hosts": int(train_df["host"].nunique()) if len(train_df) else 0,
            "test_hosts": int(test_df["host"].nunique()) if len(test_df) else 0,
            "host_disjoint": True}
