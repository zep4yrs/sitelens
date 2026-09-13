"""泄漏检查（P5）：可执行断言 + 注入回归，不是文档声明。

三道检查（开发文档 §3/Phase 5）：
  1. assert_no_blacklist：特征表不含未来结果字段（impact/exploit/replay…）；
  2. assert_asof_injection：向原始事件注入"未来"记录后，全部历史样本的
     先验特征必须逐值不变（feature_time < prediction_time 的回归验证）；
  3. assert_host_disjoint：任何 split 中 host 不得跨 train/test。
任一失败抛 AssertionError，评估不得开始。
"""

from __future__ import annotations

import pandas as pd

from . import features
from .splits import assert_host_disjoint  # re-export


def assert_asof_injection(scans: pd.DataFrame, verified: pd.DataFrame,
                          intel: pd.DataFrame, feature_cols: list[str],
                          prior_cols: list[str]) -> dict:
    """注入回归：加入晚于全部现有扫描的伪造事件，先验特征不得变化。

    注意：伪造事件只存在于本检查的内存副本中，用于验证 as-of 过滤器；
    不是训练数据（不落盘、不进任何表）。
    """
    base = features.add_scan_priors(scans, verified, intel)
    future_t = scans["scanned_at_dt"].max()
    future_t = future_t + pd.Timedelta(days=1) if pd.notna(future_t) else pd.Timestamp.now()

    fv = pd.concat([verified, pd.DataFrame([{
        "scan_uid": "INJECT:V", "host": scans["host"].iloc[0],
        "scanned_at_dt": future_t, "src": "check", "check": "injected",
        "execution_status": "executed",
    }])], ignore_index=True) if len(verified) else verified
    fi = pd.concat([intel, pd.DataFrame([{
        "scan_uid": "INJECT:I", "host": scans["host"].iloc[0],
        "scanned_at_dt": future_t, "cve": "CVE-INJECTED", "src": "afrog",
        "kev": False, "n_templates": 0,
    }])], ignore_index=True) if len(intel) else intel

    after = features.add_scan_priors(scans, fv, fi)
    for col in prior_cols:
        a = base[col]
        b = after[col]
        if a.dtype.kind in "fc" and col in ("prior_sec_score_last",):
            same = (a.fillna(-1) == b.fillna(-1)).all()
        else:
            same = (a == b).all()
        if not same:
            raise AssertionError(
                f"as-of 泄漏：注入未来记录改变了先验特征列 {col}")
    return {
        "check": "asof_injection",
        "passed": True,
        "rows": int(len(scans)),
        "prior_cols_checked": prior_cols,
        "note": "注入 1 条晚于全部样本的 verified/intel 记录，先验逐值不变",
    }


def assert_prior_upper_bound(scans: pd.DataFrame) -> dict:
    """边界断言：最早一次扫描（该 host 首扫）的先验计数必须为 0——
    它之前没有该 host 的任何记录可用。"""
    df = scans.dropna(subset=["scanned_at_dt"])
    if not len(df):
        return {"check": "prior_upper_bound", "passed": True, "note": "空表"}
    first = df.sort_values("scanned_at_dt").groupby("host").head(1)
    bad = first[first["prior_scan_count"] != 0]
    if len(bad):
        raise AssertionError(
            f"as-of 泄漏：host 首扫的 prior_scan_count 应为 0，"
            f"实际非零 {len(bad)} 行：{bad['scan_uid'].tolist()[:5]}")
    return {"check": "prior_upper_bound", "passed": True,
            "first_scans_checked": int(len(first))}


def leakage_report(scans: pd.DataFrame, feature_tables: dict[str, list[str]]) -> dict:
    """汇总全部特征表的黑名单检查。"""
    out = {"tables": {}, "passed": True}
    for name, cols in feature_tables.items():
        try:
            features.check_blacklist(cols)
            out["tables"][name] = {"blacklist": "pass", "n_features": len(cols)}
        except AssertionError as e:
            out["tables"][name] = {"blacklist": "FAIL", "error": str(e)}
            out["passed"] = False
    return out
