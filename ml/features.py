"""特征构建（P3）。

硬规则（开发文档 §3）：一切历史先验特征必须满足
  feature_time < prediction_time
即对 prediction_time=T 的样本，只允许聚合 scanned_at 严格早于 T 的记录
（同刻记录也禁入：同时刻产生的结果在预测时点不可能已知）。
实现：as-of 聚合器统一走 searchsorted(side='left') 前缀统计，
由 ml/tests 与 ml/leakage.py 的注入回归双重验证。

黑名单（禁入特征，P5 断言）：impact / impact_evidence / exploit 结果 /
replay 结果——它们是未来结果（F 语义），不是预测时点可知的信息。
"""

from __future__ import annotations

from urllib.parse import urlparse

import numpy as np
import pandas as pd

from . import config

# 特征黑名单（F 语义字段；出现即泄漏）
FEATURE_BLACKLIST = {"impact", "impact_evidence", "exploit_proven", "exploit_observed",
                     "replay_status", "regression_present"}

SEV_ORD = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# 情报行 src 词表（审计报告 §7 实测出现的全部取值）
INTEL_SRCS = ["afrog", "tscan", "xray", "cve_ms", "ms-bulletin", "tpl"]


def check_blacklist(columns) -> None:
    bad = FEATURE_BLACKLIST & set(map(str, columns))
    if bad:
        raise AssertionError(f"特征表含黑名单（未来结果）字段：{sorted(bad)}")


def _times_strictly_before(sorted_times: np.ndarray, t) -> int:
    """升序时间数组中严格早于 t 的元素个数（NaT 安全）。"""
    if sorted_times is None or len(sorted_times) == 0 or t is None or pd.isna(t):
        return 0
    return int(np.searchsorted(sorted_times, np.datetime64(t), side="left"))


def _host_time_index(events: pd.DataFrame, value_col: str | None = None):
    """按 host 分组的升序时间数组（可选伴随值数组）。剔除 NaT 时间。"""
    ev = events.dropna(subset=["scanned_at_dt"])
    out = {}
    for host, g in ev.groupby("host"):
        g = g.sort_values("scanned_at_dt")
        times = g["scanned_at_dt"].to_numpy(dtype="datetime64[ns]")
        if value_col is not None:
            out[host] = (times, g[value_col].to_numpy())
        else:
            out[host] = times
    return out


def _asof_last_value(index: dict, host, t):
    pair = index.get(host)
    if pair is None or t is None or pd.isna(t):
        return None
    times, values = pair
    idx = int(np.searchsorted(times, np.datetime64(t), side="left"))
    return values[idx - 1] if idx > 0 else None


def add_scan_priors(scans: pd.DataFrame, verified: pd.DataFrame,
                    intel: pd.DataFrame) -> pd.DataFrame:
    """站点级 as-of 先验（开发文档 §3 穷举清单的扫描级部分）：
    prior_scan_count / prior_verified_count / prior_intel_count /
    prior_sec_score_last（该 host 上一次安全评分）。"""
    ver_idx = _host_time_index(verified) if len(verified) else {}
    int_idx = _host_time_index(intel) if len(intel) else {}
    scored = scans.dropna(subset=["security_score"]) if len(scans) else scans
    score_idx = _host_time_index(scored, value_col="security_score") if len(scored) else {}
    scan_idx = _host_time_index(scans) if len(scans) else {}

    rows = []
    for host, t in zip(scans["host"], scans["scanned_at_dt"]):
        rows.append({
            "prior_scan_count": _times_strictly_before(scan_idx.get(host), t),
            "prior_verified_count": _times_strictly_before(ver_idx.get(host), t),
            "prior_intel_count": _times_strictly_before(int_idx.get(host), t),
            "prior_sec_score_last": _asof_last_value(score_idx, host, t),
        })
    priors = pd.DataFrame(rows, index=scans.index)
    return scans.drop(columns=[c for c in priors.columns if c in scans.columns]).join(priors)


def build_scan_features(scans: pd.DataFrame, techs: pd.DataFrame,
                        verified: pd.DataFrame, intel: pd.DataFrame,
                        top_techs: int = 30) -> tuple[pd.DataFrame, list[str]]:
    """T3 sanity（安全评分）特征：扫描时点已知/产物信息。

    不含 security.items（8 个响应头加权即标签来源，纳入即标签泄漏）。
    站点先验（verified/intel 计数）在函数内按 as-of 规则计算。
    """
    df = scans.copy()
    parsed = df["url"].fillna("").map(urlparse)
    df["scheme_https"] = parsed.map(lambda u: 1 if u.scheme == "https" else 0)
    df["port"] = parsed.map(lambda u: u.port or
                            (443 if u.scheme == "https" else 80 if u.scheme == "http" else 0))
    df["is_private_ip"] = df["ip"].fillna("").map(
        lambda ip: str(ip).startswith(("10.", "192.168.", "172.")) or ip == "127.0.0.1"
    ).astype(int)
    df["n_tech"] = df["tech_count"].fillna(0).astype(int)
    df["page_count_f"] = df["page_count"].fillna(0).astype(int)
    df["era_go"] = (df["era"] == "go").astype(int)
    if len(techs):
        vocab = techs["name"].value_counts().head(top_techs).index.tolist()
        present = techs.groupby("scan_uid")["name"].apply(set).to_dict()
        for name in vocab:
            df[f"tech_{name}"] = df["scan_uid"].map(
                lambda u, n=name: 1 if n in present.get(u, set()) else 0)
    df = add_scan_priors(df, verified, intel)
    df["has_prior_score"] = df["prior_sec_score_last"].notna().astype(int)
    df["prior_sec_score_last"] = df["prior_sec_score_last"].fillna(0.0)
    feat_cols = [c for c in df.columns if c.startswith(("scheme_", "tech_", "era_"))
                 or c in {"port", "is_private_ip", "n_tech", "page_count_f",
                          "prior_scan_count", "prior_verified_count",
                          "prior_intel_count", "prior_sec_score_last",
                          "has_prior_score"}]
    check_blacklist(feat_cols)
    return df, feat_cols


def build_intel_features(intel: pd.DataFrame, cve_features: pd.DataFrame,
                         top_techs: int = 20) -> tuple[pd.DataFrame, list[str]]:
    """L3 sanity 任务特征（情报行级）。标签本身是引擎 verdict（规则蒸馏，
    仅作管线验证，开发文档 §4）。"""
    df = intel.copy()
    df["sev_ord"] = df["severity_norm"].map(SEV_ORD).fillna(-1).astype(int)
    df["has_cvss"] = df["cvss_score"].notna().astype(int)
    df["cvss_score_f"] = df["cvss_score"].fillna(0.0).astype(float)
    df["kev_f"] = df["kev"].astype(int)
    df["has_templates"] = (df["n_templates"] > 0).astype(int)
    df["has_version"] = (df["version"].fillna("") != "").astype(int)
    if len(cve_features):
        cf = cve_features.set_index("cve")
        if "n_tpl_intel" in cf.columns:
            df["n_tpl_intel"] = df["cve"].map(cf["n_tpl_intel"]).fillna(0).astype(int)
        else:
            df["n_tpl_intel"] = 0
        if "in_curated_range" in cf.columns:
            df["in_curated_range"] = df["cve"].map(cf["in_curated_range"]).fillna(0).astype(int)
        else:
            df["in_curated_range"] = 0
    else:
        df["n_tpl_intel"] = 0
        df["in_curated_range"] = 0
    vocab = df["tech"].value_counts().head(top_techs).index.tolist()
    for name in vocab:
        df[f"itech_{name}"] = (df["tech"] == name).astype(int)
    for s in INTEL_SRCS:
        df[f"src_{s}"] = (df["src"] == s).astype(int)
    feat_cols = [c for c in df.columns if c.startswith(("itech_", "src_"))
                 or c in {"sev_ord", "has_cvss", "cvss_score_f", "kev_f",
                          "has_templates", "has_version", "n_tpl_intel",
                          "in_curated_range"}]
    check_blacklist(feat_cols)
    return df, feat_cols


def build_candidate_features(candidates: pd.DataFrame, verified: pd.DataFrame,
                             scans: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """T2 候选排序特征（verification target = 内置 check）。

    prior_hits_this_check：该 (host, check) 在严格早于 prediction_time 的
    扫描中的命中次数（as-of，时间截断）。
    """
    df = candidates.sort_values(["host", "scanned_at_dt", "check_id"]).reset_index(drop=True)
    hits = verified[verified["src"] == "check"] if len(verified) else verified
    pair_idx: dict[str, np.ndarray] = {}
    if len(hits):
        ev = hits.dropna(subset=["scanned_at_dt"]).copy()
        ev["host_check"] = ev["host"] + "\x00" + ev["check"]
        for key, g in ev.groupby("host_check"):
            pair_idx[key] = g.sort_values("scanned_at_dt")[
                "scanned_at_dt"].to_numpy(dtype="datetime64[ns]")
    df["prior_hits_this_check"] = [
        _times_strictly_before(pair_idx.get(h + "\x00" + c), t)
        for h, c, t in zip(df["host"], df["check_id"], df["scanned_at_dt"])
    ]
    df["sev_ord"] = df["check_severity"].map(SEV_ORD).fillna(-1).astype(int)
    df["cms_linked_flag"] = df["cms_linked"].astype(int)
    feat_cols = ["check_lv", "sev_ord", "cms_linked_flag", "prior_hits_this_check"]
    check_blacklist(feat_cols)
    return df, feat_cols
