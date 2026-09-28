"""规范化（P2）：severity / verdict / era / 时间戳。

severity 归一依据：
  - 引擎四档 + info：critical/high/medium/low/info（小写为准，大小写混排收敛）；
  - 微软公告（cve_ms / ms-bulletin 来源）的 Critical/Important 按 MS 安全公告
    分级（Critical > Important > Moderate > Low）映射 critical/medium；
  - 无法识别的值归 None（显式 missing），绝不猜测。
"""

from __future__ import annotations

from datetime import datetime

import pandas as pd

from . import config

SEVERITY_MAP = {
    "critical": "critical", "Critical": "critical",
    "high": "high", "High": "high",
    "medium": "medium", "Medium": "medium", "moderate": "medium", "Moderate": "medium",
    "important": "medium", "Important": "medium",
    "low": "low", "Low": "low",
    "info": "info", "Info": "info",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

VERDICT_KNOWN = {"confirmed", "possible", "excluded"}


def norm_severity(raw) -> str | None:
    if raw is None:
        return None
    return SEVERITY_MAP.get(str(raw).strip())


def parse_scanned_at(raw) -> datetime | None:
    """引擎格式 '2006-01-02 15:04:05'；解析失败返回 NaT（显式 missing）。"""
    if not raw:
        return None
    ts = pd.to_datetime(raw, format="%Y-%m-%d %H:%M:%S", errors="coerce")
    return None if pd.isna(ts) else ts.to_pydatetime()


def norm_verdict(raw) -> str | None:
    """verdict 空串/缺失 → None（premigrate 旧 schema 实证 169 行，显式 missing）。"""
    if raw is None:
        return None
    v = str(raw).strip().lower()
    return v if v in VERDICT_KNOWN else None


def norm_check_level(raw) -> str | None:
    """options.checks 的合法档位；'none' 表示 check 引擎关闭。"""
    if raw is None:
        return None
    v = str(raw).strip().lower()
    return v if v in {"none", "core", "all"} else None


def era_of(origin: str, scan_id) -> str:
    """era 判定（审计报告 §7）：history id<=47 为 migrate-pg 迁入的 Python 时代
    记录；premigrate 全部为 py；matrix/go 其余为 go。"""
    if origin == "premigrate":
        return "py"
    if origin == "history":
        try:
            return "py" if int(scan_id) <= config.PY_ERA_MAX_HISTORY_ID else "go"
        except (TypeError, ValueError):
            return "go"
    return "go"


def evidence_channels(evidences) -> list[str]:
    """从指纹证据字符串前缀解析证据通道类型（fingerprint.go 通道语义）。

    形态：'header: X=…' / 'cookie xxx' / 'meta a=b' / '正则 …' / '关键词 …' /
    'src …' / '内联JS …' / 'icon_hash=123'
    """
    out: list[str] = []
    for e in evidences or []:
        s = str(e)
        if s.startswith("header:"):
            ch = "header"
        elif s.startswith("cookie"):
            ch = "cookie"
        elif s.startswith("meta "):
            ch = "meta"
        elif s.startswith("正则"):
            ch = "html_regex"
        elif s.startswith("关键词"):
            ch = "html_keyword"
        elif s.startswith("src "):
            ch = "script_src"
        elif s.startswith("内联JS"):
            ch = "script_inline"
        elif s.startswith("icon_hash="):
            ch = "icon_hash"
        else:
            ch = "other"
        if ch not in out:
            out.append(ch)
    return out
