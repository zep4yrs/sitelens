"""4.0 → 5.0 数据接口 schema（Phase 11：只定义，不实现适配器，不改 4.0）。

v4.0 尚在开发（当前主线=资源占用治理，攻击链视角未开工，审计报告 §5）。
本模块只冻结 5.0 侧的只读投影契约：4.0 数据落地后按此 schema 挂接，
未落地前相关特征位保持显式 missing——禁止用 0/空串冒充，禁止提前实现。

九类投影（开发文档 Phase 11 / 审计报告 §19）。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

MISSING = "missing"  # 显式缺失哨兵：字段不存在时必须用它，不得用 0/""/None 冒充


@dataclass
class VulnNode:
    """漏洞节点（4.0 黑白盒归一后的漏洞视图）。"""
    id: str
    cve: str = MISSING
    cwes: list = field(default_factory=list)          # 等 4.0 CWE 关系
    tech_ref: str = MISSING
    evidence_refs: list = field(default_factory=list)
    source: str = MISSING                              # blackbox | whitebox
    cwe_rels: list = field(default_factory=list)       # 等 4.0


@dataclass
class ChainNode:
    """攻击链节点：entry / action / privilege / impact。"""
    id: str
    kind: str = MISSING            # entry|action|privilege|impact
    ref: str = MISSING             # 指向发现/入口点 id
    privilege_change: str = MISSING  # before→after（等 4.0 权限变化）


@dataclass
class ChainEdge:
    id: str
    src_node: str = MISSING
    dst_node: str = MISSING
    relation: str = MISSING
    evidence_ref: str = MISSING


@dataclass
class EntryPoint:
    url: str = MISSING
    param: str = MISSING
    kind: str = MISSING            # url|param|endpoint
    reachable: bool | None = None  # None=未知（显式）


@dataclass
class DataFlow:
    source: str = MISSING
    sink: str = MISSING
    path_ref: str = MISSING        # 等 4.0 真数据流分析（当前仅 TAINT-lite 行级近似）


@dataclass
class ImpactRecord:
    kind: str = MISSING
    evidence_ref: str = MISSING
    verdict: str = MISSING         # proven | observed | none（对齐 3.0 exploit 语义）


@dataclass
class EvidenceLink:
    finding_a: str = MISSING
    finding_b: str = MISSING
    relation: str = MISSING


# 白盒/黑盒证据沿用现有结构：
#   blackbox → verified map（request/response/signals/confirmed，审计报告 §8）
#   whitebox → audit.Finding（rule/severity/file/line/snippet，需 4.0 落库）

WAITING_FOR_40 = [
    "VulnNode.cwes / cwe_rels（全库无 CWE 字段；NVD 投影可先行补列，属数据包工程）",
    "ChainNode / ChainEdge（攻击链主线未开工，docs/开发文档-4.0.md 仅立项语）",
    "EntryPoint（jsmap.Endpoint 是采集物，语义不同）",
    "DataFlow（TAINT-lite 行级近似≠真数据流）",
    "privilege_change（无权限状态机）",
    "EvidenceLink（跨发现关联未实现）",
    "Whitebox Evidence 持久化（audit 结果即焚，审计报告 §3）",
]


def to_dict(obj) -> dict:
    d = asdict(obj)
    return {k: (MISSING if v == MISSING else v) for k, v in d.items()}


def waiting_list() -> list[str]:
    return list(WAITING_FOR_40)
