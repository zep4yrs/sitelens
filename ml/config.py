"""路径解析与全局常量（P1 数据基础设施）。

数据根目录解析优先级：
  1. 显式参数（CLI --data-root）
  2. 环境变量 SITLENS_DATA_ROOT
  3. ./data（当前目录下存在时）

输出根目录：显式参数 > SITLENS_ML_OUT > ./data/ml。
真实数据与产物一律不进 git（.gitignore）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# ---- 扫描记录来源（data_origin）----
ORIGIN_HISTORY = "history"          # data/state/history.json（Go 3.0 serve 落库）
ORIGIN_PREMIGRATE = "premigrate"    # history.json.premigrate（Python 时代迁移前快照）
ORIGIN_ARCHIVE = "archive"          # history.archive.jsonl（裁剪归档，可能不存在）
ORIGIN_MATRIX = "matrix"            # 靶场矩阵 ScanRecord JSON（自产，可回灌）

# era 判定：history 中 id<=47 为 migrate-pg 迁入的 Python 时代记录（审计报告 §7）
PY_ERA_MAX_HISTORY_ID = 47

# prediction_time 语义：样本自身的 scanned_at（开发文档 §3）。
# 一切历史先验特征只允许聚合 scanned_at 严格早于它的记录。
PREDICTION_TIME_FIELD = "scanned_at_dt"

# verified 行的 src 取值（engine.verifiedMap 统一键，engine.go/result.go:124）
VERIFIED_SRCS = {"check", "nuclei", "passive", "dast", "js", "weak"}

# execution_status 取值（开发文档 §2 D4：T1 observation/execution 状态建模）
EXEC_EXECUTED = "executed"
EXEC_NOT_EXECUTED = "not_executed"
EXEC_UNKNOWN = "unknown"


@dataclass(frozen=True)
class Paths:
    data_root: Path
    out_root: Path
    matrix_dir: Path | None

    @property
    def history_json(self) -> Path:
        return self.data_root / "state" / "history.json"

    @property
    def archive_jsonl(self) -> Path:
        return self.data_root / "state" / "history.archive.jsonl"

    @property
    def premigrate_json(self) -> Path:
        return self.data_root / "state" / "history.json.premigrate"

    @property
    def nuclei_index(self) -> Path:
        return self.data_root / "state" / "nuclei_index.json"

    @property
    def kev_extra(self) -> Path:
        return self.data_root / "state" / "kev_extra.json"

    @property
    def technologies_json(self) -> Path:
        return self.data_root / "go" / "technologies.json"

    @property
    def intel_dump(self) -> Path:
        return self.data_root / "intel_dump.json.gz"

    @property
    def tpl_intel(self) -> Path:
        return self.data_root / "tpl_intel.json.gz"

    @property
    def nvd_cves(self) -> Path:
        return self.data_root / "nvd_cves.json.gz"

    @property
    def affected_ranges(self) -> Path:
        return self.data_root / "affected_ranges.json"


def resolve_paths(
    data_root: str | os.PathLike | None = None,
    out_root: str | os.PathLike | None = None,
    matrix_dir: str | os.PathLike | None = None,
) -> Paths:
    """解析数据/输出根目录；解析失败抛 FileNotFoundError（不静默降级）。"""
    dr = data_root or os.environ.get("SITLENS_DATA_ROOT")
    if dr is None:
        cand = Path.cwd() / "data"
        dr = cand if cand.is_dir() else None
    if dr is None:
        raise FileNotFoundError(
            "未找到数据根目录：请传 --data-root 或设置 SITLENS_DATA_ROOT"
            "（应包含 state/history.json 的 data/ 目录）"
        )
    dr = Path(dr).resolve()
    if not (dr / "state" / "history.json").is_file():
        raise FileNotFoundError(f"数据根目录缺少 state/history.json：{dr}")

    orr = out_root or os.environ.get("SITLENS_ML_OUT") or (Path.cwd() / "data" / "ml")

    md = matrix_dir or os.environ.get("SITLENS_MATRIX_DIR")
    return Paths(
        data_root=dr,
        out_root=Path(orr).resolve(),
        matrix_dir=Path(md).resolve() if md else None,
    )
