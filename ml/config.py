"""路径解析与全局常量（P1 数据基础设施）。

BUG-028：训练脚本曾把开发者机器的绝对路径（`D:\\fengqiao\\Desktop\\...`）写死成
argparse 默认值，导致本仓无法重训。现在所有路径统一从这里解析，优先级：
  1. 显式参数（CLI 参数）
  2. 环境变量（见下表）
  3. 仓库相对默认路径（<repo> = 本文件上一级，与 cwd 无关）

| 环境变量 | 默认（仓库相对） | 用途 |
|---|---|---|
| `SITLENS_DATA_ROOT` | `<repo>/data` | 原始 KB 数据根（须含 state/history.json） |
| `SITLENS_ML_OUT` | `<repo>/data/ml` | 产物根（dataset / experiments / metrics / dist） |
| `SITLENS_ML_ASSETS` | `<bench_root>/models` | 预训练底座权重根（distilbert-base-uncased/ 等） |
| `SITLENS_ML_BENCH` | `<repo>/data/bench` | 基准/外部资产根（models/、external/ 的上一级） |
| `SITLENS_ML_GO_ASSETS` | `<repo>/data/go/ml_assets` | Go 引擎资产导出目录 |
| `SITLENS_FARM_HISTORY` | `<SITLENS_DATA_ROOT>/state/history.json` | 靶场扫描历史（EXP-1101/1102 标签来源） |

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


def repo_root() -> Path:
    """仓库根目录（ml/ 的上一级）；与 cwd 无关，脚本从任何目录启动都成立。"""
    return Path(__file__).resolve().parents[1]


def ml_out_root() -> Path:
    """ml 产物根：SITLENS_ML_OUT > <repo>/data/ml。"""
    raw = os.environ.get("SITLENS_ML_OUT")
    return Path(raw).resolve() if raw else (repo_root() / "data" / "ml").resolve()


def bench_root() -> Path:
    """基准/外部资产根：SITLENS_ML_BENCH > <repo>/data/bench。"""
    raw = os.environ.get("SITLENS_ML_BENCH")
    return (Path(raw) if raw else repo_root() / "data" / "bench").resolve()


def bench_asset(rel: str | os.PathLike) -> Path:
    """基准资产下的相对路径（如 external/msf_metadata.json）。"""
    return (bench_root() / rel).resolve()


def model_assets_root() -> Path:
    """预训练底座权重根：SITLENS_ML_ASSETS > <bench_root>/models（默认 <repo>/data/bench/models）。"""
    raw = os.environ.get("SITLENS_ML_ASSETS")
    return (Path(raw) if raw else bench_root() / "models").resolve()


def base_model_dir(
    name: str = "distilbert-base-uncased",
    explicit: str | os.PathLike | None = None,
) -> Path:
    """底座模型目录：显式参数 > SITLENS_ML_ASSETS/<name> > <repo>/data/bench/models/<name>。"""
    if explicit:
        return Path(explicit).resolve()
    return (model_assets_root() / name).resolve()


def go_assets_dir() -> Path:
    """Go 引擎资产导出目录：SITLENS_ML_GO_ASSETS > <repo>/data/go/ml_assets。"""
    raw = os.environ.get("SITLENS_ML_GO_ASSETS")
    return (Path(raw) if raw else repo_root() / "data" / "go" / "ml_assets").resolve()


def ml_artifact(rel: str | os.PathLike) -> Path:
    """产物根下的相对路径（如 experiments/EXP-xxxx/model.joblib）。"""
    return (ml_out_root() / rel).resolve()


def farm_history(
    explicit: str | os.PathLike | None = None, paths: Paths | None = None
) -> Path:
    """靶场扫描历史：显式参数 > SITLENS_FARM_HISTORY > <data_root>/state/history.json。

    仅 EXP-1101/1102 用（执行日志标签）；常规训练消费的是 data_root 下的 KB 表。
    """
    if explicit:
        return Path(explicit).resolve()
    raw = os.environ.get("SITLENS_FARM_HISTORY")
    if raw:
        return Path(raw).resolve()
    if paths is None:
        raise FileNotFoundError(
            "未给 --farm-history 且未设 SITLENS_FARM_HISTORY，无法定位靶场历史"
        )
    return (paths.data_root / "state" / "history.json").resolve()


def resolve_paths(
    data_root: str | os.PathLike | None = None,
    out_root: str | os.PathLike | None = None,
    matrix_dir: str | os.PathLike | None = None,
) -> Paths:
    """解析数据/输出根目录；解析失败抛 FileNotFoundError（不静默降级）。"""
    dr = data_root or os.environ.get("SITLENS_DATA_ROOT")
    if dr is None:
        # BUG-028：默认值跟仓库走（与 cwd 无关），不再是开发机绝对路径。
        cand = repo_root() / "data"
        dr = cand if cand.is_dir() else None
    if dr is None:
        raise FileNotFoundError(
            "未找到数据根目录：请传 --data-root 或设置 SITLENS_DATA_ROOT"
            "（应包含 state/history.json 的 data/ 目录）"
        )
    dr = Path(dr).resolve()
    if not (dr / "state" / "history.json").is_file():
        raise FileNotFoundError(f"数据根目录缺少 state/history.json：{dr}")

    orr = Path(out_root).resolve() if out_root else ml_out_root()

    md = matrix_dir or os.environ.get("SITLENS_MATRIX_DIR")
    return Paths(
        data_root=dr,
        out_root=Path(orr).resolve(),
        matrix_dir=Path(md).resolve() if md else None,
    )
