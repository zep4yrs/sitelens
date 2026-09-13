"""扫描记录读取器（P2）。

四个来源（开发文档 §6 Phase 2）：
  history    data/state/history.json        —— 主数据源（Go 3.0 serve 落库）
  archive    data/state/history.archive.jsonl —— 裁剪归档（可能不存在）
  premigrate data/state/history.json.premigrate —— Python 时代迁移前快照
  matrix     靶场矩阵 ScanRecord JSON 目录   —— 自产数据（同构可回灌）

scan_uid = f"{origin}:{id}"：矩阵与 history 共享 id 空间（实测 matrix id=114），
必须带来源前缀才全局唯一。跨来源内容去重键 = (host, url, scanned_at, duration)，
保留优先级 history > archive > premigrate > matrix，被丢弃的计入统计（不静默）。
"""

from __future__ import annotations

import json
from pathlib import Path

from . import config

# 保留优先级（越小越优先）
_PRIORITY = {config.ORIGIN_HISTORY: 0, config.ORIGIN_ARCHIVE: 1,
             config.ORIGIN_PREMIGRATE: 2, config.ORIGIN_MATRIX: 3}


def _iter_jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def read_source(path: Path, origin: str) -> list[dict]:
    """读取单来源扫描记录，附 scan_uid/origin；坏行计数不中断。"""
    records: list[dict] = []
    if not path.is_file():
        return records
    if path.suffix == ".jsonl":
        raw_iter = _iter_jsonl(path)
    else:
        raw_iter = iter(json.loads(path.read_text(encoding="utf-8"))["scans"])
    for rec in raw_iter:
        if not isinstance(rec, dict):
            continue
        if not rec.get("id") or not rec.get("host"):
            continue
        rec = dict(rec)
        rec["origin"] = origin
        rec["scan_uid"] = f"{origin}:{rec['id']}"
        records.append(rec)
    return records


def read_matrix_dir(matrix_dir: Path) -> list[dict]:
    """靶场矩阵产物：目录下每个 .json 是一条 ScanRecord（完整结构才收）。"""
    records: list[dict] = []
    if not matrix_dir or not Path(matrix_dir).is_dir():
        return records
    for p in sorted(Path(matrix_dir).glob("*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(rec, dict) or "result" not in rec:
            continue  # 缺 result 的摘要行不进数据集（如实跳过）
        rec = dict(rec)
        rec["origin"] = config.ORIGIN_MATRIX
        rec["scan_uid"] = f"{config.ORIGIN_MATRIX}:{rec.get('id')}:{p.stem}"
        records.append(rec)
    return records


def content_key(rec: dict) -> tuple:
    """跨来源内容去重键：同一扫描在多个来源出现时只保留一份。"""
    r = rec.get("result") or {}
    return (
        rec.get("host", ""), rec.get("url", ""), rec.get("scanned_at", ""),
        round(float(rec.get("duration") or 0), 3),
        len(r.get("technologies") or []),
    )


def load_all_scans(paths: config.Paths) -> tuple[list[dict], dict]:
    """读取全部来源并去重。返回 (records, source_stats)。

    两层去重（都对统计可见，绝不静默）：
      1) 事件级：premigrate 是 history id 1..47 的迁移前快照（migrate-pg
         保留 id），凡 history 已存在同 id 记录，premigrate 版本丢弃
         （迁移会对字段做规范化，内容可能略异，但事件同一，以 history 为准）；
      2) 内容级：跨来源 (host,url,scanned_at,duration,n_tech) 完全一致才丢
         （matrix 与 history 是独立实例、id 偶然碰撞，只能按内容判定重复）。
    """
    sources = [
        (config.ORIGIN_HISTORY, read_source(paths.history_json, config.ORIGIN_HISTORY)),
        (config.ORIGIN_ARCHIVE, read_source(paths.archive_jsonl, config.ORIGIN_ARCHIVE)),
        (config.ORIGIN_PREMIGRATE, read_source(paths.premigrate_json, config.ORIGIN_PREMIGRATE)),
        (config.ORIGIN_MATRIX, read_matrix_dir(paths.matrix_dir) if paths.matrix_dir else []),
    ]
    stats: dict = {"per_source_raw": {}, "dedup_dropped": [], "event_dedup": {}}
    by_key: dict[tuple, dict] = {}
    seen_uid: set[str] = set()
    for origin, recs in sorted(sources, key=lambda x: _PRIORITY[x[0]]):
        stats["per_source_raw"][origin] = len(recs)
        for rec in recs:
            if rec["scan_uid"] in seen_uid:
                stats.setdefault("dup_uid", []).append(rec["scan_uid"])
                continue
            seen_uid.add(rec["scan_uid"])
            key = content_key(rec)
            if key in by_key:
                stats["dedup_dropped"].append(
                    {"rule": "content", "dropped": rec["scan_uid"],
                     "kept": by_key[key]["scan_uid"]})
                continue
            # 事件级：history 已有的 id，premigrate/archive 快照不再保留
            if origin in (config.ORIGIN_PREMIGRATE, config.ORIGIN_ARCHIVE):
                eid = f"{config.ORIGIN_HISTORY}:{rec.get('id')}"
                if eid in seen_uid:
                    stats["dedup_dropped"].append(
                        {"rule": "event", "dropped": rec["scan_uid"], "kept": eid})
                    stats["event_dedup"][origin] = stats["event_dedup"].get(origin, 0) + 1
                    continue
            by_key[key] = rec
    out = list(by_key.values())
    out.sort(key=lambda r: (r.get("scanned_at") or "", r["scan_uid"]))
    stats["total_after_dedup"] = len(out)
    stats["dedup_dropped_n"] = len(stats["dedup_dropped"])
    return out, stats
