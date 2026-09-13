"""Manifest 版本化与可追溯性（P1 / P10）。

每个 Dataset / Feature / Label / Model / Experiment 落盘时必须携带
manifest：kind、version、created_at、git_rev、inputs[]（路径+sha256+大小）、
params、range（scan 区间/host 集合/时间区间）、producer。
load_verified 会重算输入文件哈希，任何不一致即抛异常（篡改/损坏可发现）。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_KINDS = {"dataset", "feature", "label", "model", "experiment", "report"}


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_input(path: str | Path, role: str = "input") -> dict:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"manifest 输入文件不存在：{p}")
    return {
        "role": role,
        "path": str(p),
        "sha256": sha256_file(p),
        "bytes": p.stat().st_size,
    }


def bytes_input(data: bytes, name: str, role: str = "input") -> dict:
    return {"role": role, "path": name, "sha256": sha256_bytes(data), "bytes": len(data)}


def git_rev(repo_dir: str | Path | None = None) -> str:
    """当前 git 提交号（无法获取时返回 'unknown'，绝不编造）。"""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir, capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def make_manifest(
    kind: str,
    version: str,
    inputs: list[dict],
    params: dict,
    producer: str,
    scope: dict | None = None,
    repo_dir: str | Path | None = None,
    notes: str = "",
) -> dict:
    if kind not in MANIFEST_KINDS:
        raise ValueError(f"未知 manifest kind：{kind}（允许：{sorted(MANIFEST_KINDS)}）")
    return {
        "kind": kind,
        "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_rev": git_rev(repo_dir),
        "ml_package_version": _ml_pkg_version(),
        "inputs": inputs,
        "params": params,
        "range": scope or {},
        "producer": producer,
        "notes": notes,
    }


def _ml_pkg_version() -> str:
    try:  # 延迟导入避免循环依赖
        from . import __version__

        return __version__
    except Exception:  # pragma: no cover
        return "unknown"


def write_manifest(manifest: dict, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return p


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_manifest(manifest: dict, base_dir: str | Path | None = None) -> list[str]:
    """重算 inputs 中每个真实文件的 sha256；返回问题列表（空=通过）。

    bytes_input（内存内容）不重算；name 以 'memory:' 前缀标识。
    """
    problems: list[str] = []
    if manifest.get("kind") not in MANIFEST_KINDS:
        problems.append(f"kind 非法：{manifest.get('kind')}")
    base = Path(base_dir) if base_dir else Path.cwd()
    for inp in manifest.get("inputs", []):
        name = inp.get("path", "")
        if name.startswith("memory:"):
            continue
        p = Path(name)
        if not p.is_absolute():
            p = base / p
        if not p.is_file():
            problems.append(f"输入文件缺失：{p}")
            continue
        actual = sha256_file(p)
        if actual != inp.get("sha256"):
            problems.append(f"哈希不一致：{p}（manifest={inp.get('sha256')} actual={actual}）")
    return problems
