"""P10 Model Versioning / Experiment 追溯。

每次训练产出一个 experiment 目录：
  data/ml/experiments/{exp_id}-{task}-{model}/
    model.joblib / metrics.json / config.json / EXPERIMENT_MANIFEST.json
manifest 记录上游链（dataset/feature/label manifest 的文件哈希），
verify_experiment 重算全部哈希并可反查上游版本（开发文档 Phase 10）。
汇总索引：data/ml/metrics/summary.jsonl（append-only）。
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib

from . import manifest


def create_experiment(
    out_root: Path, exp_id: str, task: str, model_name: str,
    params: dict, metrics_report: dict,
    model_obj, feature_cols: list[str],
    upstream_manifests: list[Path],
    gate_note: str = "", repo_dir: Path | None = None,
) -> Path:
    d = Path(out_root) / "experiments" / f"{exp_id}-{task}-{model_name}"
    d.mkdir(parents=True, exist_ok=True)
    model_path = d / "model.joblib"
    joblib.dump({"model": model_obj, "feature_cols": feature_cols}, model_path)
    (d / "metrics.json").write_text(
        json.dumps(metrics_report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    (d / "config.json").write_text(
        json.dumps({"task": task, "model": model_name, "params": params,
                    "feature_cols": feature_cols},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    man = manifest.make_manifest(
        kind="model", version=exp_id,
        inputs=[manifest.file_input(model_path, role="output:model"),
                manifest.file_input(d / "metrics.json", role="output:metrics"),
                manifest.file_input(d / "config.json", role="output:config")]
                + [manifest.file_input(p, role=f"upstream:{p.name}")
                   for p in upstream_manifests],
        params=params,
        producer="ml/train.py + ml/registry.py",
        scope={"task": task, "model": model_name},
        repo_dir=repo_dir,
        notes=gate_note,
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    return d


def append_summary(out_root: Path, record: dict) -> Path:
    p = Path(out_root) / "metrics" / "summary.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    return p


def verify_experiment(exp_dir: Path) -> dict:
    """校验实验目录：manifest 哈希重算 + 上游链可反查。"""
    exp_dir = Path(exp_dir)
    man = manifest.load_manifest(exp_dir / "EXPERIMENT_MANIFEST.json")
    problems = manifest.verify_manifest(man, base_dir=exp_dir)
    upstream = [i for i in man.get("inputs", []) if i["role"].startswith("upstream:")]
    return {
        "experiment": exp_dir.name,
        "kind": man["kind"],
        "version": man["version"],
        "git_rev": man["git_rev"],
        "upstream_manifests": [i["path"] for i in upstream],
        "problems": problems,
        "ok": not problems,
    }
