"""export_sev_fixtures_go.py —— 生成 Go 侧 sev-prior ONNX 对拍夹具。

从 E1 严重度评测集抽样描述，用已通过三方对拍的 fp32 ONNX（torch 对拍
MAE<0.02 的同一产物）打分作为真值，落 sev-fixtures.json 供
internal/ml/sev_onnx_parity_test.go 比对（Go MAE < 0.03 方可）。

用法（ml5 venv）：
  .venv/Scripts/python.exe ml/export_sev_fixtures_go.py <repo_root>
产出：<repo_root>/data/go/ml_assets/sev-fixtures.json
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

SEQ = 192
N = 120
SEED = 20260929


def main(repo_root: str) -> None:
    root = Path(repo_root)
    assets = root / "data" / "go" / "ml_assets"
    model_dir = Path(__file__).resolve().parents[2] / "sitelens-ml5" / "data" / "bench" / "models" / "distilbert-base-uncased"
    if not model_dir.exists():
        model_dir = root.parent / "sitelens-ml5" / "data" / "bench" / "models" / "distilbert-base-uncased"
    eval_set = Path(__file__).resolve().parents[2] / "sitelens-ml5" / "data" / "ml" / "bench" / "eval_sets" / "e1_severity.jsonl.gz"
    if not eval_set.exists():
        eval_set = root.parent / "sitelens-ml5" / "data" / "ml" / "bench" / "eval_sets" / "e1_severity.jsonl.gz"

    rows = []
    with gzip.open(eval_set, "rt", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    rows.sort(key=lambda r: r.get("cve", ""))
    rng = np.random.default_rng(SEED)
    pick = rng.choice(len(rows), size=min(N, len(rows)), replace=False)
    texts = [str(rows[i]["descr"])[:2000] for i in pick]

    tok = AutoTokenizer.from_pretrained(str(model_dir))
    enc = tok(texts, truncation=True, max_length=SEQ, padding="max_length")
    ids = np.asarray(enc["input_ids"], dtype=np.int64)
    mask = np.asarray(enc["attention_mask"], dtype=np.int64)

    sess = ort.InferenceSession(str(assets / "sev-prior-v3.1.onnx"), providers=["CPUExecutionProvider"])
    scores = []
    for i in range(0, len(texts), 16):
        logits = sess.run(["logits"], {
            "input_ids": ids[i:i + 16],
            "attention_mask": mask[i:i + 16],
        })[0]
        scores.extend(float(s) * 10.0 for s in logits.reshape(-1))

    out = {"seq": SEQ, "n": len(texts),
           "items": [{"text": t, "score": round(s, 6)} for t, s in zip(texts, scores)]}
    dst = assets / "sev-fixtures.json"
    dst.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    print(f"fixtures: {dst} (n={len(texts)}, score range "
          f"{min(scores):.3f}..{max(scores):.3f})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
