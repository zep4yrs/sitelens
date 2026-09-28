"""sev-prior v3.1 部署训练（EXP-1017 D_max 配方复现 + 权重持久化）。

背景：EXP-1017 的 D_max（train<2024 全量 + Huber(0.1) + 双种子平均，test
MAE 1.07）当时未持久化权重，导致发布件误挂 EXP-1015 权重。本脚本按同一
配方重训并落盘，供 ONNX 导出与引擎内嵌。

配方（与 train_sev_mae.py 逐项一致）：DistilBERT-base-uncased 回归头
（score/10），AdamW lr=2e-5/wd=0.01 + OneCycleLR(pct_start=0.1)，
HuberLoss(delta=0.1)，2 epochs，batch 32，seq 192，bf16 autocast，
双种子 20260928/20260929，预测平均集成。

运行（ml5 根目录）：.venv/Scripts/python.exe -m ml.train_sev_v31_deploy
产物：data/ml/dist/models/sev-prior-v3.1/s<seed>.pt ×2 +
      data/ml/dist/models/sev-prior-v3.1/deploy-metrics.json
"""
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

from . import config
from .train_sev_mae import CLASSES, DATA_VERSION, MAX_LEN, BATCH, SEED, infer

BASE_MODEL = r"data\bench\models\distilbert-base-uncased"
SEEDS = (SEED, SEED + 1)
EPOCHS = 2


def main() -> int:
    ap_args = type("A", (), {"data_root": r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data",
                             "base_model": BASE_MODEL, "out_root": None})()
    paths = config.resolve_paths(ap_args.data_root, ap_args.out_root)

    if not torch.cuda.is_available():
        print("[abort] CUDA 不可用")
        return 1
    device = torch.device("cuda")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    kb = paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz"
    print(f"[data] {kb}", flush=True)

    rows = []
    import gzip
    with gzip.open(kb, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in CLASSES and r.get("score") is not None \
                    and len(r.get("descr") or "") > 0:
                rows.append({"descr": r["descr"], "score": float(r["score"]),
                             "sev": r["sev"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    tr24 = df[df["pub_dt"] < pd.Timestamp("2024-01-01")]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    yte = te["score"].to_numpy()
    print(f"[data] tr24={len(tr24)} test={len(te)}", flush=True)

    def build(texts, labels):
        ds = []
        for t, y in zip(texts, labels):
            enc = tok(t, truncation=True, max_length=MAX_LEN,
                      padding="max_length", return_tensors="pt")
            ds.append((enc["input_ids"][0], enc["attention_mask"][0],
                       np.float32(y)))

        class _DS(torch.utils.data.Dataset):
            def __len__(self):
                return len(ds)

            def __getitem__(self, i):
                ii, aa, yy = ds[i]
                return {"input_ids": ii, "attention_mask": aa,
                        "labels": torch.tensor(yy)}
        return _DS()

    def make_loader(texts, labels, shuffle=False, bs=BATCH):
        return DataLoader(build(texts, labels), batch_size=bs, shuffle=shuffle,
                          num_workers=0)

    te_loader = make_loader(te["descr"], te["score"] / 10.0)
    out_dir = paths.out_root / "dist" / "models" / "sev-prior-v3.1"
    out_dir.mkdir(parents=True, exist_ok=True)

    test_scores = []
    metrics = {"recipe": "EXP-1017 D_max 复现：tr24 全量+Huber(0.1)+双种子平均",
               "data": {"kb": DATA_VERSION, "tr24": int(len(tr24)), "test": int(len(te))},
               "hyperparams": {"lr": 2e-5, "weight_decay": 0.01, "epochs": EPOCHS,
                                "batch": BATCH, "max_len": MAX_LEN,
                                "loss": "HuberLoss(delta=0.1)", "amp": "bf16",
                                "scheduler": "OneCycleLR(pct_start=0.1)"},
               "seeds": []}
    for seed in SEEDS:
        t0 = time.time()
        loader = make_loader(tr24["descr"], tr24["score"] / 10.0, shuffle=True)
        model = AutoModelForSequenceClassification.from_pretrained(
            BASE_MODEL, num_labels=1).to(device)
        opt = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
        sched = torch.optim.lr_scheduler.OneCycleLR(
            opt, max_lr=2e-5, total_steps=max(1, len(loader)) * EPOCHS,
            pct_start=0.1)
        loss_fn = torch.nn.HuberLoss(delta=0.1)
        g = torch.Generator().manual_seed(seed)
        for epoch in range(1, EPOCHS + 1):
            model.train()
            for step, batch in enumerate(loader, start=1):
                batch = {k: v.to(device) for k, v in batch.items()}
                with torch.autocast("cuda", dtype=torch.bfloat16):
                    pred = model(input_ids=batch["input_ids"],
                                 attention_mask=batch["attention_mask"]).logits.ravel()
                loss = loss_fn(pred.float(), batch["labels"])
                loss.backward()
                sched.step()
                opt.step()
                opt.zero_grad()
            print(f"[seed {seed}] epoch {epoch}/{EPOCHS} done "
                  f"({time.time() - t0:.0f}s)", flush=True)
        model.eval()
        ste = infer(model, te_loader, device)
        mae = float(np.abs(ste - yte).mean())
        adj = float(np.mean(np.abs(np.round(ste) - np.round(yte)) <= 1.0))
        ckpt = out_dir / f"s{seed}.pt"
        torch.save({"state_dict": model.state_dict(),
                    "meta": {"seed": seed, "recipe": metrics["recipe"],
                             "base_model": "distilbert-base-uncased",
                             "num_labels": 1, "score_scale": "score/10"}},
                   ckpt)
        test_scores.append(ste)
        metrics["seeds"].append({"seed": seed, "test_mae": round(mae, 4),
                                 "adjacent_band_1": round(adj, 4),
                                 "ckpt": ckpt.name,
                                 "train_seconds": round(time.time() - t0)})
        print(f"[seed {seed}] test_mae={mae:.4f} adjacent={adj:.4f} "
              f"saved {ckpt.name}", flush=True)
        del model
        torch.cuda.empty_cache()

    ens = (test_scores[0] + test_scores[1]) / 2.0
    ens_mae = float(np.abs(ens - yte).mean())
    ens_adj = float(np.mean(np.abs(np.round(ens) - np.round(yte)) <= 1.0))
    metrics["ensemble"] = {"test_mae": round(ens_mae, 4),
                           "adjacent_band_1": round(ens_adj, 4),
                           "interval_const": 1.07}
    (out_dir / "deploy-metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[ensemble] test_mae={ens_mae:.4f} adjacent={ens_adj:.4f} "
          f"→ deploy-metrics.json", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
