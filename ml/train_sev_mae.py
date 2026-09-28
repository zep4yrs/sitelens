"""sev-prior 分数精修（EXP-1017）：MAE 1.283 → 目标更低。

变体（严格三段切分 train<2022 / val 22-23 / test>=2024 一次）：
  a_mse2   v3 现役复现（MSE, 2ep）——参照点
  b_huber2 Huber(delta=0.1 归一化单位) 2ep——MAE 导向损失
  c_huber3 Huber 3ep
部署版（不受严格协议束缚，数据用满）：
  D_max    Huber, train<2024 全量 148k, 2ep, 双种子平均——候选现役
指标：val/test 分数 MAE（主）、档位 acc/相邻带（参考）。
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

from . import config

DATA_VERSION = "kb-5.0.2"
ALIAS = "sev-prior"
SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]
MAX_LEN = 192
BATCH = 32
EDGES = [4.0, 7.0, 9.0]


def load(path: str) -> pd.DataFrame:
    rows = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in CLASSES and r.get("score") is not None \
                    and len(r.get("descr") or "") > 0:
                rows.append({"descr": r["descr"], "score": float(r["score"]),
                             "sev": r["sev"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    return df


def band_of(s):
    x = float(s)
    return ("critical" if x >= 9 else "high" if x >= 7 else
            "medium" if x >= 4 else "low")


def band_arr(scores: np.ndarray) -> np.ndarray:
    return np.array([band_of(x) for x in scores], dtype=object)


@torch.no_grad()
def infer(model, loader, device) -> np.ndarray:
    model.eval()
    out = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits
        out.append(logits.float().cpu().numpy().ravel() * 10.0)
    return np.concatenate(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--base-model",
                    default=r"data\bench\models\distilbert-base-uncased")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    if not torch.cuda.is_available():
        print("[abort] CUDA 不可用")
        return 1
    device = torch.device("cuda")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.base_model)
    kb = paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz"

    rows = []
    with gzip.open(kb, "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in CLASSES and r.get("score") is not None \
                    and len(r.get("descr") or "") > 0:
                rows.append({"descr": r["descr"], "score": float(r["score"]),
                             "sev": r["sev"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    tr22 = df[df["pub_dt"] < pd.Timestamp("2022-01-01")]
    va = df[(df["pub_dt"] >= pd.Timestamp("2022-01-01"))
            & (df["pub_dt"] < pd.Timestamp("2024-01-01"))]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    tr24 = df[df["pub_dt"] < pd.Timestamp("2024-01-01")]
    yte_band = te["sev"].to_numpy()
    yte_score = te["score"].to_numpy()
    print(f"[data] tr22={len(tr22)} tr24={len(tr24)} val={len(va)} test={len(te)}")

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
        # num_workers=0：_DS 为闭包内本地类，Windows spawn 无法 pickle（张量索引主进程足够快）
        return DataLoader(build(texts, labels), batch_size=bs, shuffle=shuffle,
                          num_workers=0)

    va_loader = make_loader(va["descr"], va["score"] / 10.0)
    te_loader = make_loader(te["descr"], te["score"] / 10.0)

    def train_eval(tag: str, train_df: pd.DataFrame, loss_kind: str,
                   epochs: int, seed: int) -> dict:
        loader = make_loader(train_df["descr"], train_df["score"] / 10.0,
                             shuffle=True)
        model = AutoModelForSequenceClassification.from_pretrained(
            args.base_model, num_labels=1).to(device)
        opt = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
        sched = torch.optim.lr_scheduler.OneCycleLR(
            opt, max_lr=2e-5, total_steps=max(1, len(loader)) * epochs,
            pct_start=0.1)
        loss_fn = (torch.nn.MSELoss() if loss_kind == "mse"
                   else torch.nn.HuberLoss(delta=0.1))
        g = torch.Generator().manual_seed(seed)
        for epoch in range(1, epochs + 1):
            model.train()
            for step, batch in enumerate(loader, start=1):
                batch = {k: v.to(device) for k, v in batch.items()}
                with torch.autocast("cuda", dtype=torch.bfloat16):
                    pred = model(input_ids=batch["input_ids"],
                                 attention_mask=batch["attention_mask"]).logits.ravel()
                loss = loss_fn(pred.float(), batch["labels"])
                loss.backward()
                opt.step()
                sched.step()
                opt.zero_grad()
        model.eval()
        sva = infer(model, va_loader, device)
        ste = infer(model, te_loader, device)
        return {"name": tag, "model": model,
                "val_mae": round(float(np.abs(sva - va["score"].to_numpy()).mean()), 3),
                "test_mae": round(float(np.abs(ste - yte_score).mean()), 3),
                "test_scores": ste}

    results = []
    r_a = train_eval("a_mse2_tr22", tr22, "mse", 2, SEED)
    results.append({"name": r_a["name"], "val_mae": r_a["val_mae"],
                    "test_mae": r_a["test_mae"]})
    print(f"[{r_a['name']}] val={r_a['val_mae']} test={r_a['test_mae']}")
    r_b = train_eval("b_huber2_tr22", tr22, "huber", 2, SEED)
    results.append({"name": r_b["name"], "val_mae": r_b["val_mae"],
                    "test_mae": r_b["test_mae"]})
    print(f"[{r_b['name']}] val={r_b['val_mae']} test={r_b['test_mae']}")

    # 部署版：最大数据 + Huber + 双种子平均
    s_d = []
    for seed in (SEED, SEED + 1):
        r = train_eval(f"D_max_huber2_tr24_s{seed}", tr24, "huber", 2, seed)
        s_d.append(r["test_scores"])
    ste_d = np.mean(s_d, axis=0)
    d_mae = round(float(np.abs(ste_d - yte_score).mean()), 3)
    d_adj = float((np.abs(np.array([CLASSES.index(y) for y in yte_band])
                          - np.array([CLASSES.index(band_of(s)) for s in ste_d])) <= 1).mean())
    results.append({"name": "D_max_huber2_tr24_ensemble2", "val_mae": None,
                    "test_mae": d_mae})
    print(f"[D_max ensemble] test_mae={d_mae} adjacent={d_adj:.4f}")

    out = {
        "experiment": "EXP-1017", "alias": ALIAS,
        "task": "sev-prior 分数 MAE 精修（Huber 损失/最大数据/双种子集成）",
        "protocol": {"strict": "train<2022 / val 22-23 / test>=2024 一次",
                     "deployment": "train<2024 全量（与 v2.1 档位口径同思路）"},
        "results": results,
        "deployment": {"name": "D_max_huber2_tr24_ensemble2",
                       "test_mae": d_mae, "adjacent_acc": round(d_adj, 4),
                       "prev_v3_mae": 1.283},
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1017-{ALIAS}-mae.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
