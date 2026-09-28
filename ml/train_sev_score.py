"""sev-prior v3（EXP-1015）：用户方案落地——分数输出 + 边界专精模型。

用户洞察：档位显示把不确定性掩盖在离散边界上，而边界正是分析师方差所在。
本轮改为：
  1) 主回归器：DistilBERT 回归头直接预测 CVSS 分数（0-10），输出【分数±MAE】
  2) 边界专精模型：只用人造边界带样本（|score-最近档界|<=1.0）训练的
     二分类器，专攻"贴线样本归哪边"
  3) 推理：主分数落 在档界±0.75 内 → 专精模型裁决归属侧 → 档位由精修分数切出
呈现：产品层显示分数与区间，档位仅作辅助标注（用户拍板的呈现变更）。

口径：严格三段切分（train<2022 / val 22-23 / test>=2024 一次）。
指标：分数 MAE（主指标）、档位 acc、相邻带 acc、边界子集精修前后 acc。
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset

from . import config, manifest

DATA_VERSION = "kb-5.0.2"
ALIAS = "sev-prior"
VERSION = "v3"
SEED = 20260928
MAX_LEN = 192
BATCH = 32
EPOCHS_REG = 2
EPOCHS_EDGE = 2
LR = 2e-5
EDGES = [4.0, 7.0, 9.0]
EDGE_TOL_TRAIN = 1.0   # 边界专精模型的训练带宽
EDGE_TOL_INFER = 0.75  # 推理时触发专精裁决的距离


class TextDataset(Dataset):
    def __init__(self, texts, labels=None, tokenizer=None):
        self.texts = list(texts)
        self.labels = None if labels is None else np.asarray(labels)
        self.tok = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        enc = self.tok(self.texts[i], truncation=True, max_length=MAX_LEN,
                       padding="max_length", return_tensors="pt")
        item = {"input_ids": enc["input_ids"][0],
                "attention_mask": enc["attention_mask"][0]}
        if self.labels is not None:
            item["labels"] = torch.tensor(self.labels[i], dtype=torch.float32)
        return item


@torch.no_grad()
def infer(model, loader, device) -> np.ndarray:
    model.eval()
    out = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits
        out.append(logits.float().cpu().numpy().ravel())
    return np.concatenate(out)


def band_of(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def band_arr(scores: np.ndarray) -> np.ndarray:
    return np.array([band_of(s) for s in scores], dtype=object)


def _metrics(y_true_band, y_pred_band) -> dict:
    rank = {c: i for i, c in enumerate(["low", "medium", "high", "critical"])}
    tr = np.array([rank[y] for y in y_true_band])
    pr = np.array([rank[y] for y in y_pred_band])
    return {"accuracy": round(float((y_true_band == y_pred_band).mean()), 4),
            "adjacent_acc": round(float((np.abs(tr - pr) <= 1).mean()), 4),
            "rows": int(len(y_true_band))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--base-model",
                    default=r"data\bench\models\distilbert-base-uncased")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    if not torch.cuda.is_available():
        print("[abort] CUDA 不可用——按纪律不假跑")
        return 1
    device = torch.device("cuda")

    from transformers import (AutoModelForSequenceClassification, AutoTokenizer)
    tok = AutoTokenizer.from_pretrained(args.base_model)

    rows = []
    with gzip.open(paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                   "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in ("low", "medium", "high", "critical") \
                    and r.get("score") is not None and len(r.get("descr") or "") > 0:
                rows.append({"descr": r["descr"], "score": float(r["score"]),
                             "sev": r["sev"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    tr = df[df["pub_dt"] < pd.Timestamp("2022-01-01")]
    va = df[(df["pub_dt"] >= pd.Timestamp("2022-01-01"))
            & (df["pub_dt"] < pd.Timestamp("2024-01-01"))]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    print(f"[data] train={len(tr)} val={len(va)} test={len(te)}")

    tr_loader = DataLoader(TextDataset(tr["descr"], tr["score"] / 10.0, tok),
                           batch_size=BATCH, shuffle=True, num_workers=2,
                           drop_last=True)
    va_loader = DataLoader(TextDataset(va["descr"], va["score"] / 10.0, tok),
                           batch_size=BATCH * 4, num_workers=2)
    te_loader = DataLoader(TextDataset(te["descr"], te["score"] / 10.0, tok),
                           batch_size=BATCH * 4, num_workers=2)

    # ---- 1) 主回归器 ----
    reg = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=1).to(device)
    opt = torch.optim.AdamW(reg.parameters(), lr=LR, weight_decay=0.01)
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=LR, total_steps=len(tr_loader) * EPOCHS_REG, pct_start=0.1)
    mse = torch.nn.MSELoss()
    for epoch in range(1, EPOCHS_REG + 1):
        reg.train()
        for step, batch in enumerate(tr_loader, start=1):
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.autocast("cuda", dtype=torch.bfloat16):
                pred = reg(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits.ravel()
            loss = mse(pred, batch["labels"])
            loss.backward()
            opt.step()
            sched.step()
            opt.zero_grad()
            if step % 800 == 0:
                print(f"[reg e{epoch} {step}/{len(tr_loader)}] loss={loss.item():.4f}")
    sva = infer(reg, va_loader, device) * 10.0
    mae_va = float(np.abs(sva - va["score"].to_numpy()).mean())
    print(f"[reg] val MAE={mae_va:.3f}")

    # ---- 2) 边界专精模型（仅边界带样本）----
    def boundary_subset(d: pd.DataFrame):
        near = np.zeros(len(d), dtype=bool)
        for e in EDGES:
            near |= (np.abs(d["score"].to_numpy() - e) <= EDGE_TOL_TRAIN)
        sub = d[near].copy()
        nearest = np.argmin(np.abs(
            sub["score"].to_numpy()[:, None] - np.array(EDGES)), axis=1)
        sub["edge"] = np.array(EDGES)[nearest]
        sub["side"] = (sub["score"].to_numpy() >= sub["edge"]).astype(np.float32)
        return sub

    b_tr = boundary_subset(tr)
    b_va = boundary_subset(va)
    b_tr_loader = DataLoader(TextDataset(b_tr["descr"], b_tr["side"], tok),
                             batch_size=BATCH, shuffle=True, num_workers=2,
                             drop_last=True)
    edge_model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=1).to(device)
    opt2 = torch.optim.AdamW(edge_model.parameters(), lr=LR, weight_decay=0.01)
    sched2 = torch.optim.lr_scheduler.OneCycleLR(
        opt2, max_lr=LR, total_steps=max(1, len(b_tr_loader)) * EPOCHS_EDGE,
        pct_start=0.1)
    bce = torch.nn.BCEWithLogitsLoss()
    for epoch in range(1, EPOCHS_EDGE + 1):
        edge_model.train()
        for step, batch in enumerate(b_tr_loader, start=1):
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.autocast("cuda", dtype=torch.bfloat16):
                pred = edge_model(input_ids=batch["input_ids"],
                                  attention_mask=batch["attention_mask"]).logits.ravel()
            loss = bce(pred, batch["labels"])
            loss.backward()
            opt2.step()
            sched2.step()
            opt2.zero_grad()
            if step % 400 == 0:
                print(f"[edge e{epoch} {step}/{len(b_tr_loader)}] loss={loss.item():.4f}")
    print(f"[edge] train_boundary_rows={len(b_tr)}")

    # 训练产物先落盘（评估若崩不重训）
    d = paths.out_root / "experiments" / f"EXP-1015-{ALIAS}-{VERSION}"
    d.mkdir(parents=True, exist_ok=True)
    torch.save({"reg": reg.state_dict(), "edge": edge_model.state_dict(),
                "base": args.base_model, "edges": EDGES}, d / "model.pt")

    # ---- 3) 测试段一次评估：分数 + 精修档位 ----
    ste = infer(reg, te_loader, device) * 10.0
    mae_te = float(np.abs(ste - te["score"].to_numpy()).mean())

    def refine(scores: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        b_va_scores = band_arr(scores)
        refined = scores.copy()
        n_refined = 0
        near = np.zeros(len(scores), dtype=bool)
        edge_near = np.zeros(len(scores), dtype=float)
        for e in EDGES:
            m = (np.abs(scores - e) <= EDGE_TOL_INFER) & ~near
            near |= m
            edge_near[m] = e
        if near.sum():
            # 专精模型只对最近档界裁决；批量推理
            sub_idx = np.where(near)[0]
            sub_ds = TextDataset(te["descr"].to_numpy()[sub_idx], None, tok)
            logits = infer(edge_model, DataLoader(sub_ds, batch_size=BATCH * 4,
                                                  num_workers=2), device)
            # infer 返回的是回归 logits（1 维）——此处 edge_model 也是 num_labels=1
            side = (logits >= 0.0).astype(float)  # >=edge 为真
            for k, i in enumerate(sub_idx):
                e = edge_near[k]
                refined[i] = e + 0.05 if side[k] > 0.5 else e - 0.05
                n_refined += 1
        return b_va_scores, refined, n_refined

    band_raw = band_arr(ste)
    band_ref, refined_scores, n_ref = refine(ste)
    mae_ref = float(np.abs(refined_scores - te["score"].to_numpy()).mean())
    m_raw = _metrics(te["sev"].to_numpy(), band_raw)
    m_ref = _metrics(te["sev"].to_numpy(), band_ref)

    # 边界子集专项：精修前后
    b_te = boundary_subset(te)
    idx = b_te.index
    pos = {i: k for k, i in enumerate(te.index)}
    mask = np.array([pos.get(i, -1) for i in idx])
    valid = mask >= 0
    sub_raw = _metrics(te["sev"].to_numpy()[mask[valid]],
                       band_raw[mask[valid]])
    sub_ref = _metrics(te["sev"].to_numpy()[mask[valid]],
                       band_ref[mask[valid]])

    out = {
        "experiment": "EXP-1015", "alias": ALIAS, "version": VERSION,
        "task": "严重度先验 v3：分数输出 + 边界专精模型（用户方案落地）",
        "presentation": "产品层显示【分数±MAE】，档位仅作辅助标注（用户拍板）",
        "data": {"kb": DATA_VERSION, "train": int(len(tr)),
                 "val": int(len(va)), "test": int(len(te))},
        "score_mae": {"val": round(mae_va, 3), "test": round(mae_te, 3)},
        "band": {"raw": m_raw, "after_edge_refine": m_ref,
                 "refined_rows": int(n_ref)},
        "boundary_subset": {"rows": int(valid.sum()),
                            "raw": sub_raw, "refined": sub_ref},
        "models": {"primary": "DistilBERT 回归头（score/10, MSE）",
                   "specialist": "边界带样本（±1.0）二分类，推理容差 ±0.75"},
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1015-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    man = manifest.make_manifest(
        kind="model", version=f"EXP-1015-{ALIAS}-{VERSION}",
        inputs=[manifest.file_input(d / "model.pt", role="output:model"),
                manifest.file_input(
                    paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                    role="upstream:kb_cve")],
        params={"task": "sev-prior", "seed": SEED, "output": "score+interval"},
        producer="ml/train_sev_score.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": f"EXP-1015-{ALIAS}-{VERSION}",
                            "alias": ALIAS, "test_mae": round(mae_te, 3),
                            "test_acc_refined": m_ref["accuracy"]}) + "\n")
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str)[:1200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
