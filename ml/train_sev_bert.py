"""sev-prior v3（EXP-1010）：DistilBERT 小分类器——GPU 微调严重度先验。

用户拍板解禁深度学习（仅此一个分类模型；LLM/RAG/Agent/聊天继续全禁）。
架构：DistilBERT-base（66M 参数编码器，无生成能力）+ 四类分类头；
底座预训练权重：distilbert-base-uncased（通用英文，hf-mirror 本地文件）；
微调数据：kb-5.0.2 严重度四类标注（描述 → 严重度），全程本地。

口径与 EXP-1006/1007 一致（严格三段切分）：
  train <2022（93k）/ val 2022-23（选型与早停）/ test >=2024（只碰一次）
产出：模型 + tokenizer + manifest + metrics；测试段 acc/macro-F1/相邻带。
资源：RTX 5060 Laptop 8GB，bf16 混合精度，batch 32 × seq 192。
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import f1_score
from torch.utils.data import DataLoader, Dataset

from . import config, manifest

DATA_VERSION = "kb-5.0.2"
ALIAS = "sev-prior"
VERSION = "v3"
SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]
MAX_LEN = 192
BATCH = 32
EPOCHS = 2
LR = 2e-5


class TextDataset(Dataset):
    def __init__(self, texts, labels, tokenizer):
        self.texts = list(texts)
        self.labels = ([CLASSES.index(y) for y in labels] if labels is not None
                       else [0] * len(self.texts))
        self.tok = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        enc = self.tok(self.texts[i], truncation=True, max_length=MAX_LEN,
                       padding="max_length", return_tensors="pt")
        return {"input_ids": enc["input_ids"][0],
                "attention_mask": enc["attention_mask"][0],
                "labels": torch.tensor(self.labels[i], dtype=torch.long)}


@torch.no_grad()
def predict(model, loader, device) -> np.ndarray:
    model.eval()
    probs = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits
        probs.append(torch.softmax(logits.float(), dim=-1).cpu())
    return torch.cat(probs).numpy()


def _eval(y_true, proba) -> dict:
    pred = np.array(CLASSES)[proba.argmax(axis=1)]
    tr_r = np.array([CLASSES.index(y) for y in y_true])
    pr_r = np.array([CLASSES.index(y) for y in pred])
    return {"accuracy": round(float((y_true == pred).mean()), 4),
            "macro_f1": round(float(f1_score(y_true, pred, average="macro",
                                             zero_division=0)), 4),
            "adjacent_acc": round(float((np.abs(tr_r - pr_r) <= 1).mean()), 4),
            "rows": int(len(y_true))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--base-model",
                    default=r"data\bench\models\distilbert-base-uncased")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    if not torch.cuda.is_available():
        print("[abort] CUDA 不可用（当前 torch 为 CPU 版）——按纪律不假跑")
        return 1
    device = torch.device("cuda")
    print(f"[gpu] {torch.cuda.get_device_name(0)}")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.base_model)

    # ---- 数据：严格三段切分（同 EXP-1006/1007）----
    rows = []
    with gzip.open(paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                   "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in CLASSES and len(r.get("descr") or "") > 0:
                rows.append({"sev": r["sev"], "descr": r["descr"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    tr = df[df["pub_dt"] < pd.Timestamp("2022-01-01")]
    va = df[(df["pub_dt"] >= pd.Timestamp("2022-01-01"))
            & (df["pub_dt"] < pd.Timestamp("2024-01-01"))]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    print(f"[data] train={len(tr)} val={len(va)} test={len(te)}")

    tr_loader = DataLoader(TextDataset(tr["descr"], tr["sev"], tok),
                           batch_size=BATCH, shuffle=True, num_workers=2,
                           drop_last=True)
    va_loader = DataLoader(TextDataset(va["descr"], va["sev"], tok),
                           batch_size=BATCH * 4, num_workers=2)
    te_loader = DataLoader(TextDataset(te["descr"], te["sev"], tok),
                           batch_size=BATCH * 4, num_workers=2)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=4,
        id2label={i: c for i, c in enumerate(CLASSES)},
        label2id={c: i for i, c in enumerate(CLASSES)},
    ).to(device)

    opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    total_steps = len(tr_loader) * EPOCHS
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=LR, total_steps=total_steps, pct_start=0.1)
    loss_fn = torch.nn.CrossEntropyLoss()

    best_val, best_state, history = -1.0, None, []
    for epoch in range(1, EPOCHS + 1):
        model.train()
        for step, batch in enumerate(tr_loader, start=1):
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.autocast("cuda", dtype=torch.bfloat16):
                logits = model(input_ids=batch["input_ids"],
                               attention_mask=batch["attention_mask"]).logits
            loss = loss_fn(logits, batch["labels"])
            loss.backward()
            opt.step()
            sched.step()
            opt.zero_grad()
            if step % 500 == 0:
                print(f"[e{epoch} step {step}/{len(tr_loader)}] loss={loss.item():.4f}")
        pv = predict(model, va_loader, device)
        pred_va = np.array(CLASSES)[pv.argmax(axis=1)]
        f1_va = f1_score(va["sev"], pred_va, average="macro", zero_division=0)
        acc_va = float((va["sev"].to_numpy() == pred_va).mean())
        history.append({"epoch": epoch, "val_macro_f1": round(float(f1_va), 4),
                        "val_acc": round(acc_va, 4)})
        print(f"[e{epoch}] val_f1={f1_va:.4f} val_acc={acc_va:.4f}")
        if f1_va > best_val:
            best_val = f1_va
            best_state = {k: v.detach().cpu().clone()
                          for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    pt = predict(model, te_loader, device)
    te_eval = _eval(te["sev"].to_numpy(), pt)

    out = {
        "experiment": "EXP-1010", "alias": ALIAS, "version": VERSION,
        "task": "严重度先验 v3：DistilBERT GPU 微调（用户解禁深度学习用于此分类模型）",
        "base_model": {"name": "distilbert-base-uncased", "params_m": 66,
                       "source": "hf-mirror 本地文件，预训练=通用英文（非安全数据）"},
        "data": {"kb": DATA_VERSION, "train": int(len(tr)), "val": int(len(va)),
                 "test": int(len(te))},
        "train": {"epochs": EPOCHS, "batch": BATCH, "max_len": MAX_LEN,
                  "lr": LR, "precision": "bf16 autocast",
                  "select": "val macro-F1 早停，test 只碰一次"},
        "history": history,
        "test": te_eval,
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1010-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    d = paths.out_root / "experiments" / f"EXP-1010-{ALIAS}-{VERSION}"
    d.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": best_state or model.state_dict(),
                "classes": CLASSES, "base": args.base_model}, d / "model.pt")
    man = manifest.make_manifest(
        kind="model", version=f"EXP-1010-{ALIAS}-{VERSION}",
        inputs=[manifest.file_input(d / "model.pt", role="output:model"),
                manifest.file_input(
                    paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                    role="upstream:kb_cve"),
                manifest.file_input(Path(args.base_model) / "pytorch_model.bin",
                                    role="upstream:base_weights")],
        params={"task": "sev-prior", "seed": SEED, "epochs": EPOCHS,
                "lr": LR, "batch": BATCH, "max_len": MAX_LEN},
        producer="ml/train_sev_bert.py",
        scope={"data_version": DATA_VERSION,
               "policy_note": "深度学习豁免仅限本分类模型（用户 2026-09-28 拍板）"},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": f"EXP-1010-{ALIAS}-{VERSION}",
                            "alias": ALIAS, "test": te_eval,
                            "data_version": DATA_VERSION}) + "\n")
    print(f"[TEST] {json.dumps(te_eval)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
