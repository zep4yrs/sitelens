"""cwe-type v2（EXP-1013）：DistilBERT GPU 微调——用户质疑 0.7709 非极限。

协议与 EXP-1005 逐项一致（可比性）：
  数据 kb-5.0.1 cwe 主弱点、top-25 类宇宙（按训练期频次）、
  train pub<2024 / test >=2024，指标 acc / macro-F1（多数类基线 0.2489）。
变化仅一处：表示层 TF-IDF+SGD → DistilBERT-base GPU 微调（bf16，2 epochs）。
深度学习豁免延续（同 sev-prior v3 的拍板范围：分类模型用）。
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

DATA_VERSION = "kb-5.0.1"
ALIAS = "cwe-type"
VERSION = "v2"
SEED = 20260928
MAX_LEN = 224
BATCH = 32
EPOCHS = 2
LR = 2e-5


class TextDataset(Dataset):
    def __init__(self, texts, labels, classes, tokenizer):
        self.texts = list(texts)
        self.labels = [classes.index(y) for y in labels]
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
def predict(model, loader, device, classes) -> np.ndarray:
    model.eval()
    probs = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits
        probs.append(torch.softmax(logits.float(), dim=-1).cpu())
    p = torch.cat(probs).numpy()
    return np.array(classes)[p.argmax(axis=1)]


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

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.base_model)

    # ---- 数据：EXP-1005 协议逐项一致 ----
    edges = pd.DataFrame(json.loads(line) for line in gzip.open(
        paths.out_root / "dataset" / DATA_VERSION / "kb_cve_cwe.jsonl.gz",
        "rt", encoding="utf-8"))
    primary = edges.drop_duplicates("cve", keep="first")
    meta = pd.DataFrame(json.loads(line) for line in gzip.open(
        paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
        "rt", encoding="utf-8"))[["cve", "descr", "pub"]]
    df = primary.merge(meta, on="cve", how="inner").dropna(subset=["descr", "pub"])
    df["pub_dt"] = pd.to_datetime(df["pub"], errors="coerce")
    tr = df[df["pub_dt"] < pd.Timestamp("2024-01-01")]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    classes = tr["cwe"].value_counts().head(25).index.tolist()
    cls_set = set(classes)
    tr = tr[tr["cwe"].isin(cls_set)]
    te = te[te["cwe"].isin(cls_set)]
    yte = te["cwe"].to_numpy()
    majority = tr["cwe"].value_counts().index[0]
    print(f"[data] train={len(tr)} test={len(te)} classes={len(classes)}")

    tr_loader = DataLoader(TextDataset(tr["descr"], tr["cwe"], classes, tok),
                           batch_size=BATCH, shuffle=True, num_workers=2,
                           drop_last=True)
    te_loader = DataLoader(TextDataset(te["descr"], te["cwe"], classes, tok),
                           batch_size=BATCH * 4, num_workers=2)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=len(classes),
        id2label={i: c for i, c in enumerate(classes)},
        label2id={c: i for i, c in enumerate(classes)},
    ).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=LR, total_steps=len(tr_loader) * EPOCHS, pct_start=0.1)
    loss_fn = torch.nn.CrossEntropyLoss()

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
            # 协议纪律：测试段仅在训练全部结束后评估一次

    pred = predict(model, te_loader, device, classes)
    acc = float((pred == yte).mean())
    mf1 = float(f1_score(yte, pred, average="macro", zero_division=0))
    base_acc = float((yte == majority).mean())

    out = {
        "experiment": "EXP-1013", "alias": ALIAS, "version": VERSION,
        "task": "cwe-type v2：DistilBERT GPU 微调（协议与 EXP-1005 逐项一致）",
        "base_model": {"name": "distilbert-base-uncased", "params_m": 66},
        "data": {"kb": DATA_VERSION, "train": int(len(tr)), "test": int(len(te)),
                 "n_classes": len(classes)},
        "train": {"epochs": EPOCHS, "batch": BATCH, "lr": LR,
                  "precision": "bf16 autocast"},
        "test": {"accuracy": round(acc, 4), "macro_f1": round(mf1, 4),
                 "majority_baseline_acc": round(base_acc, 4),
                 "prev_recipe": {"accuracy": 0.7709, "macro_f1": 0.5899}},
        "delta_vs_prev": {"accuracy": round(acc - 0.7709, 4),
                          "macro_f1": round(mf1 - 0.5899, 4)},
        "promoted": bool(acc > 0.7709 and mf1 > 0.5899),
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1013-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    if out["promoted"]:
        d = paths.out_root / "experiments" / f"EXP-1013-{ALIAS}-{VERSION}"
        d.mkdir(parents=True, exist_ok=True)
        torch.save({"state_dict": model.state_dict(), "classes": classes,
                    "base": args.base_model}, d / "model.pt")
        man = manifest.make_manifest(
            kind="model", version=f"EXP-1013-{ALIAS}-{VERSION}",
            inputs=[manifest.file_input(d / "model.pt", role="output:model"),
                    manifest.file_input(
                        paths.out_root / "dataset" / DATA_VERSION / "kb_cve_cwe.jsonl.gz",
                        role="upstream:cwe_edges")],
            params={"task": "cwe-type", "seed": SEED, "epochs": EPOCHS, "lr": LR},
            producer="ml/train_cwe_bert.py",
            scope={"data_version": DATA_VERSION},
        )
        manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
        with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"exp_id": f"EXP-1013-{ALIAS}-{VERSION}",
                                "alias": ALIAS, "test": out["test"]}) + "\n")

    print(json.dumps(out["test"], ensure_ascii=False))
    print(f"[delta] acc {out['delta_vs_prev']['accuracy']:+.4f} "
          f"f1 {out['delta_vs_prev']['macro_f1']:+.4f} "
          f"promoted={out['promoted']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
