"""cve-tech v2（EXP-1014）：DistilBERT GPU 多标签微调——头牌的同等挑战赛。

头牌现役：EXP-1002-product-relation-model（TF-IDF + OvR SGD，
  全量测试 P@5=0.9085 / P@10=0.9425 / MRR=0.864）。
挑战者：DistilBERT-base + 200 类多标签头（BCEWithLogits，multi-hot），
  协议与 EXP-1002 逐项一致：kb-5.0.2 边表、top-200 宇宙、
  train pub<2024 / test >=2024 按 CVE 分组真值集合。
评测：同测试集同截断协议（P@5/P@10/MRR@5）重算双方——旧模型用
  持久化 joblib 在同集重打分，杜绝跨口径比较。
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import f1_score  # noqa: F401 (保留对齐习惯)
from torch.utils.data import DataLoader, Dataset
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: F401

from . import config, manifest

DATA_VERSION = "kb-5.0.2"
ALIAS = "cve-tech"
VERSION = "v2"
SEED = 20260928
MAX_LEN = 192
BATCH = 64
EPOCHS = 2
LR = 2e-5
TOP_N = 200


def load_tables(paths: config.Paths) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    kb = paths.out_root / "dataset" / DATA_VERSION
    def _load(name):
        with gzip.open(kb / name, "rt", encoding="utf-8") as f:
            return pd.DataFrame(json.loads(line) for line in f)
    return (_load("kb_cve_product.jsonl.gz"), _load("kb_cve.jsonl.gz"),
            _load("kb_product_stats.jsonl.gz"))


class MultiLabelDataset(Dataset):
    def __init__(self, texts, multihot: np.ndarray, tokenizer):
        self.texts = list(texts)
        self.labels = multihot.astype(np.float32)
        self.tok = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        enc = self.tok(self.texts[i], truncation=True, max_length=MAX_LEN,
                       padding="max_length", return_tensors="pt")
        return {"input_ids": enc["input_ids"][0],
                "attention_mask": enc["attention_mask"][0],
                "labels": torch.tensor(self.labels[i], dtype=torch.float32)}


@torch.no_grad()
def logits_of(model, loader, device) -> np.ndarray:
    model.eval()
    out = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits
        out.append(logits.float().cpu().numpy())
    return np.concatenate(out)


def _pk_mrr5(ranked5: list[list[int]], true_sets: list[set[int]]) -> dict:
    hits, mrr = 0, 0.0
    for ranked, ts in zip(ranked5, true_sets):
        for rank, c in enumerate(ranked[:5], start=1):
            if c in ts:
                hits += 1
                mrr += 1.0 / rank
                break
    n = max(1, len(ranked5))
    return {"P@5": round(hits / n, 4), "MRR@5": round(mrr / n, 4), "rows": n}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--base-model",
                    default=r"data\bench\models\distilbert-base-uncased")
    ap.add_argument("--prev-model",
                    default=r"data\ml\experiments\EXP-1002-product-relation-model\model.joblib")
    ap.add_argument("--out-root", default=None)
    ap.add_argument("--epochs", type=int, default=2)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    if not torch.cuda.is_available():
        print("[abort] CUDA 不可用——按纪律不假跑")
        return 1
    device = torch.device("cuda")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.base_model)

    edges, cve_meta, stats = load_tables(paths)
    edges["vendor_product"] = edges["vendor"] + "/" + edges["product"]
    classes = stats.head(TOP_N)["vendor_product"].tolist()
    cls_set = set(classes)
    cls_index = {c: i for i, c in enumerate(classes)}

    e = edges[edges["vendor_product"].isin(cls_set)].copy()
    meta_idx = cve_meta.set_index("cve")
    e["descr"] = e["cve"].map(meta_idx["descr"])
    e["pub"] = e["cve"].map(meta_idx["pub"])
    e = e.dropna(subset=["descr", "pub"])
    e["pub_dt"] = pd.to_datetime(e["pub"], errors="coerce")
    train_e = e[e["pub_dt"] < pd.Timestamp("2024-01-01")]
    test_e = e[e["pub_dt"] >= pd.Timestamp("2024-01-01")]

    te_groups = test_e.groupby("cve").agg(
        true_set=("vendor_product", lambda s: set(s)),
        descr=("descr", "first")).reset_index()
    label_space = sorted(train_e["vendor_product"].unique())
    lab_idx = {c: i for i, c in enumerate(label_space)}
    print(f"[data] classes={len(label_space)} test_cves={len(te_groups)}")

    # 训练样本：按 CVE 分组 multi-hot（训练段）
    tr_groups = train_e.groupby("cve").agg(
        classes=("vendor_product", lambda s: set(s)),
        descr=("descr", "first")).reset_index()
    tr_groups = tr_groups[tr_groups["classes"].map(
        lambda s: bool(s & cls_set))]
    tr_multi = np.zeros((len(tr_groups), len(label_space)), dtype=np.float32)
    for i, cs in enumerate(tr_groups["classes"]):
        for c in cs:
            if c in lab_idx:
                tr_multi[i, lab_idx[c]] = 1.0
    print(f"[train] cve_samples={len(tr_groups)}")

    tr_loader = DataLoader(
        MultiLabelDataset(tr_groups["descr"], tr_multi, tok),
        batch_size=BATCH, shuffle=True, num_workers=2, drop_last=True)
    te_multi = np.zeros((len(te_groups), len(label_space)), dtype=np.float32)
    for i, cs in enumerate(te_groups["true_set"]):
        for c in cs:
            if c in lab_idx:
                te_multi[i, lab_idx[c]] = 1.0
    te_loader = DataLoader(
        MultiLabelDataset(te_groups["descr"], te_multi, tok),
        batch_size=BATCH * 2, num_workers=2)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=len(label_space),
        problem_type="multi_label_classification").to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=LR, total_steps=len(tr_loader) * args.epochs, pct_start=0.1)
    loss_fn = torch.nn.BCEWithLogitsLoss()

    for epoch in range(1, args.epochs + 1):
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

    # ---- 现役基线同集重算（持久化 OvR SGD，截断协议 P@5/MRR@5）----
    true_sets = [set(t) for t in te_groups["true_set"]]
    art = joblib.load(Path(args.prev_model))
    Xbe = art["vectorizer"].transform(te_groups["descr"])
    proba = art["clf"].predict_proba(Xbe)
    bclasses = list(art["clf"].classes_)
    border = proba.argsort(axis=1)[:, ::-1]
    base_ranked5 = [[bclasses[j] for j in border[i][:5]] for i in range(len(te_groups))]
    base_metrics = _pk_mrr5(base_ranked5, true_sets)
    base_metrics["class_universe"] = len(bclasses)

    # ---- 挑战者评测：sigmoids 排序 → top5 ----
    logits_te = logits_of(model, te_loader, device)
    ranked5 = []
    for row in logits_te:
        order = np.argsort(-row)[:5]
        ranked5.append([label_space[j] for j in order])
    bert_metrics = _pk_mrr5(ranked5, true_sets)
    bert_metrics["class_universe"] = len(label_space)

    promoted = (bert_metrics["P@5"] > base_metrics["P@5"]
                and bert_metrics["MRR@5"] > base_metrics["MRR@5"])

    out = {
        "experiment": "EXP-1014", "alias": ALIAS, "version": VERSION,
        "task": "cve-tech v2：DistilBERT 多标签 GPU 微调挑战头牌（协议同 EXP-1002）",
        "base_model": {"name": "distilbert-base-uncased", "params_m": 66},
        "data": {"kb": DATA_VERSION, "train_cve_samples": int(len(tr_groups)),
                 "test_cves": int(len(te_groups)),
                 "top_universe": TOP_N},
        "eval_protocol": "同测试集同截断协议（top-5 内计分），基线用持久化 joblib 同集重算",
        "baseline_exp1002": base_metrics,
        "challenger_distilbert": bert_metrics,
        "promoted": bool(promoted),
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1014-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    if promoted:
        d = paths.out_root / "experiments" / f"EXP-1014-{ALIAS}-{VERSION}"
        d.mkdir(parents=True, exist_ok=True)
        torch.save({"state_dict": model.state_dict(),
                    "label_space": label_space,
                    "base": args.base_model}, d / "model.pt")
        man = manifest.make_manifest(
            kind="model", version=f"EXP-1014-{ALIAS}-{VERSION}",
            inputs=[manifest.file_input(d / "model.pt", role="output:model"),
                    manifest.file_input(
                        kb / "kb_cve_product.jsonl.gz", role="upstream:edges")],
            params={"task": "cve-tech", "seed": SEED, "epochs": args.epochs,
                    "lr": LR},
            producer="ml/train_cve_tech_bert.py",
            scope={"data_version": DATA_VERSION},
        )
        manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
        with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"exp_id": f"EXP-1014-{ALIAS}-{VERSION}",
                                "alias": ALIAS, "test": bert_metrics}) + "\n")

    print(json.dumps({"baseline": base_metrics, "distilbert": bert_metrics,
                      "promoted": promoted}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
