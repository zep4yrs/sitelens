"""sev-prior v3.1（EXP-1011）：换信息源——CWE 可得设定下的 GPU 微调。

部署场景（如实标注）：厂商通告/模板情报常常先发布弱点类型（CWE）、
后发布 CVSS 评分。"CWE 已知、严重度未打分"是该模型的真实用武之地；
描述单源设定（v3，acc 0.5484）继续适用于连 CWE 都没有的早期阶段。

输入：描述 + [SEP] weakness type: CWE-XXX（训练行主弱点，来自 NVD 记录；
测试行同理——这是【CWE 可得】设定的定义，与描述单源口径不可直接比较）。
口径：严格三段切分不变；测试段只碰一次；95% 测试行带 CWE。
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
VERSION = "v3.1-cwe"
SEED = 20260928
CLASSES = ["low", "medium", "high", "critical"]
MAX_LEN = 224
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
        print("[abort] CUDA 不可用——按纪律不假跑")
        return 1
    device = torch.device("cuda")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.base_model)

    cwe_of: dict[str, str] = {}
    with gzip.open(paths.out_root / "dataset" / "kb-5.0.1" / "kb_cve_cwe.jsonl.gz",
                   "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            cwe_of.setdefault(r["cve"], r["cwe"])

    def _render(descr: str, cve: str, use_cwe: bool) -> str:
        if use_cwe and cve in cwe_of:
            return f"{descr} [SEP] weakness type: {cwe_of[cve]}"
        return descr

    rows = []
    with gzip.open(paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                   "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in CLASSES and len(r.get("descr") or "") > 0:
                rows.append({"cve": r["cve"], "sev": r["sev"],
                             "descr": r["descr"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    tr = df[df["pub_dt"] < pd.Timestamp("2022-01-01")]
    va = df[(df["pub_dt"] >= pd.Timestamp("2022-01-01"))
            & (df["pub_dt"] < pd.Timestamp("2024-01-01"))]
    te = df[df["pub_dt"] >= pd.Timestamp("2024-01-01")]
    # CWE 可得设定：只评带主弱点的行（95%）
    tr = tr[tr["cve"].isin(cwe_of)]
    va = va[va["cve"].isin(cwe_of)]
    te = te[te["cve"].isin(cwe_of)]
    print(f"[data] train={len(tr)} val={len(va)} test={len(te)} (CWE 可得行)")

    def render_set(d: pd.DataFrame, use_cwe: bool):
        texts = [_render(x.descr, x.cve, use_cwe) for x in d.itertuples()]
        return TextDataset(texts, d["sev"], tok)

    tr_loader = DataLoader(render_set(tr, True), batch_size=BATCH, shuffle=True,
                           num_workers=2, drop_last=True)
    va_loader = DataLoader(render_set(va, True), batch_size=BATCH * 4,
                           num_workers=2)
    te_loader = DataLoader(render_set(te, True), batch_size=BATCH * 4,
                           num_workers=2)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=4,
        id2label={i: c for i, c in enumerate(CLASSES)},
        label2id={c: i for i, c in enumerate(CLASSES)},
    ).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    sched = torch.optim.lr_scheduler.OneCycleLR(
        opt, max_lr=LR, total_steps=len(tr_loader) * EPOCHS, pct_start=0.1)
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
        history.append({"epoch": epoch,
                        "val_macro_f1": round(float(f1_va), 4)})
        print(f"[e{epoch}] val_f1={f1_va:.4f}")
        if f1_va > best_val:
            best_val = f1_va
            best_state = {k: v.detach().cpu().clone()
                          for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    pt = predict(model, te_loader, device)
    te_eval = _eval(te["sev"].to_numpy(), pt)

    out = {
        "experiment": "EXP-1011", "alias": ALIAS, "version": VERSION,
        "task": "严重度先验 v3.1：换信息源——CWE 可得设定（描述 + 主弱点类型）",
        "setting": ("厂商通告/模板情报先发布 CWE、后发布 CVSS 评分时的部署场景；"
                    "与描述单源（v3: acc 0.5484）口径不可直接比较"),
        "base_model": {"name": "distilbert-base-uncased", "params_m": 66},
        "data": {"kb": DATA_VERSION, "train": int(len(tr)), "val": int(len(va)),
                 "test": int(len(te)), "cwe_coverage": "95%"},
        "train": {"epochs": EPOCHS, "batch": BATCH, "lr": LR,
                  "input": "descr [SEP] weakness type: CWE-XXX"},
        "history": history,
        "test": te_eval,
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1011-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    d = paths.out_root / "experiments" / f"EXP-1011-{ALIAS}-{VERSION}"
    d.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": best_state or model.state_dict(),
                "classes": CLASSES, "base": args.base_model}, d / "model.pt")
    man = manifest.make_manifest(
        kind="model", version=f"EXP-1011-{ALIAS}-{VERSION}",
        inputs=[manifest.file_input(d / "model.pt", role="output:model"),
                manifest.file_input(
                    paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                    role="upstream:kb_cve"),
                manifest.file_input(
                    paths.out_root / "dataset" / "kb-5.0.1" / "kb_cve_cwe.jsonl.gz",
                    role="upstream:cwe")],
        params={"task": "sev-prior", "seed": SEED, "epochs": EPOCHS,
                "setting": "cwe-available"},
        producer="ml/train_sev_bert_cwe.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    with open(out_metrics / "summary.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": f"EXP-1011-{ALIAS}-{VERSION}",
                            "alias": ALIAS, "setting": "cwe-available",
                            "test": te_eval}) + "\n")
    print(f"[TEST] {json.dumps(te_eval)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
