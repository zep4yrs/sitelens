"""sev-prior v3.1-edge（EXP-1016）：异源边界专精——结构化信号 + HistGB。

上一轮（EXP-1015）边界专精与主模型同源同输入（都是描述文本 + DistilBERT），
100% 同判零增益。本轮改为真异源：
  模型类别异源：HistGradientBoosting（传统 ML 树模型）vs 主模型的神经网络
  输入异源：主模型只看描述文本；专精模型看【主模型分数 + 到最近档界距离 +
            CWE one-hot（top-25）+ 利用可用性信号（MSF/KEV/模板覆盖）+
            描述长度 + 年份】——全部是文本之外的结构化字段
训练：主分数由 EXP-1015 主回归器推理得出（train/val/test 全量推理）；
  专精训练集 = 训练段边界带（|真分数-最近档界|<=1.0），目标=分数是否>=档界。
评测：测试段边界带（|主分数-档界|<=0.75）上，精修前 vs 精修后档位 acc；
  整体 acc 不得回退。
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score

from . import config, manifest

DATA_VERSION = "kb-5.0.2"
ALIAS = "sev-prior"
VERSION = "v3.1-edge"
SEED = 20260928
EDGES = [4.0, 7.0, 9.0]
BAND_TOL_TRAIN = 1.0
BAND_TOL_INFER = 0.75
CLASSES = ["low", "medium", "high", "critical"]


def band_of(s: float) -> str:
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


def nearest_edge(scores: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    d = np.abs(scores[:, None] - np.array(EDGES)[None, :])
    idx = d.argmin(axis=1)
    return np.array(EDGES)[idx], d.min(axis=1)


@torch.no_grad()
def primary_scores(model, tok, texts: list[str], device, batch: int = 128,
                   max_len: int = 192) -> np.ndarray:
    model.eval()
    out = []
    for i in range(0, len(texts), batch):
        chunk = texts[i:i + batch]
        enc = tok(chunk, truncation=True, max_length=max_len,
                  padding=True, return_tensors="pt")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.autocast("cuda", dtype=torch.bfloat16):
            logits = model(input_ids=enc["input_ids"],
                           attention_mask=enc["attention_mask"]).logits
        out.append(logits.float().cpu().numpy().ravel() * 10.0)
    return np.concatenate(out)


def build_exploit_signals(paths: config.Paths, msf_path: Path) -> dict[str, dict]:
    sig: dict[str, dict] = {}
    msf = json.loads(msf_path.read_text(encoding="utf-8"))
    for m in msf.values():
        for ref in (m.get("references") or []) + list(m.get("cves") or []):
            for c in re.findall(r"CVE-\d{4}-\d{4,7}", str(ref)):
                sig.setdefault(c, {"msf": 0, "kev": 0, "tpl": 0})["msf"] += 1
    k = json.loads((paths.data_root / "state" / "kev_extra.json").read_text(
        encoding="utf-8"))
    entries = k.get("kev") if isinstance(k, dict) else k
    for e in entries or []:
        c = (e.get("cve") or "").upper()
        if c:
            sig.setdefault(c, {"msf": 0, "kev": 0, "tpl": 0})["kev"] = 1
    tpl = paths.out_root / "dataset" / "kb-5.0.1" / "kb_template_cve.jsonl.gz"
    if tpl.is_file():
        import gzip
        with gzip.open(tpl, "rt", encoding="utf-8") as f:
            for line in f:
                c = (json.loads(line).get("cve") or "").upper()
                if c:
                    sig.setdefault(c, {"msf": 0, "kev": 0, "tpl": 0})["tpl"] += 1
    return sig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--primary-model",
                    default=r"data\ml\experiments\EXP-1015-sev-prior-v3\model.pt")
    ap.add_argument("--msf-json", default=r"data\bench\external\msf_metadata.json")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    if not torch.cuda.is_available():
        print("[abort] CUDA 不可用")
        return 1
    device = torch.device("cuda")
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    pm_path = Path(args.primary_model)
    if not pm_path.is_absolute():
        pm_path = Path.cwd() / pm_path
    ckpt = torch.load(pm_path, map_location="cpu", weights_only=False)
    tok = AutoTokenizer.from_pretrained(ckpt["base"])
    reg = AutoModelForSequenceClassification.from_pretrained(
        ckpt["base"], num_labels=1)
    reg.load_state_dict(ckpt["reg"])
    reg.to(device)

    rows = []
    with gzip.open(paths.out_root / "dataset" / DATA_VERSION / "kb_cve.jsonl.gz",
                   "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("sev") in CLASSES and r.get("score") is not None \
                    and len(r.get("descr") or "") > 0:
                rows.append({"cve": r["cve"], "sev": r["sev"],
                             "score": float(r["score"]), "descr": r["descr"],
                             "pub_dt": pd.to_datetime(r.get("pub"), errors="coerce")})
    df = pd.DataFrame(rows).dropna(subset=["pub_dt"])
    df = df.sort_values("pub_dt").reset_index(drop=True)
    print(f"[data] rows={len(df)}")

    # 主分数：三段分别推理（时间顺序保证无泄漏）
    df["primary"] = np.nan
    masks = {"train": df["pub_dt"] < pd.Timestamp("2022-01-01"),
             "val": (df["pub_dt"] >= pd.Timestamp("2022-01-01"))
                    & (df["pub_dt"] < pd.Timestamp("2024-01-01")),
             "test": df["pub_dt"] >= pd.Timestamp("2024-01-01")}
    for tag, m in masks.items():
        idx = df.index[m]
        df.loc[idx, "primary"] = primary_scores(
            reg, tok, df.loc[idx, "descr"].tolist(), device)
        print(f"[primary] {tag}: n={len(idx)} "
              f"mae={np.abs(df.loc[idx, 'primary'] - df.loc[idx, 'score']).mean():.3f}")

    sig = build_exploit_signals(paths, Path(args.msf_json))
    cwe_of: dict[str, str] = {}
    with gzip.open(paths.out_root / "dataset" / "kb-5.0.1" / "kb_cve_cwe.jsonl.gz",
                   "rt", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            cwe_of.setdefault(r["cve"], r["cwe"])
    top_cwe = [c for c, _ in pd.Series(list(cwe_of.values())).value_counts()
               .head(25).items()]
    cwe_set = set(top_cwe)

    year = df["pub_dt"].dt.year.fillna(2020).to_numpy()
    dlen = df["descr"].str.len().to_numpy(dtype=np.float32)
    dlen = (dlen - dlen.mean()) / (dlen.std() + 1e-6)
    msf = np.array([sig.get(c, {}).get("msf", 0) for c in df["cve"]],
                   dtype=np.float32)
    kev = np.array([sig.get(c, {}).get("kev", 0) for c in df["cve"]],
                   dtype=np.float32)
    tpl = np.array([min(sig.get(c, {}).get("tpl", 0), 20) for c in df["cve"]],
                   dtype=np.float32) / 20.0
    cwe_oh = np.zeros((len(df), len(top_cwe)), dtype=np.float32)
    for i, c in enumerate(df["cve"]):
        w = cwe_of.get(c)
        if w in cwe_set:
            cwe_oh[i, top_cwe.index(w)] = 1.0

    edge, dist = nearest_edge(df["primary"].to_numpy())
    feats = np.column_stack([
        df["primary"].to_numpy(), edge, dist, msf, kev, tpl, cwe_oh, dlen, year
    ])
    y_true_band = df["sev"].to_numpy()
    band_primary = np.array([band_of(s) for s in df["primary"]], dtype=object)
    true_score = df["score"].to_numpy()

    # 训练：训练段边界带；目标=是否 >= 最近档界
    tr_mask = masks["train"].to_numpy() & (dist <= BAND_TOL_TRAIN)
    y_side = (true_score >= edge).astype(int)
    hgb = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.08,
                                         random_state=SEED)
    hgb.fit(feats[tr_mask], y_side[tr_mask])
    tr_acc = float(accuracy_score(y_side[tr_mask], hgb.predict(feats[tr_mask])))
    print(f"[specialist] train_boundary={int(tr_mask.sum())} "
          f"train_fit_acc={tr_acc:.4f}")

    # 测试段：边界带精修
    te_mask = masks["test"].to_numpy()
    te_idx = np.where(te_mask)[0]
    near = dist[te_mask] <= BAND_TOL_INFER
    sub_idx = te_idx[near]
    side_fix = hgb.predict(feats[sub_idx])
    refined = df["primary"].to_numpy().copy()
    e_sub, d_sub = nearest_edge(refined[sub_idx])
    # 纯专精裁决：翻边/保边只由 HistGB 的预测决定（部署时真值不存在）
    refined[sub_idx] = np.where(side_fix == 1, e_sub + 0.05, e_sub - 0.05)
    band_ref = np.array([band_of(s) for s in refined], dtype=object)

    overall_before = accuracy_score(y_true_band[te_idx], band_primary[te_idx])
    overall_after = accuracy_score(y_true_band[te_idx], band_ref[te_idx])
    b_before = accuracy_score(y_true_band[sub_idx], band_primary[sub_idx])
    b_after = accuracy_score(y_true_band[sub_idx], band_ref[sub_idx])

    out = {
        "experiment": "EXP-1016", "alias": ALIAS, "version": VERSION,
        "task": "异源边界专精：HistGB（结构化信号）裁决主模型贴线归侧",
        "hetero": {"model": "HistGradientBoosting（vs 主模型 DistilBERT）",
                   "inputs": "主分数/档界距离/CWE one-hot/MSF/KEV/模板覆盖/描述长度/年份"
                             "——全部为文本外结构化字段"},
        "data": {"test_rows": int(te_mask.sum()),
                 "boundary_rows": int(near.sum())},
        "specialist_train_fit_acc": round(tr_acc, 4),
        "boundary_subset": {"accuracy_before": round(float(b_before), 4),
                            "accuracy_after": round(float(b_after), 4)},
        "overall": {"accuracy_before": round(float(overall_before), 4),
                    "accuracy_after": round(float(overall_after), 4)},
        "promoted": bool(b_after > b_before and overall_after >= overall_before),
    }
    out_metrics = paths.out_root / "metrics"
    (out_metrics / f"EXP-1016-{ALIAS}-{VERSION}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
