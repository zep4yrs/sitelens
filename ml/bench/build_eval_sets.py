"""EXP-1004 评测集构建（预注册产物，先于任何决策模型运行）。

三个任务全部来自主仓库 kb-5.0.0 真实数据：
  E1 严重度分类  kb_cve，sev∈{critical,high,medium,low}，pub>=2024-01-01
                （与 EXP-1001 同时间切分），按类分层等比例抽样 N=1500
  E2 产品关系    kb_cve_product 限定 top-200 vendor_product（EXP-1002 同类宇宙），
                pub>=2024，按 CVE 分组真值集合，抽样 N=800
  E3 候选排序    d4b_candidates 全量 + verified src=check 观测正例，
                特征构建复用 features.build_candidate_features（as-of 先验同源）

抽样 seed=20260928；产物落 data/ml/bench/eval_sets/，带 sha256 清单。
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import pandas as pd

from .. import config, dataset, features, manifest

SEED = 20260928
CUT = pd.Timestamp("2024-01-01")
SEV_CLASSES = ["critical", "high", "medium", "low"]
E1_N = 1500
E2_N = 800
TOP_N = 200


def _load_jsonl(path: Path) -> pd.DataFrame:
    import gzip
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return pd.DataFrame(json.loads(line) for line in f)


def _write_jsonl(df: pd.DataFrame, path: Path) -> None:
    import gzip
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for _, row in df.iterrows():
            f.write(json.dumps(row.to_dict(), ensure_ascii=False, default=str) + "\n")


def _stratified_sample(df: pd.DataFrame, col: str, n: int, seed: int) -> pd.DataFrame:
    """按类分层等比例抽样（最大余数法补齐到精确 n）。"""
    counts = df[col].value_counts()
    quotas = (counts / len(df) * n).astype(int)
    remain = n - int(quotas.sum())
    if remain > 0:
        frac = (counts / len(df) * n) - quotas
        for cls in frac.sort_values(ascending=False).index[:remain]:
            quotas[cls] += 1
    parts = []
    for cls, q in quotas.items():
        g = df[df[col] == cls]
        q = min(q, len(g))
        parts.append(g.sample(n=q, random_state=seed))
    out = pd.concat(parts).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return out


def build_e1(kb_dir: Path, out_dir: Path) -> pd.DataFrame:
    cve = _load_jsonl(kb_dir / "kb_cve.jsonl.gz")
    cve = cve[cve["sev"].isin(SEV_CLASSES)].copy()
    cve["pub_dt"] = pd.to_datetime(cve["pub"], errors="coerce")
    test = cve[cve["pub_dt"] >= CUT]
    sample = _stratified_sample(test[["cve", "descr", "sev", "pub"]], "sev", E1_N, SEED)
    _write_jsonl(sample, out_dir / "e1_severity.jsonl.gz")
    print(f"[E1] test_rows={len(test)} sampled={len(sample)} "
          f"dist={Counter(sample['sev'])}")
    return sample


def build_e2(kb_dir: Path, out_dir: Path) -> tuple[pd.DataFrame, list[str]]:
    stats = _load_jsonl(kb_dir / "kb_product_stats.jsonl.gz")
    classes = stats.head(TOP_N)["vendor_product"].tolist()
    # 字母序（防频次序泄露先验捷径；预注册 §四）
    products = sorted(classes)

    edges = _load_jsonl(kb_dir / "kb_cve_product.jsonl.gz")
    edges["vendor_product"] = edges["vendor"] + "/" + edges["product"]
    e = edges[edges["vendor_product"].isin(classes)].copy()
    cve = _load_jsonl(kb_dir / "kb_cve.jsonl.gz").set_index("cve")
    e["descr"] = e["cve"].map(cve["descr"])
    e["pub"] = e["cve"].map(cve["pub"])
    e = e.dropna(subset=["descr", "pub"])
    e["pub_dt"] = pd.to_datetime(e["pub"], errors="coerce")
    test = e[e["pub_dt"] >= CUT]
    groups = test.groupby("cve").agg(
        true_set=("vendor_product", lambda s: sorted(set(s))),
        descr=("descr", "first")).reset_index()
    sample = groups.sample(n=min(E2_N, len(groups)), random_state=SEED)\
        .reset_index(drop=True)
    _write_jsonl(sample, out_dir / "e2_product.jsonl.gz")
    (out_dir / "e2_products_200.json").write_text(
        json.dumps(products, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[E2] test_cves={len(groups)} sampled={len(sample)} classes={len(products)}")
    return sample, products


def build_e3(paths: config.Paths, out_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    tables, _, _ = dataset.build_tables(paths)
    cand, _ = features.build_candidate_features(
        tables["candidates"], tables["verified"], tables["scans"])
    cols = ["scan_uid", "host", "check_id", "check_severity", "sev_ord",
            "check_lv", "level", "cms_linked_flag", "prior_hits_this_check"]
    cand_out = cand[cols].copy()
    _write_jsonl(cand_out, out_dir / "e3_candidates.jsonl.gz")
    pos = tables["verified"]
    pos = pos[pos["src"] == "check"][["scan_uid", "check", "src"]] if len(pos) else pos
    _write_jsonl(pos, out_dir / "e3_positives.jsonl.gz")
    n_pos_queries = len(set(pos["scan_uid"]) & set(cand_out["scan_uid"]))
    print(f"[E3] candidates={len(cand_out)} positives={len(pos)} "
          f"query_overlap={n_pos_queries}")
    return cand_out, pos


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data",
                    help="主仓库数据根（含 state/history.json）")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)
    out_dir = paths.out_root / "bench" / "eval_sets"
    out_dir.mkdir(parents=True, exist_ok=True)
    kb_dir = paths.out_root / "dataset" / "kb"

    e1 = build_e1(kb_dir, out_dir)
    e2, products = build_e2(kb_dir, out_dir)
    e3, pos = build_e3(paths, out_dir)

    inputs = [kb_dir / "kb_cve.jsonl.gz", kb_dir / "kb_cve_product.jsonl.gz",
              kb_dir / "kb_product_stats.jsonl.gz",
              paths.out_root / "dataset" / "d4b_candidates.jsonl.gz",
              paths.out_root / "dataset" / "d4_verified.jsonl.gz"]
    man = manifest.make_manifest(
        kind="dataset", version="exp1004-eval-sets",
        inputs=[manifest.file_input(p, role="upstream") for p in inputs],
        params={"seed": SEED, "e1_n": len(e1), "e2_n": len(e2),
                "e3_rows": len(e3), "e3_positives": len(pos),
                "e2_classes": len(products), "cut": str(CUT.date()),
                "split_note": "E1/E2 与 EXP-1001/1002 同一时间切分 pub>=2024"},
        producer="ml/bench/build_eval_sets.py",
        scope={"data_version": "kb-5.0.0", "experiment": "EXP-1004"},
    )
    for f in sorted(out_dir.glob("*.gz")) + sorted(out_dir.glob("*.json")):
        man["inputs"].append(manifest.file_input(f, role="output"))
    manifest.write_manifest(man, out_dir / "EVAL_SETS_MANIFEST.json")
    print(f"[manifest] {out_dir / 'EVAL_SETS_MANIFEST.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
