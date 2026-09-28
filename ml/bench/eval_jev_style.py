"""EXP-1004 正主阵营：Jev-Style v3 0.8B（chaoliangUNSW，Apache-2.0）原生接口评测。

与零样本基座（eval_decision_model.py 的 Qwen3-0.6B）不同，这是真实决策模型，
用它自带的 decide(状态, 问题, 选项, 类别) 接口——每个选项返回校准概率：
  E1: 选项 = critical/high/medium/low（描述=词本身，不加额外暗示）
  E2: 选项 = 200 个 vendor/product（v3 分块选项原生支持，一次调用全排序）
  E3: 选项 = "0".."9"，期望分 = Σp·d（与 digit 协议同口径）
指标与基线共用 metrics_shared / metrics.eval_ranking；预注册闸门不变。
"""

from __future__ import annotations

import argparse
import gzip
import json
import statistics
import threading
import time
from pathlib import Path

from .. import metrics
from . import metrics_shared

E1_OPTIONS = {"critical": "critical", "high": "high",
              "medium": "medium", "low": "low"}
E1_QUESTION = "What is the severity of this CVE?"
E1_CATEGORY = "cve_severity"

E2_QUESTION = "Which products are affected by this CVE?"
E2_CATEGORY = "product_relation"

E3_OPTIONS = {"0": "skip", "1": "very low", "2": "low", "3": "below average",
              "4": "average", "5": "above average", "6": "moderately high",
              "7": "high", "8": "very high", "9": "highest priority"}
E3_QUESTION = ("A web scanner produced this candidate finding. "
               "How worthwhile is it to verify this finding next?")
E3_CATEGORY = "verification_priority"


def _e3_state(row: dict) -> str:
    return (f"check id: {row['check_id']}; severity: {row['check_severity']}; "
            f"level: {row['level']} (lv {row['check_lv']}); "
            f"cms linked: {str(bool(row['cms_linked_flag'])).lower()}; "
            f"prior hits of this check on this host: {row['prior_hits_this_check']}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir",
                    default=r"data\bench\models\jev-v3")
    ap.add_argument("--tasks", default="e1,e2,e3")
    ap.add_argument("--out-root", default="data/ml")
    args = ap.parse_args()

    import psutil
    import torch
    torch.set_num_threads(max(1, psutil.cpu_count(logical=False) or 24))

    import sys
    sys.path.insert(0, str(Path(args.model_dir).resolve()))
    from jev_style_decision import JevStyleDecision

    proc = psutil.Process()
    t0 = time.perf_counter()
    model = JevStyleDecision(args.model_dir)
    load_s = time.perf_counter() - t0
    rss_base_mb = proc.memory_info().rss / 1e6

    peak = {"rss_mb": rss_base_mb}
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            peak["rss_mb"] = max(peak["rss_mb"], proc.memory_info().rss / 1e6)
            stop.wait(0.5)

    threading.Thread(target=sampler, daemon=True).start()

    def decide(state, question, options, category):
        t = time.perf_counter()
        r = model.decide(state, question, options=options, category=category)
        return r, time.perf_counter() - t

    eval_dir = Path(args.out_root) / "bench" / "eval_sets"
    res_dir = Path(args.out_root) / "bench" / "results"
    res_dir.mkdir(parents=True, exist_ok=True)
    tasks = {t.strip() for t in args.tasks.split(",") if t.strip()}
    res: dict = {"experiment": "EXP-1004", "side": "decision-model-native",
                 "model_name": "Jev-Style-0.8B-Decision-v3 (safetensors bf16, CPU)",
                 "tasks_run": sorted(tasks)}

    if "e1" in tasks:
        with gzip.open(eval_dir / "e1_severity.jsonl.gz", "rt", encoding="utf-8") as f:
            rows = [json.loads(line) for line in f]
        out, lat = [], []
        for row in rows:
            r, dt = decide(row["descr"][:4000], E1_QUESTION, E1_OPTIONS, E1_CATEGORY)
            out.append((row, r["answer"]))
            lat.append(dt)
        with open(res_dir / "jev_e1_samples.jsonl", "w", encoding="utf-8") as f:
            for row, ans in out:
                f.write(json.dumps({"cve": row["cve"], "true": row["sev"],
                                    "pred": ans}, ensure_ascii=False) + "\n")
        m = metrics_shared.e1_class_metrics([r["sev"] for r, _ in out],
                                            [a for _, a in out])
        m["task"] = "E1 severity classification (native decide)"
        m["latency_p50_s"] = round(statistics.median(lat), 3)
        m["latency_p95_s"] = round(sorted(lat)[int(0.95 * (len(lat) - 1))], 3)
        res["e1_severity"] = m

    if "e2" in tasks:
        with gzip.open(eval_dir / "e2_product.jsonl.gz", "rt", encoding="utf-8") as f:
            rows = [json.loads(line) for line in f]
        products = json.loads((eval_dir / "e2_products_200.json").read_text(encoding="utf-8"))
        opts = {p: p for p in products}
        out, lat, errors = [], [], 0
        for row in rows:
            try:
                r, dt = decide(row["descr"][:4000], E2_QUESTION, opts, E2_CATEGORY)
                probs = r.get("probabilities") or {}
                ranked = sorted(probs, key=lambda k: -float(probs[k]))
            except Exception:
                ranked, dt = [], 0.0
                errors += 1
            out.append((row, ranked[:5]))
            lat.append(dt)
        with open(res_dir / "jev_e2_samples.jsonl", "w", encoding="utf-8") as f:
            for row, top5 in out:
                f.write(json.dumps({"cve": row["cve"], "true": sorted(row["true_set"]),
                                    "top5": top5}, ensure_ascii=False) + "\n")
        m = metrics_shared.pk5_mrr5([t for _, t in out],
                                    [set(r["true_set"]) for r, _ in out])
        m["task"] = "E2 product relation (native decide, 200 options, chunked)"
        m["decide_errors"] = errors
        ok_lat = [x for x in lat if x > 0]
        if ok_lat:
            m["latency_p50_s"] = round(statistics.median(ok_lat), 3)
            m["latency_p95_s"] = round(sorted(ok_lat)[int(0.95 * (len(ok_lat) - 1))], 3)
        res["e2_product"] = m

    if "e3" in tasks:
        with gzip.open(eval_dir / "e3_candidates.jsonl.gz", "rt", encoding="utf-8") as f:
            cand = [json.loads(line) for line in f]
        with gzip.open(eval_dir / "e3_positives.jsonl.gz", "rt", encoding="utf-8") as f:
            pos = [json.loads(line) for line in f]
        out, lat = [], []
        for row in cand:
            r, dt = decide(_e3_state(row), E3_QUESTION, E3_OPTIONS, E3_CATEGORY)
            probs = r.get("probabilities") or {}
            expected = sum(int(k) * float(v) for k, v in probs.items()
                           if k.isdigit())
            out.append((row, expected))
            lat.append(dt)
        with open(res_dir / "jev_e3_samples.jsonl", "w", encoding="utf-8") as f:
            for row, expected in out:
                f.write(json.dumps({"scan_uid": row["scan_uid"],
                                    "check_id": row["check_id"],
                                    "expected": round(expected, 4)},
                                   ensure_ascii=False) + "\n")
        by_query: dict[str, list[tuple[float, str]]] = {}
        for row, expected in out:
            by_query.setdefault(row["scan_uid"], []).append(
                (expected, row["check_id"]))
        ranked = {uid: [c for _, c in sorted(v, key=lambda t: (-t[0], t[1]))]
                  for uid, v in by_query.items()}
        rel: dict[str, set[str]] = {}
        for p in pos:
            rel.setdefault(p["scan_uid"], set()).add(p["check"])
        rel = {u: s for u, s in rel.items() if u in ranked and s & set(ranked[u])}
        m = metrics.eval_ranking(ranked, rel, ks=(5, 10))
        m["task"] = "E3 candidate ranking (native decide, 10-point expected score)"
        m["latency_p50_s"] = round(statistics.median(lat), 3)
        m["latency_p95_s"] = round(sorted(lat)[int(0.95 * (len(lat) - 1))], 3)
        res["e3_candidates"] = m

    stop.set()
    res["resources"] = {
        "load_time_s": round(load_s, 1),
        "process_peak_rss_mb": round(peak["rss_mb"], 1),
        "process_base_rss_mb": round(rss_base_mb, 1),
        "rss_note": "python 评测进程 WorkingSet（含 torch 运行时 + 模型权重）",
    }
    out_path = res_dir / "jev_on_same_sets.json"
    out_path.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=1)[:2600])
    print(f"[saved] {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
