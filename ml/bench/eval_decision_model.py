"""EXP-1004 决策模型侧：llama.cpp 类型化决策读出（预注册协议 §四）。

- E1：四选一严重度，GBNF 语法约束 + 首 token 概率质量 argmax
- E2：200 产品字母序编号列表置于前缀（prefix cache），输出 5 个编号，
      越界/解析失败该槽位计 miss（幻觉率如实报告）
- E3：候选特征 → 0-9 单 digit 概率期望分，排序后用与基线同一 metrics.eval_ranking

资源实测：逐调用时延 + psutil 每 1s 采样 llama-server 进程 RSS 峰值。
提示词冻结于 PRE_REGISTRATION.md，本脚本运行期不得修改。
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import threading
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import metrics
from . import metrics_shared

E1_GRAMMAR = 'root ::= "critical" | "high" | "medium" | "low"'
E2_GRAMMAR = 'root ::= num ("," num){4}\nnum ::= [1-9] [0-9]? [0-9]?'
E3_GRAMMAR = "root ::= [0-9]"

E1_PROMPT = (
    "You are a vulnerability triage assistant. Classify the severity of the CVE below.\n\n"
    "CVE description:\n{descr}\n\n"
    "Answer with exactly one word: critical, high, medium, or low.\nSeverity: "
)

E2_HEAD = (
    "You are a vulnerability analysis assistant. Below is a numbered list of {n} "
    "software products (format: vendor/product).\n\nProduct list:\n{lst}\n\n"
    "CVE description:\n{descr}\n\n"
    "Which products are affected by this CVE? Output the IDs of the 5 most likely "
    'affected products, most likely first, as comma-separated numbers (e.g. "17, 3, 105, 42, 88"). '
    "Output only the numbers.\nIDs: "
)

E3_PROMPT = (
    "You are a security scanner assistant. A web scanner produced the candidate "
    "finding below and must decide what to verify first.\n\nFinding:\n"
    "- check id: {check_id}\n- severity: {sev}\n- level: {level} (lv {lv})\n"
    "- cms linked: {cms}\n- prior hits of this check on this host: {prior}\n\n"
    "Score how worthwhile it is to verify this finding next, 0 (skip) to 9 "
    "(highest priority). Answer with a single digit.\nScore: "
)


class LlamaClient:
    def __init__(self, base_url: str):
        self.url = base_url.rstrip("/") + "/completion"

    def post(self, prompt: str, grammar: str, n_predict: int = 1,
             n_probs: int = 20) -> dict:
        payload = {
            "prompt": prompt, "grammar": grammar, "n_predict": n_predict,
            "temperature": 0.0, "n_probs": n_probs, "cache_prompt": True,
        }
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read().decode("utf-8"))

    def first_token_dist(self, resp: dict) -> list[tuple[str, float]]:
        """容忍多版本字段名，取首个生成 token 的候选分布 [(piece, prob)]。"""
        entries = None
        for key in ("completion_probabilities", "probs", "logprobs"):
            v = resp.get(key)
            if isinstance(v, list) and v:
                entries = v
                break
        if not entries:
            return []
        first = entries[0]
        if isinstance(first, dict):
            inner = first.get("probs")
            if isinstance(inner, list) and inner:
                return [(str(p.get("tok_str") or p.get("token") or p.get("piece") or ""),
                         float(p.get("prob") or 0.0)) for p in inner]
            piece = str(first.get("tok_str") or first.get("token")
                        or first.get("piece") or first.get("content") or "")
            return [(piece, float(first.get("prob") or 0.0))]
        return []


def _truncate(text: str, n: int = 600) -> str:
    return text if len(text) <= n else text[:n]


def run_e1(client: LlamaClient, eval_dir: Path, res_dir: Path,
           workers: int) -> dict:
    import gzip
    with gzip.open(eval_dir / "e1_severity.jsonl.gz", "rt", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f]

    def one(row):
        t0 = time.perf_counter()
        resp = client.post(E1_PROMPT.format(descr=_truncate(row["descr"])),
                           E1_GRAMMAR, n_predict=1)
        dt = time.perf_counter() - t0
        dist = client.first_token_dist(resp)
        mass = {"critical": 0.0, "high": 0.0, "medium": 0.0, "low": 0.0}
        for piece, p in dist:
            s = piece.strip().lower()
            for cls in mass:
                if s.startswith(cls[:4]):
                    mass[cls] += p
                    break
        pred = max(mass, key=mass.get)
        return row, pred, mass, dt

    results, lat = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for row, pred, mass, dt in ex.map(one, rows):
            results.append((row, pred, mass))
            lat.append(dt)

    samples_path = res_dir / "lm_e1_samples.jsonl"
    with open(samples_path, "w", encoding="utf-8") as f:
        for row, pred, mass in results:
            f.write(json.dumps({"cve": row["cve"], "true": row["sev"],
                                "pred": pred, "mass": mass},
                               ensure_ascii=False) + "\n")
    y_true = [r["sev"] for r, _, _ in results]
    y_pred = [p for _, p, _ in results]
    m = metrics_shared.e1_class_metrics(y_true, y_pred)
    m["task"] = "E1 severity classification"
    m["latency_p50_s"] = round(statistics.median(lat), 3)
    m["latency_p95_s"] = round(sorted(lat)[int(0.95 * (len(lat) - 1))], 3)
    return m


def run_e2(client: LlamaClient, eval_dir: Path, res_dir: Path,
           workers: int) -> dict:
    import gzip
    with gzip.open(eval_dir / "e2_product.jsonl.gz", "rt", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f]
    products = json.loads((eval_dir / "e2_products_200.json").read_text(encoding="utf-8"))
    lst = "\n".join(f"{i + 1}. {p}" for i, p in enumerate(products))
    head_tpl = E2_HEAD.format(n=len(products), lst="{lst}", descr="{descr}")

    def one(row):
        prompt = head_tpl.format(lst=lst, descr=_truncate(row["descr"]))
        t0 = time.perf_counter()
        resp = client.post(prompt, E2_GRAMMAR, n_predict=40)
        dt = time.perf_counter() - t0
        ids = [int(x) for x in re.findall(r"\d+", resp.get("content", ""))]
        valid = []
        seen = set()
        for i in ids:
            if 1 <= i <= len(products) and i not in seen:
                seen.add(i)
                valid.append(products[i - 1])
        invalid = len(ids) - len(valid)
        return row, valid[:5], invalid, dt

    results, lat, invalid_total = [], [], 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for row, top5, inv, dt in ex.map(one, rows):
            results.append((row, top5))
            lat.append(dt)
            invalid_total += inv

    samples_path = res_dir / "lm_e2_samples.jsonl"
    with open(samples_path, "w", encoding="utf-8") as f:
        for row, top5 in results:
            f.write(json.dumps({"cve": row["cve"], "true": sorted(row["true_set"]),
                                "top5": top5}, ensure_ascii=False) + "\n")
    m = metrics_shared.pk5_mrr5([t for _, t in results],
                                [set(r["true_set"]) for r, _ in results])
    m["task"] = "E2 product relation (200-class, truncated protocol)"
    m["invalid_slots"] = invalid_total
    m["latency_p50_s"] = round(statistics.median(lat), 3)
    m["latency_p95_s"] = round(sorted(lat)[int(0.95 * (len(lat) - 1))], 3)
    return m


def run_e3(client: LlamaClient, eval_dir: Path, res_dir: Path,
           workers: int) -> dict:
    import gzip
    with gzip.open(eval_dir / "e3_candidates.jsonl.gz", "rt", encoding="utf-8") as f:
        cand = [json.loads(line) for line in f]
    with gzip.open(eval_dir / "e3_positives.jsonl.gz", "rt", encoding="utf-8") as f:
        pos = [json.loads(line) for line in f]

    def one(row):
        prompt = E3_PROMPT.format(
            check_id=row["check_id"], sev=row["check_severity"],
            level=row["level"], lv=row["check_lv"],
            cms=str(bool(row["cms_linked_flag"])).lower(),
            prior=row["prior_hits_this_check"])
        t0 = time.perf_counter()
        resp = client.post(prompt, E3_GRAMMAR, n_predict=1)
        dt = time.perf_counter() - t0
        dist = client.first_token_dist(resp)
        digits = {}
        for piece, p in dist:
            s = piece.strip()
            if len(s) == 1 and s.isdigit():
                digits[s] = digits.get(s, 0.0) + p
        total = sum(digits.values())
        expected = (sum(int(d) * p for d, p in digits.items()) / total) if total else 0.0
        return row, expected, digits, dt

    results, lat = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for row, expected, digits, dt in ex.map(one, cand):
            results.append((row, expected, digits))
            lat.append(dt)

    samples_path = res_dir / "lm_e3_samples.jsonl"
    with open(samples_path, "w", encoding="utf-8") as f:
        for row, expected, digits in results:
            f.write(json.dumps({"scan_uid": row["scan_uid"],
                                "check_id": row["check_id"],
                                "expected": round(expected, 4),
                                "digits": digits}, ensure_ascii=False) + "\n")

    by_query: dict[str, list[tuple[float, str]]] = {}
    for row, expected, _ in results:
        by_query.setdefault(row["scan_uid"], []).append((expected, row["check_id"]))
    ranked = {uid: [c for _, c in sorted(v, key=lambda t: (-t[0], t[1]))]
              for uid, v in by_query.items()}
    rel: dict[str, set[str]] = {}
    for p in pos:
        rel.setdefault(p["scan_uid"], set()).add(p["check"])
    rel = {u: s for u, s in rel.items() if u in ranked and s & set(ranked[u])}
    m = metrics.eval_ranking(ranked, rel, ks=(5, 10))
    m["task"] = "E3 candidate ranking (19 positive queries, observed-only)"
    m["latency_p50_s"] = round(statistics.median(lat), 3)
    m["latency_p95_s"] = round(sorted(lat)[int(0.95 * (len(lat) - 1))], 3)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8817")
    ap.add_argument("--model-name", required=True)
    ap.add_argument("--model-file", default="")
    ap.add_argument("--server-pid", type=int, default=0)
    ap.add_argument("--load-time-s", type=float, default=None)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out-root", default="data/ml")
    ap.add_argument("--probe", action="store_true",
                    help="只发一次探针请求并打印原始响应（调试字段名用）")
    args = ap.parse_args()

    client = LlamaClient(args.base_url)
    out_root = Path(args.out_root)
    eval_dir = out_root / "bench" / "eval_sets"
    res_dir = out_root / "bench" / "results"
    res_dir.mkdir(parents=True, exist_ok=True)

    if args.probe:
        resp = client.post(E3_PROMPT.format(
            check_id="git-leak", sev="high", level="core", lv=0, cms="false",
            prior=1), E3_GRAMMAR, n_predict=1)
        print(json.dumps(resp, ensure_ascii=False)[:3000])
        return 0

    stop = threading.Event()
    peak = {"rss_mb": 0.0}

    def sampler():
        if not args.server_pid:
            return
        try:
            import psutil
            proc = psutil.Process(args.server_pid)
            while not stop.is_set():
                peak["rss_mb"] = max(peak["rss_mb"],
                                     proc.memory_info().rss / 1e6)
                stop.wait(1.0)
        except Exception as e:  # 进程退出/权限不足：如实记录
            print(f"[rss sampler stopped] {e}")

    threading.Thread(target=sampler, daemon=True).start()
    t0 = time.perf_counter()
    res = {
        "experiment": "EXP-1004",
        "side": "decision-model",
        "model_name": args.model_name,
        "model_file": args.model_file,
        "server": {"runtime": "llama.cpp b11222 win-cpu-x64",
                   "threads": 24, "parallel_slots": args.workers,
                   "temperature": 0},
        "e1_severity": run_e1(client, eval_dir, res_dir, args.workers),
        "e2_product": run_e2(client, eval_dir, res_dir, args.workers),
        "e3_candidates": run_e3(client, eval_dir, res_dir, args.workers),
    }
    stop.set()
    res["resources"] = {
        "llama_server_peak_rss_mb": round(peak["rss_mb"], 1),
        "load_time_s": args.load_time_s,
        "wall_time_s": round(time.perf_counter() - t0, 1),
        "rss_note": "峰值采样自 llama-server 进程 WorkingSet，按需加载场景的瞬时占用",
    }
    out = res_dir / "lm_on_same_sets.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=1)[:2600])
    print(f"[saved] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
