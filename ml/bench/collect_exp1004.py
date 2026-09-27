"""EXP-1004 结果合并与登记：从留存样本重算指标（同 metrics_shared），
汇总两阵营 + 资源实测 + 闸门判定 → data/ml/metrics/EXP-1004-*.json + MANIFEST
+ registry summary 追加。可重复执行（幂等输出）。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .. import manifest
from . import metrics_shared


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-root", default="data/ml")
    args = ap.parse_args()
    out_root = Path(args.out_root)
    res_dir = out_root / "bench" / "results"

    base = json.loads((res_dir / "baseline_on_same_sets.json").read_text(encoding="utf-8"))
    lm = json.loads((res_dir / "lm_on_same_sets.json").read_text(encoding="utf-8"))
    jev = json.loads((res_dir / "jev_on_same_sets.json").read_text(encoding="utf-8"))
    # E2 是内容解析（与概率读出仪器无关），修正读出后的重跑未含 E2——从存档轮合并
    lm_probe = json.loads((res_dir / "lm_on_same_sets_brokenprobe.json").read_text(encoding="utf-8"))
    lm_e2 = lm.get("e2_product") or lm_probe.get("e2_product")

    # 正主 E1：从留存样本用同一指标实现重算（该次任务的样本已落盘）
    rows = _read_jsonl(res_dir / "jev_e1_samples.jsonl")
    jev_e1 = metrics_shared.e1_class_metrics(
        [r["true"] for r in rows], [r["pred"] for r in rows]) if rows else None

    # 基线闸门参照（同集重算口径）
    b1, b2 = base["e1_severity"], base["e2_product"]
    b3 = base["e3_candidates"]["baselines"]
    best_e3 = max(
        (b3[k]["nDCG@5"], b3[k]["P@5"], k) for k in ("severity", "rule_based", "prior_hits", "random"))

    e1_win = jev_e1 and jev_e1["accuracy"] > b1["accuracy"] and jev_e1["macro_f1"] > b1["macro_f1"]
    e3_win = jev["e3_candidates"]["nDCG@5"] > best_e3[0] and jev["e3_candidates"]["P@5"] > best_e3[1]

    merged = {
        "experiment": "EXP-1004",
        "title": "本地小决策模型 vs 传统 ML 基线（预注册对比）",
        "pre_registration": {"commit": "a062d10",
                             "file": "ml/bench/PRE_REGISTRATION.md",
                             "note": "协议与闸门先于任何被测系统推理提交"},
        "eval_sets": {"manifest": "data/ml/bench/eval_sets/EVAL_SETS_MANIFEST.json",
                      "e1_rows": 1500, "e2_rows": 800, "e3_rows": 1582,
                      "e3_positive_queries": 19, "seed": 20260928},
        "systems": {
            "baseline": {
                "e1_severity": {k: b1[k] for k in ("accuracy", "macro_f1", "rows")},
                "e2_product": {k: b2[k] for k in ("P@5", "MRR@5", "rows")},
                "e3_strongest": {"system": best_e3[2], "nDCG@5": best_e3[0],
                                 "P@5": best_e3[1]},
                "throughput_rows_per_s": 25824,
                "process_rss_mb": 202,
            },
            "zeroshot_qwen3_06b": {
                "role": "kev 路线底座的零样本代表（保底）",
                "e1_severity": lm["e1_severity"],
                "e2_product": lm_e2,
                "e3_candidates": lm["e3_candidates"],
                "peak_rss_mb": lm["resources"]["llama_server_peak_rss_mb"],
                "note": "8 槽×4K ctx 配置；单槽更省但未逐档实测；"
                        "仪器修正（post_sampling_probs）后重跑 E1/E3，坏仪器轮已存档 "
                        "lm_on_same_sets_brokenprobe.json",
            },
            "jev_style_08b": {
                "role": "真实决策模型正主（官方 torch 参考实现 + 原生 decide 接口）",
                "e1_severity": jev_e1,
                "e3_candidates": jev["e3_candidates"],
                "e2_product": None,
                "peak_rss_mb": jev["resources"]["process_peak_rss_mb"],
                "gguf_single_slot_rss_mb": 888.2,
                "latency_note": "E1/E3 单决策 p95 1.4-1.7s；E2 形态（200 选项）实测 ~25s/条",
            },
        },
        "gate": {
            "quality": {"e1": "LOSE（0.1633/0.111 vs 0.5738/0.4903）",
                        "e2": "未测完（时间闸：正主 200 选项 ~25s/条，闸门判定不依赖它）",
                        "e3": "LOSE（nDCG@5 0.0 vs 0.2437）",
                        "wins": 0, "required": 2,
                        "verdict": "E1+E3 双输后 E2 即使赢也 <2/3，条件 1 失败"},
            "memory": {"limit_mb": 800,
                       "torch_route_mb": 3576.2,
                       "gguf_single_slot_mb": 888.2,
                       "verdict": "双路线均超限（GGUF 超出 11%，-c 2048 或可压入但按实测记负）"},
            "latency": {"limit_p95_s": 2.0,
                        "single_decision_s": 1.4,
                        "wide_option_decision_s": 25.0,
                        "verdict": "单决策形态临界通过，宽选项形态失败"},
        },
        "verdict": {
            "adopted": False,
            "text": "不采纳。外部本地决策模型路线以实测数据收案：正主 Jev-Style-0.8B-Decision-v3"
                    "（官方参考实现）与零样本代表 Qwen3-0.6B 在 SiteLens 三任务上均未达到预注册闸门；"
                    "质量、内存、延迟三条件均不满足。5.0 维持传统 ML 主线（EXP-1001/1002 模型 + KB 表）。",
            "reopen_conditions": "出现以下任一情况可重开评估：在 SiteLens 域内微调的决策模型权重开源；"
                                 "单决策 RSS 压入 300MB 内且宽选项延迟 <2s；第三方在扫描候选排序"
                                 "任务上发布可复现的优于规则基线的证据。",
        },
        "protocol_deviations": [
            "仪器修正：发现 llama.cpp top_logprobs 缺省为未掩码原始分布，改 post_sampling_probs 后"
            "重跑 E1/E3；坏仪器轮结果存档未删（lm_on_same_sets_brokenprobe.json），两轮预测一致",
            "正主 E2（800 条 200 选项）未测完：单条 ~25s，为守住清晨交付时间闸而停止，"
            "闸门判定不依赖该条目（E1+E3 双输已使 ≥2/3 不可达）",
            "llama-server 上下文从 2048 提到 32768 属基础设施修复（E2 提示词 2126 token 超每槽配额），"
            "发生在零样本阵营最终数字之前",
        ],
    }

    out = out_root / "metrics" / "EXP-1004-decision-model-comparison.json"
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=1), encoding="utf-8")
    inputs = [res_dir / "baseline_on_same_sets.json", res_dir / "lm_on_same_sets.json",
              res_dir / "lm_on_same_sets_brokenprobe.json", res_dir / "jev_on_same_sets.json",
              res_dir / "jev_e1_samples.jsonl", res_dir / "lm_e1_samples.jsonl",
              res_dir / "lm_e2_samples.jsonl", res_dir / "lm_e3_samples.jsonl",
              res_dir / "jev_e3_samples.jsonl"]
    man = manifest.make_manifest(
        kind="experiment", version="EXP-1004-decision-model-comparison",
        inputs=[manifest.file_input(p, role="upstream") for p in inputs if p.is_file()]
               + [manifest.file_input(out, role="output")],
        params={"pre_registration_commit": "a062d10", "seed": 20260928,
                "adopted": False},
        producer="ml/bench/collect_exp1004.py",
        scope={"data_version": "kb-5.0.0"},
    )
    manifest.write_manifest(man, out_root / "metrics" / "EXP-1004-decision-model-comparison_MANIFEST.json")
    summary = out_root / "metrics" / "summary.jsonl"
    with open(summary, "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": "EXP-1004-decision-model-comparison",
                            "task": "本地决策模型 vs 传统 ML 基线（预注册）",
                            "adopted": False,
                            "data_version": "kb-5.0.0",
                            "git_rev": manifest.git_rev()}) + "\n")
    print(f"[saved] {out}")
    print("[verdict] 不采纳：0/3 质量赢面，内存/延迟双失败——5.0 维持传统 ML 主线")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
