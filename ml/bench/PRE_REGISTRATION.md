# EXP-1004 预注册：本地小决策模型 vs 传统 ML 基线

> 注册时间：2026-09-28（任何决策模型推理运行之前落盘并提交 git）。
> 实验注册人：ZCode（自主执行，用户睡前的整夜授权窗口）。
> 目的：用真实数据可证伪地回答「0.x B 本地决策模型能否替代 5.0 已训练的传统 ML」。

## 一、背景与假设

- H1（用户假设）：社区出现的 Jev 类本地小决策模型（0.x B、类型化决策+校准概率）可以直接承担 T1/T2 决策，无需自有训练。
- H0（对照）：在 SiteLens 的安全域任务上，从本仓库 10 万级语料训练的传统 ML（TF-IDF+SGD / HistGB）仍优于通用小决策模型零样本决策。
- 判定方式：三个任务、同一评测行、同一指标代码、同机资源实测。

## 二、被测系统

| 系统 | 说明 |
|---|---|
| LM（决策模型代表） | llama.cpp b11222 CPU（24 线程）本地服务；权重首选调研确认真实可下载的开源决策模型复刻（NanoJev/kev 等）；若全部不可得，保底代表 = Qwen3-0.6B-Instruct Q8_0（kev 路线公开声明的底座）零样本 + 预注册决策提示词 + GBNF 语法约束的 digit/choice logprob 读出头 |
| 基线 | EXP-1001-severity-model（TF-IDF 1-2gram + SGD，joblib 持久化）、EXP-1002-product-relation-model（OvR SGD）、P6 四基线（severity/rule_based/prior_hits/random，同 baselines.py 代码） |

基线指标在**同一抽样评测行**上用同一指标代码重算，不以全量历史数字代替。

## 三、评测集（固定，构建脚本 build_eval_sets.py，seed=20260928）

| 任务 | 来源 | 切分 | 抽样 | 指标 |
|---|---|---|---|---|
| E1 严重度分类 | kb_cve.jsonl.gz（kb-5.0.0） | pub>=2024-01-01（与 EXP-1001 同切分） | 按类分层等比例 N=1500 | accuracy、macro_f1（与基线同代码） |
| E2 产品关系 | kb_cve_product 限定 top-200 vendor_product（EXP-1002 同类宇宙） | pub>=2024 | 按 CVE 分组抽样 N=800 | P@5、MRR@5（截断协议：两系统都只在各自给出的 Top-5 内计分） |
| E3 候选排序 | d4b_candidates 全量 1582 行 + verified src=check 观测正例（P6 同协议） | 全量（历史数据，as-of 先验同源） | 不抽样 | P@5/P@10/R@K/nDCG@K，仅在 19 个有正例查询上（诚实分母） |

unknown/未命中/未执行不作为负类；E3 指标只在观测正例上定义——沿用 P6 纪律。

## 四、LM 侧推理协议（冻结，运行期间不得修改提示词）

- llama-server：`-t 24 -np 8 -c 2048`，temperature=0（贪心），prompt cache 开启。
- E1 提示词（冻结）：
  `You are a vulnerability triage assistant. Classify the severity of the CVE below.\n\nCVE description:\n{descr(截断600字符)}\n\nAnswer with exactly one word: critical, high, medium, or low.\nSeverity:`
  语法约束 `root ::= "critical" | "high" | "medium" | "low"`；预测=首 token 概率质量 argmax。
- E2 提示词（冻结）：200 产品按 vendor_product 字母序列表置于提示词前缀（prefix cache 复用），
  之后接 CVE 描述，要求输出最可能受影响的 5 个产品编号（逗号分隔）。语法约束编号格式；
  越界编号该槽位计 miss；产品列表字母序为防位置偏差（频次序会泄露先验捷径）。
- E3 提示词（冻结）：候选特征（check id/severity/level/cms/历史命中数）→ 输出 0-9 单个数字。
  语法约束 `root ::= [0-9]`；排序分 = digit 概率期望 Σp(d)·d；档位说明：9 档制，
  与基线可比性不受影响（指标只依赖序）。
- 并发 8 路；逐调用记录时延；每 2 秒采样 llama-server 进程 RSS 取峰值。

## 五、采纳闸门（先于结果写下；平局判给基线——采纳方举证）

LM 代表（任意一个被测权重）被采纳为 5.0/5.x 可选决策层，当且仅当全部满足：

1. **质量**：三个任务中至少 2 个，LM 指标严格优于同集重算的最强基线
   （E1 accuracy 与 macro_f1 均须更高才算赢；E2 比 P@5、MRR@5 均高；E3 比四个基线中最强者的 nDCG@5 与 P@5 均高）。
2. **内存**：LM 进程推理期峰值 RSS ≤ 800 MB（4.0 之后引擎空闲目标 300MB 的 2.6 倍以内，可按需加载容忍）。
3. **延迟**：批量模式下 p95 单决策时延 ≤ 2000 ms。

任一不满足 → 不采纳，外部决策模型路线在文档收案（记录全部数据），5.0 维持传统 ML 主线。

## 六、诚实纪律

- 不看结果调提示词；提示词冻结于本文件，评测代码随本文件同 commit。
- 基线重算与 LM 评测共用 metrics_shared.py 的同一指标实现。
- 全部数字来自真实执行；LM 幻觉输出（越界编号/解析失败）按 miss 计并如实报告比例。
- 被测权重的选择依据（调研工作流结论）随结果一并落盘；若保底代表上阵，报告明示其类别代表地位。
- 评测行样本留存（lm_*_samples.jsonl），可复核。
