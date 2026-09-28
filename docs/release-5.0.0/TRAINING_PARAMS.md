# SiteLens 5.0 现役模型训练参数（ml-models-v1）

本文档记录 SiteLens 5.0 三个现役机器学习模型（cve-tech、cwe-type、sev-prior）的完整训练参数，随模型权重一并开源，供使用者复现与审计。

**参数随模型开源**：本文所列每一个超参数、数据口径与评估协议均直接摘自训练代码与实验指标文件，不使用回忆或推测值；每个参数注明其在仓库中的出处（相对 `sitelens-ml5` 仓库根的文件路径）。训练代码全流程开放于仓库 `ml/` 目录，权重文件与本文档同属发布 `ml-models-v1`（CNB Release，`feng-qiao/sitelens`，发布于 2026-09-28T17:04:14Z，见 `data/ml/rel_check.json`）。凡代码中不存在或未记录的参数，本文不写；凡多处记录不一致的参数，在文末"一致性核对记录"中如实列出，不做调和。

配套机器可读版本：[`training-params.json`](training-params.json)。

---

## 0. 共同口径

### 0.1 训练语料

- 语料为本地 NVD 漏洞镜像等真实数据：NVD 371,755 条 CVE（0 重复，发布年份 1988-2026）、CPE 产品约束 3,038,966 条、CWE 关联边 349,291 条；无合成数据、无 LLM 生成内容。
  出处：`ml/knowledge.py`（文件头数据血缘注释）；CWE 边数出自 `data/ml/dist/MODEL_CARD.md`。
- KB 表分版本构建：cve-tech 用 `kb-5.0.0`（`ml/train_kb.py` 第 31 行 `DATA_VERSION`），cwe-type 用 `kb-5.0.1`（`ml/train_cwe.py` 第 27 行），sev-prior 系列用 `kb-5.0.2`（`ml/train_sev_score.py`/`train_sev_big.py`/`train_sev_mae.py` 的 `DATA_VERSION`）。版本间差异为字段增补（v2 镜像解锁 `cwes` 与 `score` 字段），语料同源。
- 每条训练样本携带 `source/source_type/label_type/label_confidence/sample_id/data_version` 溯源字段（`ml/train_kb.py` 第 10-11 行 docstring）。

### 0.2 时间切分纪律

- 全部模型按 CVE 发布时间切分，训练集不含测试期数据：`train pub < 2024-01-01 / test >= 2024-01-01`（cve-tech、cwe-type、sev-prior 部署版）；sev 线的选型实验另用严格三段切分 `train < 2022 / val 2022-2023 / test >= 2024（只碰一次）`。
- 出处：`ml/train_kb.py` 第 67-69 行 `_year_split`、`ml/train_cwe.py` 第 32-34 行、`ml/train_sev_mae.py` 第 100-104 行、`ml/train_sev_big.py` 第 93-96 行。

### 0.3 预注册评测集（E1/E2/E3）

- 评测集构建：`ml/bench/build_eval_sets.py`，抽样 seed=20260928（第 25 行），切分截点 2024-01-01（第 26 行），数据版本 kb-5.0.0。
  - E1 严重度分类：`kb_cve` 中 `pub>=2024` 按类分层等比例抽样 N=1500（第 27 行 `E1_N`）。
  - E2 产品关系：top-200 vendor_product 宇宙内 `pub>=2024` 按 CVE 分组抽样 N=800（第 28 行 `E2_N`），产品列表按字母序呈现（防频次序泄露先验捷径）。
  - E3 候选排序：d4b_candidates 全量 1582 行 + verified `src=check` 观测正例，仅在 19 个有正例的查询上计分（诚实分母）。
- 预注册协议与采纳闸门先于任何被测系统推理提交 git：`ml/bench/PRE_REGISTRATION.md`（commit a062d10）。闸门为外部决策模型挑战者设定：三个任务至少 2 个严格优于同集重算的最强基线、推理峰值 RSS 不超过 800 MB、批量 p95 单决策时延不超过 2000 ms；平局判给基线。
- 现役模型在同一评测行的基线重算结果：E2 上 cve-tech（EXP-1002 持久化模型）P@5 0.905 / MRR@5 0.8585（`data/ml/bench/results/baseline_on_same_sets.json`，N=800，类宇宙 196）。

### 0.4 复现环境

- Python 依赖基线：`numpy>=2.0, pandas>=2.2, scikit-learn>=1.5, pytest>=8.0`（`ml/requirements.txt`）。
- 深度学习线（sev-prior）另需 `torch`、`transformers`（底座 distilbert-base-uncased 本地权重）与 `onnxruntime`；这些依赖未在 requirements.txt 中固定版本（如实记录，见第 4 节）。
- GPU 训练环境：RTX 5060 Laptop 8GB，bf16 混合精度（`ml/train_sev_bert.py` 第 11 行文件头说明，sev-prior BERT 系列同一环境）。代码在 CUDA 不可用时拒绝运行（`ml/train_sev_mae.py` 第 81-83 行），不做 CPU 假跑。

---

## 1. cve-tech（产品关系先验）

| 项 | 值 |
|---|---|
| 公开名 / 版本 | cve-tech v1 |
| 追溯 id | EXP-1002-product-relation-model（`ml/model_registry.json`） |
| 任务 | CVE 描述 → 受影响产品/技术 Top-K（top-200 高频产品宇宙） |
| 训练脚本 | `ml/train_kb.py` 函数 `exp1002_product_relation`（第 198-276 行） |
| 数据版本 | kb-5.0.0 |
| 随机种子 | 20260914（CLI `--seed` 默认值，`ml/train_kb.py` 第 384 行；传入模型 `random_state`） |

### 1.1 算法与超参数

| 参数 | 值 | 出处 |
|---|---|---|
| 文本特征 | TfidfVectorizer（输入字段 `descr`，CVE 英文描述） | `ml/train_kb.py` 215-216 行 |
| ngram_range | (1, 2)，词级 | 同上 |
| min_df | 3 | 同上 |
| max_features | 120000 | 同上 |
| sublinear_tf | true | 同上 |
| 分类器 | OneVsRestClassifier(SGDClassifier)，n_jobs=8 | `ml/train_kb.py` 221-223 行 |
| loss | log_loss（即概率输出可用） | 同上 |
| alpha（L2 正则） | 1e-5 | 同上 |
| max_iter | 20 | 同上 |
| class_weight | 未设置（默认 None，无类平衡） | 同上 |
| random_state | 20260914 | 同上 |
| 类宇宙 | kb_product_stats 按出现 CVE 数降序 head(200)；实际训练中出现过正样本的类为 196 | `ml/train_kb.py` 204 行；196 见 `data/ml/metrics/EXP-1014-cve-tech-v2.json`（class_universe）与 `ml/export_go_assets.py` 第 6 行注释（系数 196x120k） |
| 训练样本口径 | 类内去重：同 (cve, vendor_product) 只留一条；多产品 CVE 由 OvR 天然处理 | `ml/train_kb.py` 217-218 行 |

### 1.2 训练数据口径

- 来源：KB 表 `kb_cve_product`（NVD CPE 产品约束，vendor/product）、`kb_cve`（描述与发布时间）、`kb_product_stats`（类频次）。标签出处=NVD CPE product constraints，label_type=weak/relation，label_confidence=medium（`data/ml/metrics/EXP-1002-product-relation.json` 的 label_provenance）。
- 切分：train `pub < 2024-01-01` / test `pub >= 2024-01-01`（`ml/train_kb.py` 212-213 行）。
- 规模：训练期边数 1,066,892；测试期 CVE 数 31,130（`data/ml/metrics/EXP-1002-product-relation.json`）。
- 类宇宙为 top-200 高频产品，长尾产品无覆盖；200 类中 35 类与 SiteLens 技术指纹目录直接对应（同上 metrics 文件 `classes_matching_sitelens_techs`）。

### 1.3 评估协议与指标

- 协议：时间切分测试段全量评估，每个 CVE 的真实类集合可为多个；P@K 定义为 top-K 与真实集合有交集的 CVE 占比；MRR 为首个命中类排名倒数的均值；同时报告随机基线 P@5=5/200=0.025（`ml/train_kb.py` 227-266 行）。
- E2 预注册评测行（N=800，seed 20260928）同集重算：P@5 0.905 / MRR@5 0.8585（`data/ml/bench/results/baseline_on_same_sets.json`）。
- 挑战实验 EXP-1014（DistilBERT 多标签，同测试集同截断协议）未晋升，现役卫冕（`data/ml/metrics/EXP-1014-cve-tech-v2.json`）。

| 指标 | 登记值（31,130 测试 CVE） | 复现值（31,141 测试 CVE，EXP-1014 同集重算） |
|---|---|---|
| P@5 | 0.9085 | 0.9083 |
| P@10 | 0.9425 | 未复算 |
| MRR / MRR@5 | 0.864 | 0.8563 |
| 随机 P@5 | 0.025 | 同 |

出处：`data/ml/metrics/EXP-1002-product-relation.json`（登记值）、`data/ml/metrics/EXP-1014-cve-tech-v2.json`（复现值）。发布物（MODEL_CARD/Release Notes）采用复现值 0.9083。两值差异属不同测试行集合的复算，见第 4 节记录 1。

### 1.4 导出形态

- 训练产物：joblib 序列化字典（vectorizer + clf + classes + feature 说明），落 `data/ml/experiments/EXP-1002-product-relation-model/model.joblib`（`ml/train_kb.py` 331-354 行 `_persist_model`），附 `EXPERIMENT_MANIFEST.json`。
- 发布资产：`cve-tech-v1.joblib`，193,406,291 字节，SHA256 `2f8bdf549bec0a77972d23effcc01a8e427345e7ca367528cb28dcd52dce1d58`。经实测与 `EXP-1002-product-relation-model/model.joblib` 哈希完全一致。
- Go 引擎嵌入资产（`ml/export_go_assets.py`）：`cve-tech.vocab.txt`（词表，行号=特征 id，120k 行）、`cve-tech.idf.f32`（120k float32 LE）、`cve-tech.coef.f32`（196x120k float32 LE，行=类）、`cve-tech.meta.json`（类别表/intercept/维度）、`fixtures.json`（500 条描述 + Python 侧预测）。Go 移植须与 Python 侧预测对拍一致（不低于 99.5%，该文件 docstring）。
- 加载方式：`art = joblib.load(...)`，`X = art["vectorizer"].transform(texts)`，`art["clf"].predict_proba(X)` 排序取 Top-K（`data/ml/dist/MODEL_CARD.md`）。

### 1.5 复现指引

```bash
# 在 sitelens-ml5 仓库根，默认数据根为主仓库 data/（须含 state/history.json）
.venv/Scripts/python.exe -m ml.train_kb --seed 20260914
# 产物：data/ml/metrics/EXP-1002-product-relation.json 与
#       data/ml/experiments/EXP-1002-product-relation-model/model.joblib
```

说明：`ml.train_kb` 一次跑 EXP-1001/1002/1003 三个实验；单独复现 cve-tech 时以 metrics 文件中 `task=K2` 条目为准。重建预注册评测行：`python -m ml.bench.build_eval_sets`。

---

## 2. cwe-type（弱点类型分类）

| 项 | 值 |
|---|---|
| 公开名 / 版本 | cwe-type v1 |
| 追溯 id | EXP-1005-cwe-model（`ml/model_registry.json`） |
| 任务 | CVE 描述 → CWE 弱点类型（top-25 主弱点单标签） |
| 训练脚本 | `ml/train_cwe.py`（EXP-1005，函数 `exp1005_cwe_relation`，第 77-135 行） |
| 数据版本 | kb-5.0.1（`ml/train_cwe.py` 第 27 行） |
| 随机种子 | 20260914（模块常量 `SEED`，第 29 行） |

### 2.1 算法与超参数

| 参数 | 值 | 出处 |
|---|---|---|
| 文本特征 | TfidfVectorizer（输入字段 `descr`） | `ml/train_cwe.py` 95-96 行 |
| ngram_range | (1, 2)，词级 | 同上 |
| min_df | 3 | 同上 |
| max_features | 120000 | 同上 |
| sublinear_tf | true | 同上 |
| 分类器 | SGDClassifier（原生多类，非 OvR） | `ml/train_cwe.py` 101-103 行 |
| loss | log_loss | 同上 |
| alpha（L2 正则） | 1e-5 | 同上 |
| max_iter | 30 | 同上 |
| class_weight | balanced（类权重平衡） | 同上 |
| random_state | 20260914 | 同上 |
| 类别数 TOP_N | 25；类宇宙只看训练期频率（value_counts().head(25)），避免用测试期频率选类 | `ml/train_cwe.py` 28 行、88-93 行 |
| 标签定义 | 主弱点 = 每 CVE 首个 cwe（NVD 宣告序，`drop_duplicates("cve", keep="first")`） | `ml/train_cwe.py` 80-82 行 |

### 2.2 训练数据口径

- 来源：KB 表 `kb_cve_cwe`（NVD weaknesses 字段，4.x P5 v2 镜像自带）；label_type=supervised，label_confidence=medium；代码注明"CWE 分配本身有噪声且多值，取主弱点作单标签是保守近似"（`ml/train_cwe.py` 文件头与 metrics label_provenance）。
- 切分：train `pub < 2024-01-01` / test `pub >= 2024-01-01`（与 EXP-1001/1002 同口径，`ml/train_cwe.py` 32-34、88 行）。
- 规模：train 129,860 行 / test 84,507 行；测试期主弱点在 top-25 之外的 57,808 行如实排除不硬凑（`data/ml/metrics/EXP-1005-cwe-relation.json`）。
- 25 类清单（按训练期频率降序）：CWE-79、CWE-119、CWE-89、CWE-20、CWE-200、CWE-787、CWE-125、CWE-22、CWE-352、CWE-264、CWE-416、CWE-94、CWE-287、CWE-78、CWE-399、CWE-310、CWE-476、CWE-190、CWE-120、CWE-284、CWE-434、CWE-862、CWE-400、CWE-269、CWE-77（同上 metrics 文件）。

### 2.3 评估协议与指标

- 协议：时间切分测试段（仅 top-25 宇宙内行）accuracy 与 macro-F1；对照多数类基线（恒预测训练期多数类 CWE-79）。
- 预注册 E1 评测行的严重度基线重算使用的是 EXP-1001 模型（非本文档模型）；cwe-type 无对应 E 评测行，评估以时间切分测试段为准。

| 指标 | 值 |
|---|---|
| accuracy | 0.7709 |
| macro_f1 | 0.5899 |
| 多数类基线 accuracy | 0.2489 |

出处：`data/ml/metrics/EXP-1005-cwe-relation.json`。

### 2.4 导出形态

- 训练产物：joblib 序列化字典（vectorizer + model + classes + feature 说明），落 `data/ml/experiments/EXP-1005-cwe-model/model.joblib`（`ml/train_cwe.py` 53-74 行），附 `EXPERIMENT_MANIFEST.json`。
- 发布资产：`cwe-type-v1.joblib`，28,904,894 字节，SHA256 `7820b34c375dd5b9e7b7ba2e18be02436fc6e561e0fa500dfb31e63f3930abea`。经实测与 `EXP-1005-cwe-model/model.joblib` 哈希完全一致。
- Go 引擎嵌入资产：与 cve-tech 同构（25 类），见 `ml/export_go_assets.py` 第 8 行与 `dump_linear`。

### 2.5 复现指引

```bash
.venv/Scripts/python.exe -m ml.train_cwe
# 产物：data/ml/metrics/EXP-1005-cwe-relation.json 与
#       data/ml/experiments/EXP-1005-cwe-model/model.joblib
```

---

## 3. sev-prior（严重度先验，双版本并存）

sev-prior 采用双版本并存（`ml/model_registry.json` 第 23 行）：v3.1 分数输出版为产品主呈现（显示 CVSS 分数与区间），v2.2 档位集成为辅助档位标注。两版本口径不同，数字不可直接比较（同 MODEL_CARD 口径注记）。

### 3.1 sev-prior v3.1（分数输出版，现役呈现）

| 项 | 值 |
|---|---|
| 版本 / 追溯 id | v3.1，EXP-1017（`ml/model_registry.json`：现役 EXP-1017-sev-prior-v3.1） |
| 任务 | CVE 描述 → CVSS 分数回归（0-10），呈现【分数 ± MAE】 |
| 训练脚本 | `ml/train_sev_mae.py`（EXP-1017，部署变体 `D_max_huber2_tr24_ensemble2`，第 177-188 行） |
| 数据版本 | kb-5.0.2（第 26 行） |
| 随机种子 | 双种子 20260928 与 20260929（`SEED, SEED + 1`，第 28、179 行），两模型分数取平均 |

算法与超参数（部署版 D_max）：

| 参数 | 值 | 出处 |
|---|---|---|
| 底座 | distilbert-base-uncased（66M 参数编码器，通用英文预训练，hf-mirror 本地文件，非安全语料） | `ml/train_sev_bert.py` 171-173 行（同底座说明）；`ml/train_sev_mae.py` 86-88 行（`--base-model` 默认 `data\bench\models\distilbert-base-uncased`） |
| 任务头 | AutoModelForSequenceClassification(num_labels=1) 回归头 | `ml/train_sev_mae.py` 138-139 行 |
| 回归目标 | CVSS score / 10.0（归一化到 0-1）；推理输出 x10 还原 0-10 分数 | `ml/train_sev_mae.py` 131、68 行 |
| 优化器 | AdamW，lr=2e-5，weight_decay=0.01 | `ml/train_sev_mae.py` 140 行 |
| 学习率调度 | OneCycleLR，max_lr=2e-5，pct_start=0.1 | `ml/train_sev_mae.py` 141-143 行 |
| 损失 | HuberLoss(delta=0.1)（0-1 归一化尺度上） | `ml/train_sev_mae.py` 145 行 |
| epochs | 2 | `ml/train_sev_mae.py` 180 行 |
| batch_size | 32（训练）；评估 batch 为 32 同值（`make_loader` 默认 bs=BATCH） | `ml/train_sev_mae.py` 31、126-129 行 |
| max_seq_length | 192（truncation + padding=max_length） | `ml/train_sev_mae.py` 30、111-113 行 |
| 精度 | bf16 autocast（CUDA） | `ml/train_sev_mae.py` 151-152 行 |
| 集成 | 双种子分别训练后分数平均 | `ml/train_sev_mae.py` 177-182 行 |
| 档位切带边界 | EDGES = [4.0, 7.0, 9.0]（分数转 low/medium/high/critical） | `ml/train_sev_mae.py` 32、49-52 行 |
| 训练集 | tr24 = `pub < 2024-01-01` 全量（约 148k 行；同一切分在 EXP-1009 记录为 148,356 行，见第 4 节记录 6） | `ml/train_sev_mae.py` 104 行；规模见 `data/ml/metrics/EXP-1017-sev-prior-mae.json` conclusion |

选型协议（严格三段切分，供对照，选型不使用部署版数字）：train<2022（94,485 行）/ val 2022-2023（53,871 行）/ test>=2024 一次；严格协议下 MSE 变体 a_mse2 test MAE 1.283、Huber 变体 b_huber2 test MAE 1.301（`ml/train_sev_mae.py` 100-103、168-175 行；`data/ml/metrics/EXP-1015-sev-prior-v3.json` 提供三段行数）。

评估协议与指标（`data/ml/metrics/EXP-1017-sev-prior-mae.json`）：

- 测试段 = `pub >= 2024-01-01`（与 v2.1/v2.2 档位口径同一切分；同切分测试行数 143,680，见 EXP-1009/EXP-1015 metrics）。
- 主指标：分数 MAE。部署版 D_max：test MAE 1.07，相邻带容忍 acc 0.9654（较 v3 的 0.9549 提升）。
- 晋升记录：promoted=true，promoted_as="sev-prior v3.1（分数输出版部署升级）"；结论注明生效杠杆为数据量（94k 到 148k）与种子集成，Huber 单独在严格协议下无益。

导出形态：

- `ml/train_sev_mae.py` 本身不持久化权重（metrics conclusion 明示"权重可按记录配置复现，产品接入时持久化"）。
- 发布资产：`sev-prior-v3.1.pt`，535,716,895 字节，SHA256 `9d34cca731789be54e94701afb7283795c903d7021d4a329dd4c41b06f5e0fb1`。经实测与 `data/ml/experiments/EXP-1015-sev-prior-v3/model.pt` 哈希完全一致：该 checkpoint 由 `ml/train_sev_score.py` 第 208-209 行保存，内容为 `{"reg", "edge", "base", "edges"}`，其中 reg 为 EXP-1015 严格协议 v3 主回归器（MSE、train<2022、test MAE 1.283），edge 为边界专精二分类器。此对应关系与 v3.1 名义的 D_max 配置（Huber、148k、双种子）不一致，属发布物与指标口径的事实差异，如实记录（第 4 节记录 3）。
- ONNX 导出（`ml/export_sev_onnx.py`）：从 EXP-1015 checkpoint 取 `reg` 重建模型；导出 `sev-prior-v3.1.onnx`（fp32）与 `sev-prior-v3.1-int8.onnx`。输入 input_ids/attention_mask，动态 batch，seq=192，opset 17（第 33-34、55-71 行）。int8 为动态量化（weight_type=QInt8，per_channel=True），pre_classifier/classifier 分类头节点排除量化保持 fp32（第 96-99 行）。对拍：200 条真实 CVE 描述（测试段 pub>=2024，seed 20260928 固定采样），torch fp32 / ONNX fp32 / ONNX int8 三方对拍，通过闸门为 logits（0-1）尺度 fp32 MAE<0.02 且 int8 MAE<0.05（第 9-11、35-37、200-203 行）。
- 加载方式：`ck = torch.load("sev-prior-v3.1.pt", weights_only=False)`；`AutoTokenizer/from_pretrained(ck["base"])` + `num_labels=1` 加载 `ck["reg"]`；输出 logits x10 即 0-10 CVSS 分数（`data/ml/dist/MODEL_CARD.md` 加载代码）。

### 3.2 sev-prior v2.2（档位集成版，辅助档位标注）

| 项 | 值 |
|---|---|
| 版本 / 追溯 id | v2.2，EXP-1009（registry 前版本列表：EXP-1009-sev-prior-v2.2，档位集成，acc 0.6024） |
| 任务 | CVE 描述 → 严重度四类档位（low/medium/high/critical） |
| 训练脚本 | `ml/train_sev_big.py`（EXP-1009，C_ensemble 变体为胜者，第 149-152 行） |
| 数据版本 | kb-5.0.2（第 31 行） |
| 随机种子 | 20260928（模块常量 `SEED`，第 34 行） |

三路构成与超参数：

| 路径 | 参数 | 出处 |
|---|---|---|
| 特征 | TfidfVectorizer word (1,2)，min_df=3，max_features=120000，sublinear_tf=true（与 v2.1 同配方） | `ml/train_sev_big.py` 101-103 行 |
| base（v2.1 现役参照） | SGDClassifier：loss=log_loss，alpha=1e-5，max_iter=30，class_weight=balanced，random_state=20260928 | `ml/train_sev_big.py` 111-112 行 |
| A（容量升级） | TruncatedSVD(n_components=300) + HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1) | `ml/train_sev_big.py` 119-123 行 |
| B（数据扩充自训练） | 伪标注池 80,496 条无标注描述（descr 长度>30，与测试段无交集 CVE），base 模型最大概率 >= 0.8（PSEUDO_CONF）入训，实际入训 16,917 条 | `ml/train_sev_big.py` 36、97、129-141 行 |
| C（集成，胜者） | base、A、B 三路概率软投票平均（proba_c = (base+A+B)/3） | `ml/train_sev_big.py` 149-152 行 |

训练数据口径：train = `pub < 2024-01-01` 且 sev 四类标注，148,356 行；test = `pub >= 2024-01-01`，143,680 行（`ml/train_sev_big.py` 93-96 行；`data/ml/metrics/EXP-1009-sev-prior-v2.2.json`）。

晋升闸门（先于结果写在代码里）：变体当且仅当 test acc 与 macro-F1 均不低于 base 且至少一项严格提升才晋升；C_ensemble 胜出（`ml/train_sev_big.py` 154-159 行；metrics 的 promoted 字段）。

指标（C_ensemble，`data/ml/metrics/EXP-1009-sev-prior-v2.2.json`）：

| 指标 | 值 |
|---|---|
| accuracy | 0.6024 |
| macro_f1 | 0.5047 |
| adjacent_acc（相邻带容忍） | 0.952 |
| macro_auc | 0.8463 |

导出形态：promoted 触发 joblib 持久化，落 `data/ml/experiments/EXP-1009-sev-prior-v2.2/model.joblib`（304,132,769 字节，含 vec/base/svd/hgb/selftrain/classes，`ml/train_sev_big.py` 180-186 行）。该文件未包含在 ml-models-v1 发布资产中（发布资产仅 4 个，见第 4 节记录 5）；v2.2 在产品中的角色为档位辅助标注，主呈现为 v3.1 分数输出。

### 3.3 复现指引

```bash
# 严格协议三变体 + 部署版 D_max（双种子集成，CUDA 必需）
.venv/Scripts/python.exe -m ml.train_sev_mae
# 指标：data/ml/metrics/EXP-1017-sev-prior-mae.json

# v2.2 三路实测
.venv/Scripts/python.exe -m ml.train_sev_big
# 指标：data/ml/metrics/EXP-1009-sev-prior-v2.2.json

# ONNX fp32 + int8 导出与三方对拍（需先有 EXP-1015 checkpoint）
.venv/Scripts/python.exe -m ml.export_sev_onnx

# 线性模型 Go 资产导出与对拍夹具
.venv/Scripts/python.exe -m ml.export_go_assets
```

底座权重需预先放置于 `data/bench/models/distilbert-base-uncased`（各脚本 `--base-model` 默认值）；训练硬件需 CUDA GPU（代码在无 CUDA 时退出）。

---

## 4. 一致性核对记录（多处记录不一致，如实列出）

1. **cve-tech P@5 存在两个记录值**：登记值 0.9085（MRR 0.864，31,130 测试 CVE，`data/ml/metrics/EXP-1002-product-relation.json`）与复现值 0.9083（MRR@5 0.8563，31,141 测试 CVE，EXP-1014 同集重算，`data/ml/metrics/EXP-1014-cve-tech-v2.json`）。`ml/model_registry.json` 记 0.9085；发布物（`data/ml/dist/MODEL_CARD.md`、`RELEASE_NOTES.md`、rel_check.json）采用 0.9083。差异来自两次评估的测试行集合不同，非数据错误。
2. **cve-tech 类宇宙 200 与 196 并存**：实验登记 n_classes=200（目标宇宙，`ml/train_kb.py` 204 行）；实际模型 `clf.classes_` 为 196 类（训练期出现过正样本的类），见 `data/ml/metrics/EXP-1014-cve-tech-v2.json`（class_universe=196）、`data/ml/bench/results/baseline_on_same_sets.json`（同注记）与 `ml/export_go_assets.py` docstring（系数 196x120k）。
3. **发布的 `sev-prior-v3.1.pt` 实为 EXP-1015 checkpoint**：实测 SHA256 与 `data/ml/experiments/EXP-1015-sev-prior-v3/model.pt` 完全一致（9d34cca7...），内含 reg（严格协议 v3 主回归器，MSE、train<2022、test MAE 1.283）与 edge（边界专精模型）两个 state_dict。而 v3.1 名义指标 MAE 1.07 对应 EXP-1017 的 D_max 配置（Huber、tr24 全量、双种子集成），该配置的权重未被单独持久化（`data/ml/metrics/EXP-1017-sev-prior-mae.json` conclusion 明示"产品接入时持久化"）。使用者按第 3.1 节超参可复现 D_max 权重；随发布 .pt 加载得到的模型对应 EXP-1015 配置（test MAE 1.283，相邻带 0.9549）。ONNX 导出同样基于 EXP-1015 的 reg。
4. **`ml/train_sev_mae.py` docstring 列有 c_huber3 变体，实际未实现**：metrics 如实记录仅运行 a/b/D 三变体（`data/ml/metrics/EXP-1017-sev-prior-mae.json` conclusion）。
5. **v2.2 集成模型未随 ml-models-v1 发布**：发布资产仅 cve-tech-v1.joblib、cwe-type-v1.joblib、sev-prior-v3.1.pt、verify-rank-v0.1.joblib 四个（`data/ml/dist/models/SHA256SUMS.txt`、rel_check.json）。EXP-1009 的 model.joblib 留存在实验目录。
6. **sev 部署版训练行数 148k 为约数**：EXP-1017 conclusion 记"148k"；kb-5.0.2 同切分（pub<2024 且 sev 四类）在 EXP-1009 记录为 148,356 行。EXP-1017 的 tr24 额外要求 score 非空且 descr 非空，精确行数未在 metrics 单独记录，以打印口径 `[data] tr24=...` 为准（脚本第 107 行）。
7. **深度学习依赖未锁版本**：`ml/requirements.txt` 仅含 numpy/pandas/scikit-learn/pytest；torch、transformers、onnxruntime 版本未在仓库内固定，复现时以当前稳定版自行安装（CPU 推理 ONNX 亦需 onnxruntime）。

## 5. 文件与发布索引

| 资产 | 大小（字节） | SHA256 |
|---|---|---|
| cve-tech-v1.joblib | 193,406,291 | 2f8bdf549bec0a77972d23effcc01a8e427345e7ca367528cb28dcd52dce1d58 |
| cwe-type-v1.joblib | 28,904,894 | 7820b34c375dd5b9e7b7ba2e18be02436fc6e561e0fa500dfb31e63f3930abea |
| sev-prior-v3.1.pt | 535,716,895 | 9d34cca731789be54e94701afb7283795c903d7021d4a329dd4c41b06f5e0fb1 |

下载地址形如 `https://cnb.cool/feng-qiao/sitelens/-/releases/download/ml-models-v1/<文件名>`（`data/ml/rel_check.json`）。权重与训练代码遵循仓库整体许可（GPL-3.0，`data/ml/dist/MODEL_CARD.md`）。

本文档生成时只读访问 sitelens-ml5 仓库，未修改其中任何文件。所有数字均可由所引路径下的代码与 metrics 文件复算。
