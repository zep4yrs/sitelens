# SiteLens 5.0 ML 预训练（ml/）

5.0 的机器学习线：从主仓库 10 万级真实安全数据中学习安全知识、漏洞关系与候选排序
规律，全部基于传统 ML（scikit-learn），全部可追溯（Dataset/Feature/Label/Model/
Experiment 五级 Manifest + git 提交链），全部数字来自真实执行。

分支 `ml-5.0-docs`；数据与模型产物一律不进 git（`.gitignore` 的 `data/`）。

## 快速开始

```bash
# venv（Windows）
.venv/Scripts/python.exe -m ml.run_pipeline            # P1-P10 全流程（含 P6 基线/P7 实验登记）
.venv/Scripts/python.exe -m ml.train_kb                # 学习阶段：EXP-1001/1002/1003（KB 六表）
.venv/Scripts/python.exe -m ml.bench.build_eval_sets   # EXP-1004 评测集（预注册，seed 固定）
.venv/Scripts/python.exe -m ml.bench.eval_baselines_same_sets
.venv/Scripts/python.exe -m ml.bench.eval_decision_model --probe   # 需先起 llama-server
.venv/Scripts/python.exe -m ml.bench.eval_jev_style --tasks e1,e2,e3
```

默认数据根：`--data-root`（主仓库 `实训考核2/data`，须含 `state/history.json`），
输出根 `data/ml/`。

## 实验索引

| 实验 | 任务 | 状态 | 结果 |
|---|---|---|---|
| EXP-0001..0004 | S1 sanity（LOHO）/ S2 分数 sanity | 完成 | 见 `data/ml/metrics/`（sanity 定位，L3 不作成绩） |
| EXP-1001 | CVE 严重度分类（NVD 29.1 万有标签，2024 时间切分） | 完成 | SGD acc 0.5738 / macro-F1 0.484 |
| EXP-1002 | CVE→产品关系（top-200，时间切分） | 完成 | P@5 0.9085 / MRR 0.864 |
| EXP-1003 | 模板命中先验（历史 nuclei 命中 lift） | 完成 | info 级模板 lift 12.0× |
| EXP-1004 | 本地小决策模型 vs 传统 ML 基线（预注册对比） | 完成 | 不采纳，见 `docs/5.0-总报告.md` |
| EXP-1005 | CVE→CWE 弱点类型（kb-5.0.1，balanced 权重） | 完成 | acc 0.7709 / macro-F1 0.5899 |
| EXP-1006 | 严重度 v2（过拟合诊断修正，alpha=1e-5，严格三段切分） | 完成 | test acc 0.5221 / F1 0.3941 |
| EXP-1007 | 严重度堆叠冲击 0.75（sev-prior-v3） | 完成 | 0.5058 未达标未晋升，负结果入档 |
| EXP-1101/1102 | T1/T2 首次监督训练（执行日志标签，靶场） | 机制实证 | 正例=1，指标待积累 |

## 模型命名

对外一律用**公开名**（见名知义），EXP 追溯 id 只活在 manifest 链——
全量映射与命名规则见 [`ml/model_registry.json`](model_registry.json)：

| 公开名 | 中文名 | 现役版本 | 质量 |
|---|---|---|---|
| `sev-prior` | 严重度先验 | sev-prior-v2（EXP-1006） | test acc 0.5221，相邻带 0.94 |
| `cve-tech` | 产品关系先验 | EXP-1002 | P@5 0.9085 |
| `cwe-type` | 弱点类型分类 | EXP-1005 | acc 0.7709 |
| `verify-rank` | 验证优先级（T1） | EXP-1101 | 待正例积累 |
| `find-rank` | 候选发现排序（T2） | EXP-1102 | 待正例积累 |

## 目录

```
ml/
  config.py        路径解析与全局常量（标签语义、era、execution_status）
  readers.py       四源读取（history/premigrate/archive/matrix）+ 双层去重
  normalize.py     严重度归一、时间解析、verdict 三值化
  dataset.py       D1-D5 数据表 + DATASET_MANIFEST
  features.py      扫描/情报/候选特征（as-of 先验，searchsorted 严格时间截断）
  labels.py        L1 三值标签（executed∧hit=positive / miss=negative / 未执行=unknown≠negative）
  leakage.py       注入回归泄漏测试、先验上界、host 不相交断言、切分等价
  splits.py        LOHO / 时间切分
  quality.py       质量闸（T1/T2 监督训练 BLOCKED 的证据链；T2 基线排序评估 ALLOWED）
  baselines.py     T2 规则基线（severity/rule/prior_hits/random）+ 排序指标
  train.py         S1/S2 sanity 训练（skipped_folds 如实记录）
  explain.py       score/probability/confidence 三分离；未过校验 probability=null
  registry.py      实验登记与校验（上游链 EXP→KB_MANIFEST）
  predict.py       离线预测（特征对齐训练列）
  recon.py         数据侦察（文件盘点/真实统计/血缘）
  knowledge.py     KB 六表（37.2 万 CVE、5.6 万模板-CVE、模板严重度脏值归一）
  train_kb.py      学习阶段三实验 + 模型持久化
  interfaces/v40.py 4.0 数据挂接接口（9 投影 schema，MISSING 哨兵）
  bench/           EXP-1004：预注册对比实验（评测集/基线同集重算/零样本读出/Jev-Style 原生接口）
tests/             32 项 pytest（P1/P2/P345/P7）
```

## 纪律（红线）

- unknown/未命中/未扫描/缺失 ≠ negative；negative 只来自 executed∧miss。
- feature_time < prediction_time：一切历史先验严格时间截断（代码级断言）。
- 预注册：对比实验的协议与采纳闸门先于任何被测系统推理提交 git
  （`bench/PRE_REGISTRATION.md`，commit a062d10）。
- 基线与被测系统共用同一指标实现（`bench/metrics_shared.py`、`metrics.eval_ranking`）。
- 不为指标改数据；跑不了的任务如实记录原因（见 quality gate）。
