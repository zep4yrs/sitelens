# SiteLens 5.0 ML Pretraining TODO

> 分支：`feature/ml-5.0-pretraining`（v2 修订）。计划全文：
> docs/开发文档-5.0-ML预训练.md；审计全文：docs/审计报告-5.0-ML预训练.md。
> 状态标记：`[x]` 完成 / `[~]` 进行中 / `[ ]` 待做；（等待 4.0）= 依赖 4.0 数据，
> 当前不开工。执行前等待人工确认。
>
> **v2 修订要点（2026-09-14）**：T1 标签三分（executed/verified 区分，
> unknown 不作负样本）、历史特征严格时间截断、T2 收窄为 candidate-finding
> ranking、L3 降格 sanity、host/target split 等价性、replay 降为可选增强、
> score/probability/confidence 分离、P5 数据 gate（数据不支持的任务延期，
> 不造数据）。核心线 P1→P10 不得跳步。

## Phase 0：代码与数据审计

[x] 01. 通读全部非 vendor Go 源码（cmd + 31 个 internal 包，25,476 行）
[x] 02. 从真实程序入口追踪调用链与数据流（scan/serve/audit/migrate-pg/regression 六入口）
[x] 03. 3.0 数据逐项审计：产生位置/结构/函数/存储/ML 可用性（审计报告 §6）
[x] 04. 4.0 状态判定：已实现/开发中/仅设计/不存在（审计报告 §5）
[x] 05. 历史数据规模统计（119 扫描/10 host/456 verified/1135 情报行等实测）
[x] 06. 数据质量与泄漏风险分析（重复/稀疏/不平衡/格式脏/组泄漏）
[x] 07. 输出《SiteLens 5.0 ML 预训练代码审计报告》（docs/审计报告-5.0-ML预训练.md）
[x] 08. 输出 Task Plan 与本 TODO（docs/开发文档-5.0-ML预训练.md、docs/todo-5.0-ml.md）
[x] 09. 建立 feature/ml-5.0-pretraining 分支并提交文档（不碰 main）
[x] 10. v2 设计修正：T1 三分标签/时间泄漏硬规则/T2 收窄/L3 降格/split 等价/replay 可选/输出接口分离/执行顺序固定（三文档同步修订）

## P1 数据基础设施（Phase 1）

[ ] 11. data/ml/ 目录骨架 + .gitignore 增补一行（data/ml/ 整体忽略）
[ ] 12. ml/ Python 包骨架：paths/config/manifest（含 sha256 输入指纹与版本字段）
[ ] 13. manifest 读写往返单测（生成→加载→校验失败路径）

## P2 Dataset（Phase 2）

[ ] 14. readers.py：history.json / history.archive.jsonl / premigrate / 靶场矩阵 ScanRecord 四源读取器
[ ] 15. normalize.py：severity 归一（important/Important→medium 等映射表落地）、era 标记（py/go）、verdict 空串→missing
[ ] 16. dataset.py：D1 站点扫描表（含 prediction_time=scanned_at）+ DATASET_MANIFEST
[ ] 17. dataset.py：D2 技术表（evidence 通道类型解析）
[ ] 18. dataset.py：D3 情报表（含 NVD pub 联接；T2 candidate finding 来源）
[ ] 19. dataset.py：D4 验证表（证据链存在性五键判定；T2 verification target 来源）
[ ] 20. T1 observation/execution 状态建模：D4 增加 execution_status（executed/not_executed/unknown）与 execution_basis 字段，推断规则=内置 check 档位推断、Nuclei/DAST 执行集不可复原一律 unknown（开发文档 §2）
[ ] 21. dataset.py：D5 静态字典联接表（NVD/KEV/tpl_intel/nuclei_index/technologies，sha256 版本化）
[ ] 22. dataset 行数与审计报告 §7 数字一致性断言测试 + execution_status 分布统计

## P3 Feature（Phase 3）

[ ] 23. features.py：资产/网络组（P0）
[ ] 24. features.py：技术栈组（one-hot + 类别聚合 + confidence/版本覆盖统计）
[ ] 25. dict_join.py：CVE 级特征（CVSS 8 维向量分解/KEV/ransomware/pub_days/模板可用数）
[ ] 26. features.py：验证面组（check/template 元数据 + 历史命中先验）
[ ] 27. 历史特征严格时间截断：as-of 聚合器，先验特征（host 历史 verified/漏洞次数、CVE/check/template 历史命中、历史验证成功率、历史扫描结果）只聚合 scanned_at < prediction_time 的记录（开发文档 §3 硬规则）
[ ] 28. features.py：证据强度/时延组（signals 计数、resp_size、timing 数值抽取）
[ ] 29. 特征黑名单断言（impact/exploit/重放结果/当前样本自身与其后记录不得出现在特征表）

## P4 Label（Phase 4）

[ ] 30. labels.py：L1 verified-hit 三分语义生成——executed+hit=positive（456 行断言）；executed+未中=negative（当前无 execution 日志，如实报告 0）；未执行=unknown
[ ] 31. T1 unknown 样本隔离：unknown 独立成表，不进训练集与指标分母，规模单列统计报告
[ ] 32. labels.py：L3 confirmed-verdict 生成（定位=sanity/pipeline validation，POLE 中声明非核心能力、不投入主要资源）
[ ] 33. labels.py：L4/L5 接口占位（L4=可选 replay 增强；L5=0 样本显式 disabled）
[ ] 34. 每标签 POLE（口径与可靠性说明）文件生成（含负样本纪律声明）

## P5 Leakage / Data Quality（Phase 5，数据 gate）

[ ] 35. leakage.py：host 隔离断言 + time 切分工具（host 组为原子）
[ ] 36. host/target split 等价性检查：统计 target 与 host 对应关系；当前 target≡host 则只保留 host split 并在评估报告说明原因，不伪造两个独立实验（开发文档 Phase 5/8）
[ ] 37. leakage.py：重复组（host+check+url）跨 split 检查、先验特征时间截断抽样复核断言、farm/真实目标域标记
[ ] 38. quality.py：不平衡/稀疏/截断偏差/execution unknown 占比定量报告（落 data/ml/metrics/）
[ ] 39. replay 作为可选数据增强：重放实验（158 行带 replay 输入）结果存 data/ml/labels/，不回写历史库、不阻塞基础管线；无 replay 数据时基础训练流程照常运行
[ ] 40. （可选，靶场）重跑 matrix_par.sh 生成 L2 模板验证标签（速率=硬件上限 2/3 惯例）
[ ] 41. P5 后重新评估 T1/T2 数据可训练性：产出《真实数据统计报告》（execution_status 分布、正/负/unknown 计数、split 可分性、任务可训练性结论）；数据不支持的任务正式延期并记录原因，不人为构造数据

## P6 Baseline（Phase 6）

[ ] 42. baselines.py：Severity 序基线（对齐 intel.go severityOrder 语义）
[ ] 43. baselines.py：CVSS 降序 / KEV 优先 / 现行 rule-based priority（nuclei.Select 启发式近似）基线
[ ] 44. T2 基线对比口径定义：与 T2 同粒度（scan × candidate finding）、同指标、同 split
[ ] 45. 基线指标真实运行入库（禁止任何手填数字）

## P7 ML Training（Phase 7）

[ ] 46. T2 candidate-finding ranking 定义落地：输入=单次扫描的 D3 候选发现+D4 验证目标，输出=ranking score + Top-K，训练粒度=scan × candidate finding（备选 host × verification target），不以 scan/host 整体为粒度
[ ] 47. models.py：LR / RF / GBDT 三族（scikit-learn；数据不支持的不加）
[ ] 48. train.py：gate 放行任务训练（T2 按 46；T1 仅当 41 的 gate 放行）
[ ] 49. 模型 vs 基线对照报告（同粒度同口径；数据不足时如实标注并延期，不硬超）

## P8 Evaluation（Phase 8）

[ ] 50. evaluate.py：分类 P/R/F1、ROC-AUC、PR-AUC；排序 P@K、nDCG@K、MRR（T2 指标只定义在观测正例上，unobserved 不作负例）
[ ] 51. evaluate.py：time split + host split（target split 仅当 36 确认可分才单独统计）+ 校准曲线
[ ] 52. 泄漏检查前置门（不过不开跑）

## P9 Explainability / Calibration（Phase 9）

[ ] 53. score/probability/confidence 分离：统一输出契约 score（必给）/ probability（仅校准验证可靠后填，否则 null）/ confidence（第一阶段一律 null）/ top_features / prediction_reason；未经 calibration 的输出不得称"置信度"
[ ] 54. explain.py：top_features（≤5 特征贡献）与 prediction_reason（中文短句，无 emoji）；线性/树两条解释路径
[ ] 55. calibrate.py：校准曲线/校准误差验证，决定 probability 是否转正

## P10 Model Versioning（Phase 10）

[ ] 56. registry.py：按版本加载模型 + 上游（dataset/feature/label/参数/git rev）反查
[ ] 57. experiments 索引 summary.jsonl（append-only）

## 辅助线（不阻塞核心线）

[ ] 58. Phase 11：ml/interfaces/v40.py 九类 4.0 投影 schema（漏洞节点/链节点/链边/入口点/CWE 关系/DataFlow/权限变化/Impact/证据关联；显式 missing；不提前实现不存在的字段）+《等待 4.0 数据清单》
[ ] 59. Phase 12：predict.py 离线预测（对 ScanRecord JSON 产出 ranking+解释，零网络请求、不接生产）
[ ] 60. Phase 13：端到端复现演练（删 data/ml/ 后一键重建成功）+ 完成报告 docs/开发文档-5.0-ML预训练-完成报告.md（含 gate 延期任务及原因）

## 暂缓 / 等待 4.0 / 不做（不在当前执行序列）

- （等 P5 gate）T1 训练：历史无执行日志、可靠负样本=0，gate 不放行即延期
- （等待 4.0）攻击链 Node/Edge/Path/Chain 特征、链预测任务（T6）
- （等待 4.0）CWE 关系特征、入口点特征、权限变化标签、黑白盒证据关联特征
- （暂缓）L5 exploit-proven 标签启用与 T4 可利用性预测——当前 0 样本
- （暂缓）T5 验证策略推荐——等 T1/T2 立住且有序列数据
- （不做）LLM/RAG/Chat/Agent 类一切内容；深度学习起步；Severity 作 Label；
  无 execution 证据造 negative；为指标造 synthetic 数据；ML 接入生产扫描；
  修改 3.0/4.0 行为代码；伪造任何指标；提前实现 4.0 攻击链字段
