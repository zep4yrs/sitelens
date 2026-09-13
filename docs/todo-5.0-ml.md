# SiteLens 5.0 ML Pretraining TODO

> 分支：`ml-5.0-docs`。计划全文：docs/开发文档-5.0-ML预训练.md；
> 审计全文：docs/审计报告-5.0-ML预训练.md；本轮运行结果：
> docs/5.0-ML-运行报告.md（数据/指标全部来自真实执行）。
> 状态标记：`[x]` 完成 / `[~]` 进行中 / `[ ]` 待做；（等待 4.0）= 依赖 4.0 数据。
>
> **v2 修订要点（2026-09-14）**：T1 标签三分（executed/verified 区分，
> unknown 不作负样本）、历史特征严格时间截断、T2 收窄为 candidate-finding
> ranking、L3 降格 sanity、host/target split 等价性、replay 降为可选增强、
> score/probability/confidence 分离、P5 数据 gate（数据不支持的任务延期，
> 不造数据）。核心线 P1→P10 不得跳步。
>
> **2026-09-14 执行记录**：P1-P10 核心线 + P11/P12 已在 ml-5.0-docs 分支
> 实现、测试（24 单测）并真实运行（119 扫描/10 host）；T1/T2 训练按 gate
> BLOCKED（无执行日志，可靠负样本=0）；完整流水线两次运行 149 字段零差异，
> 删 data/ml/ 从零重建通过（EXP-0001..0004）。

## Phase 0：代码与数据审计

[x] 01. 通读全部非 vendor Go 源码（cmd + 31 个 internal 包，25,476 行）
[x] 02. 从真实程序入口追踪调用链与数据流（scan/serve/audit/migrate-pg/regression 六入口）
[x] 03. 3.0 数据逐项审计：产生位置/结构/函数/存储/ML 可用性（审计报告 §6）
[x] 04. 4.0 状态判定：已实现/开发中/仅设计/不存在（审计报告 §5）
[x] 05. 历史数据规模统计（119 扫描/10 host/456 verified/1135 情报行等实测）
[x] 06. 数据质量与泄漏风险分析（重复/稀疏/不平衡/格式脏/组泄漏）
[x] 07. 输出《SiteLens 5.0 ML 预训练代码审计报告》（docs/审计报告-5.0-ML预训练.md）
[x] 08. 输出 Task Plan 与本 TODO（docs/开发文档-5.0-ML预训练.md、docs/todo-5.0-ml.md）
[x] 09. 分支与提交管理（feature 分支两建两删，最终落位 ml-5.0-docs；main 未动）
[x] 10. v2 设计修正：T1 三分标签/时间泄漏硬规则/T2 收窄/L3 降格/split 等价/replay 可选/输出接口分离/执行顺序固定（三文档同步修订）

## P1 数据基础设施（Phase 1）

[x] 11. data/ml/ 目录骨架 + .gitignore（data/ 运行产物整体忽略）
[x] 12. ml/ Python 包骨架：paths/config/manifest（含 sha256 输入指纹与版本字段）
[x] 13. manifest 读写往返单测（生成→加载→校验失败路径）

## P2 Dataset（Phase 2）

[x] 14. readers.py：history.json / history.archive.jsonl / premigrate / 靶场矩阵 ScanRecord 四源读取器
[x] 15. normalize.py：severity 归一（Important→medium 等）、era 标记（py/go）、verdict 空串→missing
[x] 16. dataset.py：D1 站点扫描表（含 prediction_time=scanned_at）+ DATASET_MANIFEST
[x] 17. dataset.py：D2 技术表（evidence 通道类型解析）
[x] 18. dataset.py：D3 情报表（含 NVD pub 联接；T2 candidate finding 来源）
[x] 19. dataset.py：D4 验证表（证据链存在性五键判定；T2 verification target 来源）
[x] 20. T1 observation/execution 状态建模：D4 增加 execution_status（executed/unknown）与 execution_basis；候选层一律 unknown（开发文档 §2）
[x] 21. dataset.py：D5 静态字典联接表（NVD/KEV/tpl_intel/nuclei_index/technologies，sha256 版本化）
[x] 22. dataset 行数与审计报告 §7 数字一致性断言测试 + execution_status 分布统计（456/1135/119 全对齐）

## P3 Feature（Phase 3）

[x] 23. features.py：资产/网络组（P0）
[x] 24. features.py：技术栈组（one-hot + 类别聚合 + confidence/版本覆盖统计）
[x] 25. dict_join.py：CVE 级特征（CVSS 8 维向量分解/KEV/ransomware/pub_days/模板可用数）
[x] 26. features.py：验证面组（check/template 元数据 + 历史命中先验）
[x] 27. 历史特征严格时间截断：as-of 聚合器（searchsorted side=left），先验只聚合 scanned_at < prediction_time
[x] 28. features.py：证据强度/时延组（signals 计数、resp_size、timing 数值抽取）
[x] 29. 特征黑名单断言（impact/exploit/重放结果/未来记录不得出现在特征表）

## P4 Label（Phase 4）

[x] 30. labels.py：L1 verified-hit 三分语义生成（positive=456 断言；negative=0 如实报告）
[x] 31. T1 unknown 样本隔离：候选层 unknown=1557 独立成层，不进训练与指标分母
[x] 32. labels.py：L3 confirmed-verdict 生成（定位=sanity/pipeline validation，POLE 声明非核心能力）
[x] 33. labels.py：L4/L5 接口占位（L4=可选 replay 增强；L5=0 样本显式 disabled）
[x] 34. 每标签 POLE（口径与可靠性说明）生成（含负样本纪律声明）

## P5 Leakage / Data Quality（Phase 5，数据 gate）

[x] 35. leakage.py：host 隔离断言 + time 切分工具（host 组为原子）
[x] 36. host/target split 等价性检查：实测 127.0.0.1 有 7 个目标 URL，但同 host 多目标按 URL 切分会引入 host 级交叉 → 只保留 host split（更严口径），结论写入泄漏报告
[x] 37. leakage.py：重复组统计、先验特征注入回归断言（未来记录注入→先验逐值不变）、首扫上界断言（prior=0）、farm/真实目标域标记
[x] 38. quality.py：不平衡/稀疏/截断偏差/execution unknown 占比定量报告（data/ml/metrics/data_quality_report.json）
[ ] 39. replay 作为可选数据增强：本轮未执行（重放需对真实目标发请求；管线已把 replay 定义为可选、基础流程零依赖——真实执行留待授权窗口）
[ ] 40. （可选，靶场）重跑 matrix_par.sh 生成 L2 模板验证标签（速率=硬件上限 2/3 惯例）——本轮未执行
[x] 41. P5 后重新评估 T1/T2 数据可训练性：gate_report 落盘（T1/T2 训练 BLOCKED：可靠负样本=0；T2 基线排序评估 ALLOWED：候选 1582/观测正例 19）

## P6 Baseline（Phase 6）

[x] 42. baselines.py：Severity 序基线（对齐 intel.go severityOrder 语义）
[x] 43. baselines.py：CVSS 降序 / KEV 优先 / 现行 rule-based（nuclei.Select 启发式近似）基线定义；CVSS/KEV 因 intel 候选无可观测结局标记"不评指标"
[x] 44. T2 基线对比口径定义：同粒度（scan × candidate finding）、同指标（P@K/R@K/nDCG@K，仅观测正例）
[x] 45. 基线指标真实运行入库（19 查询/19 正例；prior_hits R@5=0.474 最优，severity 系 P@5=0——真实反直觉发现）

## P7 ML Training（Phase 7）

[x] 46. T2 candidate-finding ranking 定义落地：候选=内置 check（1582），输出 score+Top-K，粒度 scan×candidate；nuclei/CVE 候选不可复原已如实排除
[x] 47. models：LR / RF / GBDT 三族（scikit-learn）
[x] 48. train.py：gate 放行任务训练（S1=L3 sanity 分类 966 行/12 正例；S2=安全评分回归 111 行；T1/T2 训练按 gate BLOCKED 并记录原因）
[x] 49. 模型 vs 基线对照报告：S2 的 LOHO MAE 40-42 劣于 median 基线 10（host 泛化差，如实报告不硬超）；time split MAE 0.04-0.28（同 host 时序可预测）

## P8 Evaluation（Phase 8）

[x] 50. evaluate：分类 ROC-AUC/PR-AUC（S1 OOF 正例=0 → AUC 不可算，如实标注 auc_note）；排序 P@K/R@K/nDCG@K（T2，仅观测正例）
[x] 51. evaluate：time split + host split 双口径（target split 按 36 结论不单独统计）
[x] 52. 泄漏检查前置门（黑名单/注入回归/host 隔离任一失败即不评估）

## P9 Explainability / Calibration（Phase 9）

[x] 53. score/probability/confidence 分离：统一契约输出（score 必给/probability 校准判定 unreliable → null/confidence 第一阶段 null）；判定规则=AUC≥0.55 前置 + n≥50 + 分箱偏差≤0.15
[x] 54. explain：top_features（线性=coef×standardized value；树=importance 近似）+ prediction_reason 中文短句
[x] 55. calibrate：LR OOF Brier=0.0003 但 AUC 不可算 → 判 unreliable（退化校准无意义），probability 保持 null

## P10 Model Versioning（Phase 10）

[x] 56. registry.py：按实验目录加载模型 + 上游（dataset manifest 哈希/git rev/参数）反查；verify_experiment 重算哈希
[x] 57. experiments 索引 summary.jsonl（append-only）

## 辅助线（不阻塞核心线）

[x] 58. Phase 11：ml/interfaces/v40.py 九类 4.0 投影 schema（显式 missing 语义）+ waiting_list()《等待 4.0 数据清单》7 项
[x] 59. Phase 12：predict.py 离线预测（对 ScanRecord JSON 产出 score+Top-K+解释，零网络请求；schema 对齐=按训练期特征列重索引）
[x] 60. Phase 13：端到端复现演练（删 data/ml/ 从零重建通过，两次运行 149 字段零差异）+ 运行报告 docs/5.0-ML-运行报告.md（含 gate 延期任务及原因）

## 暂缓 / 等待 4.0 / 不做（不在当前执行序列）

- （gate BLOCKED，等待执行日志）T1 训练：历史无执行日志、可靠负样本=0；启用前提=未来扫描具备 executed∧未命中 实证记录
- （等待 4.0）攻击链 Node/Edge/Path/Chain 特征、链预测任务（T6）
- （等待 4.0）CWE 关系特征、入口点特征、权限变化标签、黑白盒证据关联特征
- （暂缓）L5 exploit-proven 标签启用与 T4 可利用性预测——当前 0 样本
- （暂缓）T5 验证策略推荐——等 T1/T2 立住且有序列数据
- （可选未执行）39/40：replay 实验与靶场 L2 标签生成——需授权窗口发真实请求
- （不做）LLM/RAG/Chat/Agent 类一切内容；深度学习起步；Severity 作 Label；
  无 execution 证据造 negative；为指标造 synthetic 数据；ML 接入生产扫描；
  修改 3.0/4.0 行为代码；伪造任何指标；提前实现 4.0 攻击链字段
