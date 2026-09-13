# SiteLens 5.0 ML Pretraining TODO

> 分支：`feature/ml-5.0-pretraining`。计划全文：docs/开发文档-5.0-ML预训练.md；
> 审计全文：docs/审计报告-5.0-ML预训练.md。
> 状态标记：`[x]` 完成 / `[~]` 进行中 / `[ ]` 待做；（等待 4.0）= 依赖 4.0 数据，
> 当前不开工。执行前等待人工确认本 TODO。

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

## Phase 1：ML 数据基础设施

[ ] 10. data/ml/ 目录骨架 + .gitignore 增补一行（data/ml/ 整体忽略）
[ ] 11. ml/ Python 包骨架：paths/config/manifest（含 sha256 输入指纹与版本字段）
[ ] 12. manifest 读写往返单测（生成→加载→校验失败路径）

## Phase 2：Dataset Pipeline

[ ] 13. readers.py：history.json / history.archive.jsonl / premigrate / 靶场矩阵 ScanRecord 四源读取器
[ ] 14. normalize.py：severity 归一（important/Important→medium 等映射表落地）、era 标记（py/go）、verdict 空串→missing
[ ] 15. dataset.py：D1 站点扫描表 + DATASET_MANIFEST
[ ] 16. dataset.py：D2 技术表（evidence 通道类型解析）
[ ] 17. dataset.py：D3 情报表（含 NVD pub 联接）
[ ] 18. dataset.py：D4 验证表（证据链存在性五键判定）
[ ] 19. dataset.py：D5 静态字典联接表（NVD/KEV/tpl_intel/nuclei_index/technologies，sha256 版本化）
[ ] 20. dataset 行数与审计报告 §7 数字一致性断言测试

## Phase 3：Feature Pipeline

[ ] 21. features.py：资产/网络组（P0）
[ ] 22. features.py：技术栈组（one-hot + 类别聚合 + confidence/版本覆盖统计）
[ ] 23. dict_join.py：CVE 级特征（CVSS 8 维向量分解/KEV/ransomware/pub_days/模板可用数）
[ ] 24. features.py：验证面组（check/template 元数据 + host-leave-one-out 历史先验）
[ ] 25. features.py：证据强度/时延组（signals 计数、resp_size、timing 数值抽取）
[ ] 26. 特征黑名单断言（impact/exploit/重放结果不得出现在特征表）

## Phase 4：Label Pipeline

[ ] 27. labels.py：L1 verified-hit 生成（正样本数=456 断言）
[ ] 28. labels.py：L3 confirmed-verdict 生成（附"近确定性规则"口径说明）
[ ] 29. labels.py：L4/L5 接口占位（L4 待 Phase 5 数据、L5 显式 disabled 说明）
[ ] 30. 每标签 POLE（口径与可靠性说明）文件生成

## Phase 5：数据质量与防泄漏

[ ] 31. leakage.py：host 隔离断言 + time/target 切分工具（host 组为原子）
[ ] 32. leakage.py：重复组（host+check+url）跨 split 检查、farm/真实目标域标记
[ ] 33. quality.py：不平衡/稀疏/截断偏差定量报告（落 data/ml/metrics/）
[ ] 34. 对 158 行带 replay 输入的 verified 行跑重放，结果存 data/ml/labels/（不回写历史库）
[ ] 35. （可选，靶场）重跑 matrix_par.sh 生成 L2 模板验证标签（速率=硬件上限 2/3 惯例）

## Phase 6：Baseline

[ ] 36. baselines.py：Severity 序基线（对齐 intel.go severityOrder 语义）
[ ] 37. baselines.py：CVSS 降序 / KEV 优先 / nuclei.Select 启发式近似 三条基线
[ ] 38. 四基线指标真实运行入库（禁止任何手填数字）

## Phase 7：第一批 ML 模型

[ ] 39. models.py：LR / RF / GBDT 三族（scikit-learn；数据不支持的不加）
[ ] 40. train.py：T1 验证目标优先级排序训练（只拟合 train split）
[ ] 41. train.py：T2 风险排序训练（标签 L1/L2 复合口径）
[ ] 42. 模型 vs 基线对照报告（数据不足时如实标注，不硬超）

## Phase 8：Training Pipeline

[ ] 43. run_experiment.py：一键 dataset→features→labels→split→baseline→train→eval→manifest
[ ] 44. 幂等复现验证：连续两次运行 manifest 除时间戳外一致

## Phase 9：Evaluation Pipeline

[ ] 45. evaluate.py：分类 P/R/F1、ROC-AUC、PR-AUC；排序 P@k、nDCG@k、MRR
[ ] 46. evaluate.py：time/host/target 三口径 split + 校准曲线
[ ] 47. 泄漏检查前置门（不过不开跑）

## Phase 10：Model Explainability

[ ] 48. explain.py：risk_score/confidence/top_features/prediction_reason 输出契约
[ ] 49. 解释单测：线性系数路径 + 树重要性路径各一

## Phase 11：Model Versioning

[ ] 50. registry.py：按版本加载模型 + 上游（dataset/feature/label/参数/git rev）反查
[ ] 51. experiments 索引 summary.jsonl（append-only）

## Phase 12：4.0 → 5.0 数据接口（仅 schema，不实现适配器，不改 4.0）

[ ] 52. ml/interfaces/v40.py：漏洞节点/链节点/链边/入口点/CWE 关系/DataFlow/权限变化/Impact/证据关联 九类投影 schema（显式 missing 语义）
[ ] 53. 《等待 4.0 数据清单》文档（从审计报告 §19 固化为 checklist）

## Phase 13：Offline Prediction

[ ] 54. predict.py：对指定 ScanRecord JSON 离线产出 T1/T2 排序+解释（零网络请求、不接生产）

## Phase 14：5.0 ML Pretraining 完成

[ ] 55. 端到端复现演练（删 data/ml/ 后一键重建成功）
[ ] 56. 完成报告 docs/开发文档-5.0-ML预训练-完成报告.md（含局限与等待 4.0 清单）

## 暂缓 / 等待 4.0（不在当前执行序列）

- （等待 4.0）攻击链 Node/Edge/Path/Chain 特征、链预测任务（T6）
- （等待 4.0）CWE 关系特征、入口点特征、权限变化标签、黑白盒证据关联特征
- （暂缓）L5 exploit-proven 标签启用与 T4 可利用性预测——等 Phase 5 靶场样本积累（当前 0 样本）
- （暂缓）T5 验证策略推荐——等 T1/T2 立住且有序列数据
- （不做）LLM/RAG/Chat/Agent 类一切内容；深度学习起步；Severity 作 Label；
  ML 接入生产扫描；修改 3.0/4.0 行为代码；伪造任何指标
