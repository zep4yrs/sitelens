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
[x] 25. CVE 级特征（dataset.build_cve_features 投影 + features 联接：CVSS 8 维向量分解/KEV/ransomware/pub_days/模板可用数）
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

## 学习阶段（2026-09-14 第二轮：主仓库 10 万级知识数据）

[x] 61. 数据侦察：144,954 文件/821MB 全盘点（recon-5.0.0）；实证 NVD 371,755（0 重复，pub 1988-2026，303 万产品约束，**CWE 字段=0**）、模板 117,889（56,066 带 CVE）、tpl_intel 29,554、cve_ms 34,931、yaml id 115,635 唯一
[x] 62. 知识层 kb-5.0.0：kb_cve/kb_cve_product/kb_product_stats/kb_template/kb_template_cve/kb_tpl_intel 六表 + 模板 sev 脏值逐条归一（仅 85 条显式 missing）+ manifest
[x] 63. EXP-1001 CVE 严重度学习：148k 训练/143k 测试（时间切分），LR+TF-IDF acc 0.574/F1 0.484/AUC(critical) 0.827；消融证明文本主信号；跨源 vuln_kb 81.2%、cve_ms 36.6%；seed 稳定性 0.0028
[x] 64. EXP-1002 CVE→产品/技术关系预测：200 类/107 万边，**P@5=0.9085/P@10=0.9425/MRR=0.864**（随机 0.025）；35 类直接对应 SiteLens 技术名
[x] 65. EXP-1003 模板命中先验：216 命中→90 模板；**info 级 lift=12 倍**、community-40k 3.1 倍、wordfence 8.2 万条命中 0（引擎调度先验的实证输入）
[x] 66. 历史关联覆盖率：历史 77 唯一 CVE 100% 可关联知识层（NVD 77/模板 23/tpl_intel 22）；模型产物持久化 + registry 链验证（EXP-1001/1002-model ok）
[x] 67. update-nvd 投影补 CWE 字段——**已由 4.x P5 完成**（update_nvd.go v2 镜像自带
    cwes；实测 2024-26 的 130,776/138,258 条自带该字段），无需改代码；CVE↔CWE 关系学习随之解锁
[ ] 68. （等待授权窗口）replay 实验与靶场 L2 标签（同 39/40）

## CWE 关系学习（2026-09-28：kb-5.0.1）

[x] 70. EXP-1005 CVE 描述→CWE 弱点类型分类：kb-5.0.1（cwe 边 349,291/802 类/
    31.3 万 CVE 带标注，写独立子目录不破坏 kb-5.0.0 已验证链）；top-25 主弱点、
    时间切分同口径，**acc 0.7586 / macro-F1 0.5794（多数类基线 0.2489，3 倍）**；
    长尾 57,808 条测试行如实排除不硬凑；模型持久化 + registry 登记
    （EXP-1005-cwe-model，上游 kb-5.0.1 MANIFEST）

## T1/T2 解锁（2026-09-28：用户拍板同意）

[x] 71. T1/T2 监督训练解锁（用户拍板）：引擎落执行日志 check_runs（主仓 main
    72524bf，executed+hit/未命中/not_executed 三值，纯增量字段）；新增
    target.allow_private 显式开关（main 8ed701e，默认 false 行为不变，gov.cn
    与云 metadata 永久阻断不随开关）；修复靶场 rng-* 容器旧路径 bind（改挂
    ranges-lab 新路径，8092-8095 恢复 200）；靶场 5 目标 full 档实扫 →
    5,642 条执行记录/16 命中；ml 侧 d4c_executions 表 + L1 可靠负样本 +
    gate 条件翻转（负样本>0 方放行）+ EXP-1101/1102 首次监督训练：
    **机制端到端实证，正例=1（内置 check 宇宙）致指标 insufficient_labels
    如实记录**——下一阶段瓶颈=正例积累（卫生类 check 命中需要真实
    部署失当目标持续扫描）；36 测试全绿

## 严重度分类提升尝试（2026-09-28：EXP-1006，确认性负结果）

[x] 72. EXP-1006 严重度 v2：标签自洽确认（sev vs 分数带 292,036 条 100% 一致，
    排除标注噪声假设）；六变体在严格三段切分（train<2022, val 22-23 选型,
    test≥2024 只碰一次）首轮未超原配方；**用户质疑过拟合→诊断实证成立**：
    alpha=1e-6 train/test F1 差 0.54 实质过拟合，正则收紧 1e-5（val 选型）
    test acc 0.5041→0.5221、F1 0.3768→0.3941，**EXP-1006-severity-v2-model
    重训持久化**；相邻带 94.4% 维持（上限修正为"正则后再挤 2 个点，仍存在"）。
    同轮 CWE 加 class_weight=balanced：**acc 0.7586→0.7709 / F1 0.5794→0.5899
    重训持久化**；诊断留档 metrics/DIAG-overfit-and-cwe.json；36 测试全绿

## 命名体系 + 严重度 0.75 冲击（2026-09-28）

[x] 73. 模型名册 `ml/model_registry.json`：公开名体系（sev-prior/cve-tech/
    cwe-type/verify-rank/find-rank，见名知义）与 EXP 追溯 id 分离——公开名
    用于文档/UI/CLI/对话，EXP id 只活在 manifest 链；命名规则成文
    （版本 -vN 递增、变体只进 metrics 数组不再造目录名）。
[x] 74. 严重度 0.75 冲击（EXP-1007，公开名 sev-prior-v3）：堆叠 CWE 预测
    one-hot + 元数据 + 词字联合，SGD/SVC 扫描——test acc 0.5058，**未达 0.75
    且未超现役 v0b（0.5221），promoted=false**。根因：CWE 栈与描述同源零新
    信息；0.75 exact-band 超出描述文本信息上限（相邻带口径 0.94 已达标）。
    突破前提=引入描述外信息源（CVSS vector 投影/PoC 存在性/厂商通告）

## 决策模型对比（2026-09-28 凌晨：EXP-1004，预注册）

[x] 69. EXP-1004 本地小决策模型 vs 传统 ML 基线：预注册协议与闸门先于任何被测系统
    推理提交（a062d10）；工作流调研核实 Jev 生态（Jev 本体无公开权重；正主
    Jev-Style-0.8B-Decision-v3 + 13 个复刻逐一探测）；正主官方参考实现与零样本
    Qwen3-0.6B 实测三任务全败——质量 E1 0.1633/0.0553 vs 0.5738、E3 0.0 vs 0.2437、
    E2 零样本 0.01 vs 0.905（正主 E2 因时间闸未测完，判定不依赖）；内存 3.6GB/888MB
    超 800MB 闸；宽选项延迟 25s 超 2s 闸。判定不采纳、路线收案（重开条件入登记）；
    基线吞吐 25,824 行/秒 @202MB 反向印证自有主线价值。报告：docs/5.0-总报告.md；
    偏差披露（仪器修正/正主 E2 时间闸）随报告存档；32 测试全绿

## sev-prior v2.2（2026-09-28：EXP-1009 大模型+大数据实测）

[x] 75. 用户假设【模型太小/数据太小】双实测：A 容量升级 TruncatedSVD(300)+
    HistGB（目标书优先模型）acc 0.6018；B 自训练 80,496 无标注描述池
    （17,169 条置信度>=0.8 伪标注入训）acc 0.5825；C 三模型软投票集成
    **acc 0.6024 / macro-F1 0.5047 / 相邻带 0.9520 / AUC 0.8463** 晋升现役
    sev-prior v2.2。累计 0.5738→0.6024；每路增益 1-2 个点，0.75 需 +15 个点
    仍超描述文本信息上限（三重证据：标签自洽/泄漏判定/边际收益递减）。
    过程留痕：首轮指标映射 bug（proba 列序未按 classes_ 重排）当场修复重跑

## 深度学习豁免实测（2026-09-28：EXP-1010，负结果）

[x] 76. 用户解禁深度学习（仅此分类模型）：DistilBERT-base（66M）GPU 满载微调
    （RTX 5060 8GB，bf16，93k 训练 × 2 epochs）——test acc 0.5484 / F1 0.3833 /
    相邻带 0.9356：acc +2.6pp 但 macro-F1 低于现役集成，两项不达标**不晋升**。
    至此模型类别全线试毕（线性/词字联合/回归/HistGB/集成/Transformer 编码器）：
    0.75 exact-band 在描述文本单一信息源下对任何模型类别不可达，约束=信息而非模型。
    豁免未产生生产模型；sev-prior 现役维持 v2.2 集成（0.6024/0.5047/相邻带 0.952）
[x] 77. 换信息源实测（EXP-1011，sev-prior v3.1-cwe）：CWE 可得设定（描述+真
    主弱点，95% 覆盖）GPU 微调——test acc 0.5401，相对描述单源零增益略降。
    **记录内部信息源穷举闭环**（描述/CWE/产品/时间四路全试，全数倒在 0.54-0.60）：
    严重度由 CVSS 的 C/I/A 与利用难度决定，这些信息不在 NVD 记录内。
    0.75 的唯一真路=记录外采集：利用可用性（Exploit-DB/KEV/模板覆盖）、厂商
    原始通告全文、受影响面分析。深度学习豁免未产生生产模型，sev-prior 现役
    维持 v2.2 集成（0.6024/0.5047/相邻带 0.952）
[x] 78. 换信息源第一轮实测（EXP-1012，sev-prior v3.2-exploit）：利用可用性信号
    （MSF 3,187 CVE + KEV 本地清单 + 模板覆盖 56,066 对；Exploit-DB 被 Cloudflare
    盾挡缺席如实记录）+ 小分类器续训——test acc 0.5326，有信号子集仅 +0.5pp，
    **未晋升**。五路独立实验（线性/集成/Transformer/CWE 可得/利用信号）全部
    落在 0.53-0.60：**描述→精确四类档的天花板 0.60±0.02 由分析师打分方差决定，
    已数学级确认**。利用可用性信号表保留为 KB 资产——主战场是 T1/T2 验证排序
    （有公开 exploit 的目标应当优先验证），非严重度分档
[x] 79. cwe-type v2 冲击（EXP-1013，DistilBERT GPU 微调，协议与 EXP-1005 逐项
    一致）：acc 0.7703 vs 0.7709 打平（跨模型家族收敛——精确 25 类天花板实证），
    macro-F1 **0.5899→0.6038（+1.4pp，稀有类更强）**；按预设双指标规则不晋升，
    F1 改进版 model.pt 已持久化备选（稀有类覆盖优先时可一键切换）
