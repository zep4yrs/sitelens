# CHANGELOG 5.0.0（技术档案）

基线：v4.0.0（含 v4.0.1 修复版全部内容）。以下逐条对应仓库提交，短 hash 可在
仓库历史中检索。

## 新增

- **5.0 机器学习线**（模型治理体系：公开名册 sev-prior / cve-tech / cwe-type /
  verify-rank / find-rank；挑战赛制度；预注册评测闸门）—— 986cf6f、eddc96e
- **深度融合·前置通道**：cve-tech 产品先验实时改变 check 执行顺序（提权排序）
  与覆盖（核心档位增量纳入扩展集检测项）—— 00d6c00
- **深度融合·中段通道**：检测项命中后同家族（wp/spring/bak/git/vcs/cms-login/
  dbadmin）未执行组联动提前，每家族至多一次 —— 00d6c00
- **深度融合·后置通道**：扫描收尾对发现 CVE 的产品 Top-5 / CWE 类型 / 严重度
  预测富化（predictions 字段，先验参考不参与判定）—— d40416b
- **sev-prior v3.1 ONNX 进引擎**：模型分直接进 sev_score（±1.07 区间呈现），
  sev_source 标注来源（onnx/nvd），缺失自动回退 NVD 先验；纯 Go WordPiece
  分词器与 HF 对拍 n=120 MAE=0.00000 —— b6990c2
- **桌面安装器全量内嵌 ML 资产**：线性模型 + sev-prior ONNX（fp32/int8）+
  onnxruntime.dll 随包，ml.sev_onnx 桌面默认开 —— 装箱与构建链改造
- **工作台 AI 预测呈现**：AI 产品先验摘要行、逐 CVE 预测表（sev_score±1.07
  区间、来源徽章）、模型降级说明 —— web/app.js
- **npm 分发线（0.0.1-rc 地基版）**：@fengqiao666/sitelens-cli（Ink TUI +
  非交互 CLI + serve 直通）与五平台引擎包（win32/linux x64+arm64/darwin
  x64+arm64），引擎按平台自动选包 —— c7d1160
- **check_runs 执行证据**：验证型检测项逐条 executed+hit / executed+未命中 /
  not_executed 三值证据，T1/T2 监督标签地基 —— 72524bf
- **target.allow_private 显式开关**（默认 false 行为不变）：本机靶场/授权内网
  场景；gov.cn 与云 metadata 端点永久阻断不随开关放宽 —— 8ed701e
- 训练参数与评测集随模型开源（TRAINING_PARAMS.md / training-params.json /
  评测集 E1/E2/E3）

## 修复（阶段 B 审计确认，4d2bb1a 及相关）

- CVE 编号整体形态校验：`CVE-2021-1002 (PoC)` 类带尾杂质不再进入 predictions
- mlFor 资产就绪判定改为全量预检（双模型 × 4 文件）：分步部署/更新窗口内
  一次扫描不再把 ML 永久禁用到进程重启
- 未配置资产目录时置死标记避免反复空转（区别于「配置了但未就绪」）
- 预测富化的 NVD 查询惰性纪律：cveMs-only 场景不因富化首次拉起全量索引
- gofmt 收口与口径统一（ml.go 文件头升级为三通道总说明）

## 模型质量（EXP-1004~1017，详见模型卡）

- sev-prior v3.1 现役：分数输出 MAE 1.07（-17% vs 1.283），相邻带 0.9654
- cve-tech 卫冕：P@5=0.9083（DistilBERT 挑战者 0.8162 不晋升）
- cwe-type 0.7709 现役（BERT 备选 macro-F1 +1.4pp 持久化）
- 六路实验矩阵闭合：严重度 exact-band 0.75 在 NVD 记录内信息不可达（负结果
  如实入档）；本地决策模型（Jev 类）不采纳
- T1/T2（verify-rank/find-rank）监督训练解锁：check_runs 正例持续积累中，
  未随本版本交付模型

## 内部

- ml/ 训练管线、bench 评测基建（预注册协议）、模型名册与模型卡入仓 —— 986cf6f
- 仓库 vendor 化 onnxruntime_go v1.36.0
- 文档：开发文档-5.0-ML预训练.md（§10 接线方案 / §10.7 深度融合落地 /
  §10.8 融合路线图）、模型卡、对比报告（4.0.0 vs 5.0.0 档位×深度实测）
