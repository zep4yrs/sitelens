# 更新日志

## v5.2.3（2026-11-01，待发布）

> 本版汇总：5.2.x 第二/三/四批收尾 + G09/G10 全量接线 + 企业化 6.x 基座 + MCP/辰极接口 +
> URL 自动修正 + 目录探测误报修复。完整发行说明见
> [`docs/release-5.2.3/release-body-5.2.3.md`](docs/release-5.2.3/release-body-5.2.3.md)
> （出包后回填体积/SHA256）；发布欠账清单见
> [`docs/release-5.2.3-发布欠账.md`](docs/release-5.2.3-发布欠账.md)。

### 高级 Web 检测（G09/G10，默认关）

- 越权矩阵（IDOR/水平/垂直）接进引擎，需调用方提供多角色会话（`Options.Sessions`）；
- 业务逻辑探测（数量/价格/优惠券/幂等）接进引擎，默认 **dry-run 只出计划**，显式授权才发请求；
- 上传绕过（危险扩展名/伪造 MIME/双扩展名）、反序列化入口标记识别接进引擎；
- WebSocket 明文/未校验 Origin、h2c/HTTP2 ALPN 协议面检查接进 DAST 阶段；
- 配置项集中在 `dast.*`（`proto`/`deser`/`logic`/`upload`/`idor`/`max_requests`），**默认全关**；
- 前端新增「高级 Web 检测」折叠组、扫描中提示与结果卡。

### 企业化 6.x 基座（additive，默认不启用）

> 默认构建已编入 sqlite（modernc，纯 Go）与 postgres（pgx stdlib）驱动；SQLite 已实测
> 建表/落库/历史读取，PostgreSQL 需自备实例（驱动与方言 DDL 已就绪）。

- 存储：`store.driver=json|sqlite|postgres` + `store.dsn`；SQLite/PG 自动迁移，失败回退 JSON；
- 鉴权：`web.auth_mode=token` + `web.auth_secret` 启用 HMAC-SHA256 令牌、`X-Tenant-ID` 租户校验、
  RBAC（viewer/operator/admin）；
- 批量：`batch.use_worker_pool=true` 走 `MemoryQueue + WorkerPool`（同 host 串行/重试/进度/取消/Webhook）。

### 生态与接口

- `sitelens mcp`：MCP stdio server（13 工具：capabilities/scan/scan_status/scan_result/scan_cancel/
  history/history_get/graph/export/triage/apispec/graphql_introspect/assets），辰极 Lodestar 可直接接入；
- URL 输入自动修正：补协议/去标点/hxxp 还原/全角转半角/默认端口，**只改格式不改目标**，
  修正说明在响应/extras/前端留痕；`target.auto_normalize: false` 可关闭。

### 修复

- 目录探测不再把 WAF/兜底 200 页当成真实文件（xgzwk 类站点误报修复）；
- 5.2.x 第二/三/四批内容（爬虫深度、认证矩阵、API spec、triage、SARIF、合规报告、分片/续跑、
  归档、模板治理、指纹置信、无障碍/i18n/桌面）见下方预留章节明细。

### 升级说明

- 不启用新配置时行为与 5.2.0 等价；企业能力与 G09/G10 均为 additive、默认关；
- URL 自动修正默认开（仅格式归一），如需严格旧行为设 `target.auto_normalize: false`；
- SQL 后端限制：`Import` 不支持（用 `store.MigrateFromJSON` 一次性迁移）、`Verified` 暂不提供；
- 已知限制见发行说明；`-race` 与 `govulncheck -tags onnx` 已在本地 MinGW/CGO 环境通过，CI 复核。

## v5.2.x 第二批 / 第三批（**未发布**；预留章节）

> 已实现，随下一次 5.2.x 发版整理；对应 main 分支 `13b688b`（第二批）+ `41a5514`（第三批）。
> 详细说明与数字复测见 [`docs/release-5.2.0/release-body-5.2.0.md`](docs/release-5.2.0/release-body-5.2.0.md)
> 文末「附：5.2.x 第二批 / 第三批（预留章节）」；进度见
> [`docs/新功能路线图-5.2.md`](docs/新功能路线图-5.2.md) §9。

### 源码审计（AU-02 / AU-03）

- 基线/忽略（只报新增）+ 与上次审计报告 diff（new/fixed）。
- 规则扩展：Java/Go/TS（含 JSX/TSX）+ OWASP Top 10:2021 映射；密钥扫描增强（云厂商 key 前缀 +
  高熵检测，报告不落密钥值）。
- SCA：解析 go.mod / package-lock.json / requirements*.txt。**边界**：无本地 OSV 库时只列依赖，
  漏洞状态标 `unknown`，不联网、不臆造漏洞。
- 兼容：不带新开关时 audit JSON 逐字节不变；新字段/新开关均为 additive。

### 网络层（NS-02）

- 证书资产线索（SAN/颁发者/到期 + 剩余天数）、cipher 套件分级、ALPN/HTTP2 观测。
- 端口/服务探测（TCP connect + 被动 banner ≤256B，`scan.port_scan` 默认关）、单主机组合与
  多主机批量入口；只读语义不变。

### 登录爆破（LB-02）与授权护栏（XC-03）

- 多步登录（先用户名后密码，JSON 端点与多步 action 同样受限）。
- 失败原因分类（凭据/锁号/限流/验证码/网络），不改变命中判定。
- 批量目标（串行、每目标独立护栏、跨目标总尝试上限 `MaxTotalTries`）。
- 授权白名单 `scan.allow_hosts`（空=不限制；精确域名或 `*.example.com`；不在白名单零请求
  拒绝）；SSRF/内网/gov.cn 硬闸门不受影响，白名单是授权护栏而非 SSRF 防护。

### 批量与定时（BT-03）

- cron 定时任务（持久化 + 到点调度 + 重启恢复）、与上次结果 diff（new/fixed）、`tag` 分组。
- 完成后 webhook POST JSON 摘要（`webhook_url`，空=不推送；只发摘要，不含证据链与凭据）。

### 报告与护栏（XC-02 / XC-03、CP-07）

- 扫描结果 **SARIF 2.1.0** 导出（结果页「SARIF」按钮 + `/api/export?format=sarif`），既有
  JSON/CSV/宽表/HTML/MD 导出不变。
- 合规评估报告（CP-07）：对标等保 2.0 三级与 OWASP ASVS 4.0.3，输出 Markdown/HTML
  （可打印 PDF）；显式声明「提示性映射，未命中≠合规」，不作为合规证书。
- 护栏：授权白名单、每 host 限速、WAF/限流拦截提示保持既有口径。

### 前端（FE-04 / 05 / 06 / 07 / 09 / 11 / 12）

- 无障碍：跳过导航、地标/页签/进度/分割条语义与键盘、弹层焦点陷阱与焦点归还、主题按钮
  `aria-pressed`、全局快捷键（Ctrl/⌘+Enter 扫描、Esc 取消/关弹层、Ctrl/⌘+E 导出）+
  中文输入法组合输入守卫。
- 动效：`web/js/motion.js` 骨架屏/列表渐入，只用设计令牌并尊重 `prefers-reduced-motion`。
- 质量门禁：`frontend-check.mjs`（语法 + a11y/标签）、`a11y-smoke.mjs`、i18n 测试接入 CI。
- i18n：中英字典（`web/js/i18n.js`，zh/en 各 113 键、对称）+ `t()/apply()` 接线壳/模式行/
  主要按钮/表单标签，支持 `data-i18n*` 标注与 `data-i18n-vars` 插值，切换同步 `<html lang>`。
  **边界**：页面静态文案分批标注（`app.html` 16 处，其余待接）；toast/服务端报告仍以中文为主。
- Monaco 懒加载瘦身（FE-09）：进入审计页/打开编辑器才加载（约 12MB），骨架 + 12s 超时降级为
  只读 textarea，不白屏。
- 响应式与打印（FE-11）：≤900px 窄屏布局 + `@media print`（结果/报告可打印或另存 PDF）。
- 状态机与零丢失（FE-12）：作业状态机（running/paused/blocked/partial）+ 取消/中断时部分
  结果落库（`partial` 标记，页面/技术/发现/证据保留）+ ResumePlan 续扫规划，不再「取消即丢弃」。

### 桌面（FE-08）

- 托盘：快速扫描剪贴板 URL、打开对比窗口、左键唤起工作台；快捷键 `Ctrl+Shift+S`（唤起并聚焦
  URL）/`Ctrl+Shift+Q`（快速扫描剪贴板 URL）。
- 快速扫描走既有 API（引擎零改动）：剪贴板 → `POST /api/scan {"level":"quick"}` → 轮询 →
  结果入历史 → 壳内通知窗（右下角、Acrylic、6s 自动关闭）。
- 窗口材质：Win11 Mica（旧系统 blur-behind）、深色标题栏跟随系统，`SITLENS_WIN_MATERIAL=off`
  回退纯色。**边界：未做 Windows 真机验收，对外发布前需实机复测。**

### 对标补课（CP-01/02/04/05/06/08/10/11）

- CP-01 爬虫深度：`crawler.max_depth`（默认 2）、JS/SPA 路由发现、链接归一化、跳过计数。
- CP-02 认证矩阵：Header/Bearer/Basic/Cookie 只读注入 + 凭据脱敏/防头注入 + 多会话原语
  （能力层，未接入扫描主流程）。
- CP-04 基准评测：`benchmark/` 体系（P/R/F1、`catalogCoverage` ≥80% 口径、季度复评、
  `score.mjs` 自检），流程见 `docs/基准评测-5.2.md`。
- CP-05 性能分片：SplitShards / checkpoint 恢复 / 并发上限 ≤4 / 失败重试 1（能力层）。
- CP-06 持久化：文件分层 + 归档（`history.archive.jsonl`，JSON Lines、0600、可回灌），
  **未引入 SQLite/PG 后端**。
- CP-08 UI triage：复核结论（误报/覆盖）与白名单持久化，`/api/triage/{scanID}`、
  `/api/whitelist` + 前端 triage 入口。
- CP-10 模板治理：按来源统计 runs/pass/fail/hits，通过率（模板可用性）与命中率（有效产出）
  分开统计。
- CP-11 指纹置信度：证据计数 + 通道加权 + 同页冲突降权 + 版本交叉校验 → confidence(0-1) +
  reasons，供 Tech.Confidence(0-100) 与「为什么判定为该技术」展示。

### 已知限制与顺延（本批）

- SCA 漏洞状态 unknown（无本地 OSV 库时只列依赖）。
- 桌面未 Windows 真机验收。
- 品牌更名「晦明 SiteLens」暂缓（FE-13）。
- CP-06 为归档分层，非 SQLite/PG。
- CP-02/05/07/10/11 为能力层，扫描器/UI 接线随后续批次。
- CP-09 资产台账、FE-10 组件预览页未随本批交付，顺延。
- 升级影响：既有导出/报告格式不变；SARIF 与合规报告为新增格式/入口；无需重扫历史数据。
  回退：`scan.allow_hosts` 清空、`webhook_url` 留空、`port_scan`/`max_depth` 关闭即回旧行为。

## v5.2.0（2026-10-29，全代码库体检修复集 + 交付体验）

> 主题：**把扫描结果里会误导人的地方修准**。不新增扫描能力；会改变部分历史结论，
> 升级前请读 [`docs/release-5.2.0/release-body-5.2.0.md`](docs/release-5.2.0/release-body-5.2.0.md)
> 的「升级前必读」。36 条缺陷修 35 条（BUG-035 包体瘦身已落**阶段 1**：ONNX 退出默认
> 分发、严重度改「NVD 查表 + 0.7MB 线性回归」兜底，ML 资产 748.9 → 约 106 MiB；
> 同轮仓库瘦身：ONNX 资产与 LFS/git 历史已清理，完整 clone 约 1.35 GB → 0.5 GB），
> 13 条文档漂移对齐，另新发现并修复 4 条同类静默缺陷。完整实测记录见
> [`docs/bug清单-5.1.0.md`](docs/bug清单-5.1.0.md) §0.5。

### 结论正确性（P0 / P1）

- **CVSS v3.1 计分与 NVD 官方 100% 对齐**：修三处叠加缺陷（`AV:L` 误用 v2 权重、
  Scope Changed 漏 ×1.08、PR 权重依赖向量书写顺序）；29 万条官方向量逐条对拍
  由 41.42% 不符降到 0，并固化为门禁。
- **四段版本号不再误判「确认受影响」**：`versioncmp.Parse` 改不定长逐段比较
  （`10.0.19041.1234 <= 10.0.19041` 现为 false）。
- **复现命令可复现且不被目标站做手脚**：表单地址/字段名/载荷全部 shell 转义；
  表单类证据链改 POST 语义并按表单编码；URL 通道的 CRLF/反序列化预编码载荷不再被
  二次编码（字节级断言）。
- **云 metadata 端点永久阻断**：`allow_private` 不再放宽；HTTP 拨号层改为
  「一次解析 → 全量校验 → 按已校验 IP 拨号」，封堵 DNS 重绑定。
- **afrog 模板来源恢复**：rule 级 expression 接线（新增 `internal/afrogx` 求值器 +
  `checks.Match.Expr`），通过率 0/1,699 → **878/1,699（51.7%）**、转出 1,051 条检查；
  不可判定/纯状态码/多请求 AND 等按「宁少报」拒收。
- **模板多 path 覆盖**：path 列表按上限 4 展开（此前只探第一条），请求量 +17%~36%。

### 稳定性与并发

- KEV / 漏洞表 / CVE 公告表加锁与副本换代（覆盖合并不再原地排序）；`techIDs`、
  `apiToken` 原子换枪；403 绕过计数改原子；重定向中间跳响应体正确关闭。
- 启动期增量情报（KEV / CPE 映射）不再被首次解码覆盖；空闲释放内存（`Release`）后
  重载不再丢 KEV 增量；调度表 `null`/损坏不再 panic；历史残缺记录统计路径不再 panic；
  插件热加载索引不再陈旧。

### 交付与体验

- **包体瘦身（阶段 1）**：默认安装包不再带 sev-prior ONNX（643.3 MiB）与
  onnxruntime.dll（15.7 MiB）；严重度默认「NVD/情报行查表（误差 0）→
  `ml.sev_linear` 0.7MB 线性回归兜底（留出 MAE 1.180；同一 600 抽样对照 1.079）」，
  ML 资产 748.9 → 约 106 MiB，引擎载荷实测 173.8 MB。ONNX 降为可选高级包
  （`SITLENS_BUNDLE_ONNX=1` 出包 + 设置页 `ml.sev_onnx` 开关），旧能力可回退；
  详见[阶段 1 落地记录](docs/release-5.2.0/阶段1-线性severity与ONNX下线-5.2.0.md)。
- **ML 数据快照刷新（2026-10-30）**：NVD 字典 372,542 → **398,118 条**（内容到
  2026-10-30；v3 格式 + 字段精简/去重，37.8 → **30.7 MiB**）；指纹库 +16 条
  （13,727 → 13,743）；词表文件内去重 1,446 行；OSV 补全 206 条区间/评分；
  `sev-linear` 按新快照复训（留出 MAE 1.1802 / 夹具 1.0858）。详见
  [数据快照刷新记录](docs/release-5.2.0/数据快照刷新-2026-10-30.md)。
- **ML 查表优先（阶段 2）**：`predictions` 的产品/CWE/严重度改为「NVD CPE / NVD
  weaknesses / CVSS 分 / 情报行字段 → 模型兜底」，查表全覆盖时不加载 94MB 模型；
  前置先验通道改为「指纹技术名 → 产品映射」确定性路径（不依赖模型资产）；新增
  `tech_source`/`cwe_source` 来源标注，查表结果的 `tech_top5[].prob` 固定为 1（非概率）。
  详见[阶段 2 落地记录](docs/release-5.2.0/阶段2-查表优先与指纹先验-5.2.0.md)。
- **引擎与 CLI 拆成两个二进制**：桌面壳只拉起引擎（`serve` + `update-seed`），
  CLI 独立分发；桌面端启动/退出不再弹控制台窗口（`CREATE_NO_WINDOW`）。
- **CLI 收口到 TUI 单一入口**；`~/.sitelens/` 统一用户区；全局 flag 放在子命令前后都生效。
- **前端失败分级**：网络/HTTP/非 JSON 三类失败带 URL 与原因，11 处静默 catch 收口，
  新增「引擎不可达」界面态。
- **应用内反馈页 + 本机脱敏诊断包**：`GET /api/diagnostics` 资产就位矩阵、降级清单、
  最近失败记录、配置摘要；默认不提交，不做常驻埋点（用户协议承诺不变）。
- **安全收紧**：`overrides_path` 限定数据目录内；历史/配置文件权限 0600；
  更新通道强制 HTTPS + 实测 SHA256 留痕（可选钉值硬校验），先校验后解包；
  `migrate-pg` 口令改环境变量、`sslmode` 默认 `prefer`。
- **部署/工程**：Dockerfile 补齐情报/CVE/模板情报资产（模板池与 ML 改为挂载并写明
  降级矩阵）；`.gitattributes` 统一 `eol=lf`；13 处文档漂移订正。
- **构建工具链升级到 Go 1.26.10**：修复标准库 `crypto/x509` 证书验证漏洞
  GO-2026-6809（1.26.9 及以前受影响）。安全扫描器本身必须用已修复工具链构建；
  CI `govulncheck -tags onnx ./...` 门禁已清零。

### 性能（第二轮优化，实测）

以下均为同机、同语料、新旧实现交错对比的实测数字（Windows / i7-14650HX）：

- **指纹匹配**（40KB 页面 × 13,727 条指纹）：24.7ms → **5.3ms（4.7×）**，
  单页内存分配 4,381 → **194 次**（-95.6%）。做法：字面量预筛改滚动 4 字节 key +
  开放寻址表；正则按语法树推导「必含字面量条件树」，可证不匹配时不执行
  （拟真页 436 条正文正则实际只跑 2 条）；相同正则只编译一次 + 同页结果复用；
  Evidence 正文小写惰性缓存；Matcher 名称查表。
- **多页扫描**（4 页 × 40KB 端到端）：≈102ms → **6.2ms（16.4×）**。
  额外做法：多页指纹识别页间并行（结果仍按页序合并，行为与串行一致）。
- **模板索引热路径**（每次扫描固定开销，14.4 万模板池）：≈1.1s → **≈6ms/次**；
  缓存格式升级 **cacheSchema v10**（目录 mtime 戳 + 进程内单条缓存），
  升级后首次扫描重建一次（满池约 8s）。
- **模板索引冷构建**（14.4 万模板折算）：≈35–57s → **≈8s（4.5–6.6×）**。
  做法：模板前端形状字节级预筛（afrog 模板 3 次 YAML 解析 → 1 次）+ 按核并行转换；
  输出与旧实现逐条等价（差分快照 + fuzz 兜底，fuzz 期间抓到并修掉 1 个 YAML
  换行形态误判）。
- **HTTP 拨号**：在「一次解析 → 全量校验 → 只拨已校验 IP」的 SSRF 语义不变前提下，
  对已校验 IP 做轻量 Happy Eyeballs（RFC 8305，250ms 错峰、先成功者胜出并取消其余）。
  首地址黑洞、后一地址可用的场景：**从请求超时失败（默认 20s）变为 ≈250ms 成功**。

性能基准已固化：`BenchmarkMatch`（internal/sitelens）、`BenchmarkMultiPageScan`
（internal/engine）；等价性由「旧语义参照逐字段比对」「门控跳过 ⇒ 正则确实不匹配」
测试与模板转换差分快照兜底。

### 效率（第三轮：WAF-aware 自适应限速 + 请求去重）

- **限速层重做**：修掉旧 `wait()` 的 pairing 缺陷（并发调用者齐发 → 实际速率
  N/interval，400ms 配置实际 ≈5 rps）；改为 **per-host 共享令牌桶**（全进程共享、
  容量 1、空闲 5min TTL）。新增 `scan.rate_mode`：`balanced`（默认，400ms 起步 →
  连续干净成功减半 → **默认硬下限 125ms ≈ 平均 ≤8 req/s/主机**；代码级绝对上限
  10 req/s，配置无法突破；间隔高于下限才抖动）与 `polite`（固定 `rate_interval_ms`，
  修正后 400ms = 真实 2.5 rps）。RTT 恶化自动退避；429/503/Retry-After/WAF 特征头/
  挑战页/2xx→403 降级 → `Resp.Blocked` + 锁定低速；`Stats()` 暴露请求数/间隔/
  平均 RPS/blocked/backoffs。
- **请求去重**：DAST benign 基线跨通道复用（payload 绝不复用；时间差分复用携带
  首次真实 RTT 防误报）、只读页面响应单扫描复用、crawler additive `SetPageHook`
  逐页流式指纹/被动、主页/robots/favicon/种子页去重；WAF 拦截响应不参与任何判定
  （防回显假阳性）。
- **诊断账本**：`Result.Diagnostics`（JSON `diagnostics`，additive）——总请求/
  blocked/backoffs/WAF 原因/去重命中/平均 RPS/实际间隔/流式标记 + 每阶段明细。
- **实测**（4 页带表单/带参，deep+DAST）：旧实现 775 请求/155.1s → 新默认
  **771 请求/98.1s（-36.8%）**，发现结果等价（dast 层复用对照 + 旧/新逐字节等价
  用例）；保守档 `rate_max_rps: 5` 与旧实现同速（156.09s），polite 400ms 为
  310.01s。目标侧默认平均 7.9 req/s/主机、峰值 1s=9、并发不增（最大并发 1）、
  RTT/WAF 信号自动退避；详见 `docs/release-5.2.0/效率轮-5.2.0.md`。

### 交互反馈（5.2 P0：扫描前 / 扫描中）

- **扫描前**：目标即时预检（空/非法/非 http(s) 明确报错，IP/内网给授权风险提示），
  目标非法时禁用开始按钮；右画布显示「扫描计划」——将运行项、请求量级（低/中/高）、
  经验估时，全部纯本地计算、不额外发请求。
- **扫描中**：引擎新增 Options.OnLive（节流 ~250ms，phase/请求/页面/被拦/瞬时速率），
  服务端 /api/job/{id} 增 additive live 字段；前端实时面板按阶段时间线高亮
  （DAST 长阶段不再假进度）、请求/页面/被拦/速率统计条、ETA 随实际进度外推、
  被拦 >0 显示「WAF/限流：已自动降速，被拦响应不参与判定」横幅。
- 全部 additive：不改结果 JSON/导出格式，不改变扫描行为。

### 5.2 新增（部分）：预检 / 网络层 / 爆破护栏 / SARIF

> 其余能力列入 5.3（见 `docs/新功能路线图-5.2.md`）。

- **扫描前预检 + 建议卡**：输入目标后 1 次只读 GET（≤ MaxHops 跳/256KB/5s），展示状态/标题/服务器/WAF/指纹并给建议档位；**开始扫描时复用该响应为首页，总请求不增加**；`scan.preflight` 可关，同 URL 30s 去重。
- **网络层 P0**：证书 hostname/SAN、链完整性、SHA-1、RSA<2048；DMARC 策略 + rua、SPF 查询数/语法、HSTS、HTTP→HTTPS 跳转；修复证书校验配置导致既有证书类发现长期空转的前提缺陷。
- **登录爆破安全护栏**：锁号/429/403/连续失败自动停止或退避、每账号上限、每次重取 hidden/CSRF、成功证据（响应差异 + Set-Cookie + 跳转 + curl）。
- **源码审计 SARIF 2.1.0 导出**：`sitelens audit <dir> --sarif out.sarif`，ruleId/level/locations/partialFingerprints 稳定；既有 JSON 报告键位不变。
- **批量扫描增强**：逐行档位（`url quick|standard|deep|full`，中英文均可）、失败自动重试 3 次、同 host 串行/跨 host 并行、任务队列显示档位/尝试次数、结果 CSV 导出、**断点续跑**（状态落盘 `data/state/batches/`，取消/重启后可续跑未完成目标）。

### 已知限制 / 待拍板
- BUG-035 包体瘦身：已实测 891.4 MiB 构成、确认「只带 int8」零 Go 改动（≈380 MiB），
  但 int8 精度需 CGO + onnxruntime 环境实测后拍板；打包脚本本版未改。
- 表单 POST 通道的 CRLF 探针仍待引擎「原始表单体」通道；`netx` CNAME→私网缺口保留。
- `-race` 门禁需 CGO 环境（本机无 C 编译器，用例按 race 友好设计）。
- 模板索引的目录 mtime 校验在网络盘/粗粒度文件系统或「批量落盘后数毫秒内立即扫描」
  的极端时序下可能延后一次扫描才感知（只会少跑新模板，不会误报）；in-place 覆盖写
  与 5.1 同口径。
- 指纹正则的旧字面量门控对 `\s`/`\d` 有既有误提取（HTML 通道保持 5.1 语义未改召回，
  meta 通道已改用语法树门控）；修正属语义变更，另行评估。

## v5.1.0（2026-10-11，模板调度 CVE 通道 + 桌面切 Wails 壳 + 判定通道补齐）

### 桌面交付：正式切到 Wails 壳

- 交付线从 Electron 壳（`desktop/`）切到 **Wails 壳**（`desktop-wails/`，
  Go + 系统 WebView2），单文件壳约 12MB（对比 Electron 安装包 ~100MB），
  壳与引擎同语言栈。Electron 壳保留为历史形态，不再作为发版产物。
- 端口决策补齐：**壳偏好 > 配置原文 `web.listen` > 默认 5087**，被占用才换
  随机空闲端口，协商结果回写 `desktop-prefs.json` 供下次认领（旧 Wails 壳
  恒取随机端口，书签/排障 URL 每次失效）。纯逻辑抽 `internal/portpolicy`，
  跨平台单测覆盖。
- 壳版本号新增单一来源 `desktop-wails/version.go`，启动页版本号位与托盘
  提示由此取值（此前恒空）。
- 发版链路切换：`tools/release_local.sh` 改走 `tools/wails_build.sh`
  （构建壳 + 引擎载荷 → PE 魔数校验 → 壳/引擎版本一致性硬闸 → NSIS 打包）。
- CI 新增「Wails 壳回归」步骤：独立模块单测 + `GOOS=windows` 构建/vet 门禁。
- **未接线项（如实记录）**：自动更新、崩溃自愈、单实例三块尚未实现，
  本版以手动覆盖安装交付；用户数据区与旧壳不同（`SiteLens-Wails`），
  升级需手工迁移。详见 `desktop-wails/README.md`。

> 承接「技术名 → 模板 tag 归一」（上一个已合并的改动）。tag 归一解决的是
> 「指纹名与模板 tag 两侧写法不一致」，但模板里还有一大类**只用 CVE 命名、
> 不带产品 tag**——这类模板在 tag 通道里永远是空集，只能等 LRU 轮转碰到。
> EXP-1003 的实证就是这条路的终点：wordfence 源 82,709 条在靶场命中 0，
> 不是模板写错，是「它瞄的这台目标上没有」却照样排队，把预算吃完。

### 新增：CVE 通道（`SelectWithCVE`）

- 调度新增第三路：**指纹技术名 → 受影响 CVE（intel KB 关联）→ 声明该 CVE 的
  模板置顶**。命中 CVE 的模板优先于 tag 命中——「这台机器真的中的」比
  「tag 词面对得上」更值得先花预算。
- 预算配比不变：命中集（CVE + tag）合计至多占 2/3，余下留给 LRU 轮转；
  被截断的命中退回轮转池参与竞争，不丢弃——「全池迟早跑完一遍」的数学
  保证不被更强的匹配破坏。
- **零回归**：intel 未挂载 / 指纹无关联时 CVE 集为空，`SelectWithCVE`
  行为与 `Select` 逐条一致（有等价性测试）。
- 封顶：单次扫描纳入 CVE 通道的 CVE 数上限 64（指纹繁多的目标不得让
  反查集无界膨胀）。

### 判定边界（诚实）

CVE 集合来自 intel 关联（可能含 possible 级）。本通道**只调整调度优先级，
不改变任何判定逻辑**——跑出来的结论仍由模板自身的 matcher + 二次确认负责。
所以它零误报风险，收益是「对的有机会跑」，不是「把库存变成命中」。

### 可观测性

`extras.nuclei` 新增 `cve_total`（关联出的受影响 CVE 数）与 `cve_hits`
（声明这些 CVE 的模板数），与既有 `tag_hits` / `selected` / `budget` /
`sources` 并列。

**收口（本轮补齐）**：`extras.nuclei` 此前只落进 JSON，Web 端与
HTML/MD 报告都没渲染它（前端通用 extras 循环按数组处理，遇到这个对象
只会显示标题、内容空白）。现在三处都出「模板调度」摘要行：
候选池 / tag 命中 / 受影响 CVE / CVE 命中模板 / 本轮选入 / 来源分布。
`受影响 CVE` 与 `CVE 命中模板` 刻意分开列——前者为 0 是指纹没对上情报，
后者为 0 是模板池里没有声明这些 CVE 的模板，两者含义不同，合成一个数
就看不出来了。这正是这条通道唯一的在线判读口径。

### 验证

- `internal/nuclei`：CVE 优先于 tag/severity、cveSet 为空时与 `Select`
  逐条等价、CVE 命中集不饿死轮转（多轮覆盖非命中模板）。
- `internal/engine`：指纹 → 受影响 CVE 映射、无 KB/无技术安全回退、CVE 集封顶；
  端到端 `nucleiSubset` 在 cap=1 且存在 tag 命中诱饵时，仍把受影响 CVE 的
  模板选进预算（关闭通道时该测试失败——已验证）。
- `go test ./internal/...` 全绿，`gofmt`/`go vet` 干净。


### 爬虫 robots 解析修复：Disallow: / 不再静默塌缩

> 走查发现一个会让爬取在真实目标上塌缩到入口页的 P0：`allowed()` 用的是
> 「Disallow 前缀」的极简实现，只认 `User-agent: *` 段、忽略 `Allow` 与通配，
> 且当目标 robots.txt 写 `Disallow: /`（封禁整站）时，**每一条同域链接都会被
> 静默跳过**——扫描出来只有一页，报告却毫无线索。

### 修复

- **robots 解析重写**（`internal/crawler/robots.go`）：按 UA 分组（连续 UA 共享
  规则、精确 UA 优先于 `*`），组内 `Allow`/`Disallow` **最长匹配优先、同长 Allow 胜**，
  支持 `*` 通配与 `$` 结尾锚点，剥离行内注释与 CRLF，空 `Disallow:` 视为无限制。
  此前 `Allow: /admin/public` 无法覆盖 `Disallow: /admin/`、`/*.php$` 被当成字面前缀，
  都会误判。
- **整站封禁不再静默**：命中组封禁 `/` 时记 `Result.RobotsAll`，引擎在扫描进度里
  明确提示「robots.txt 封禁整站（Disallow: /），爬取仅入口页」，并给出
  `crawler.respect_robots=false` 的覆盖指引。是否遵循仍是配置项，但结果不再无声无息。

### 复现与验证（真实目标）

- `https://pentest-ground.com:4280/robots.txt` 实际内容即 `User-agent: *` +
  `Disallow: /`——此前该目标爬取只会得到入口页。回归测试逐字节复刻这份 robots，
  断言：遵循时 `RobotsAll=true` 且仅入口页、关闭遵循时恢复完整爬取。
- 新增 robots 单测：Allow 覆盖、空 Disallow、通配 `*`/锚点 `$`、多 UA 分组、
  注释/CRLF、Sitemap 收集。

### 口径

`respect_robots` 默认仍为 `true`（遵循）。对**授权目标**（本机靶场/已授权内网）
若要完整爬取，按需置 `false`——这是配置决策，不是被静默吞掉的 bug。


### 验证码识别重放 / 越权 / 加密实现 / 开放 API：四条判定通道

> 承接上一轮「判定通道补齐」的思路，这一轮把 Issue 里点名的四个模块
> 逐个落地：captcha（识别接线 + 侧信道重放）、authbypass（越权）、
> cryptography（加密实现）、api（开放 API）。四类都不是「参数注入」，
> 判定依据与既有注入通道正交，各自单列通道。

### captcha：OCR 接线 + 侧信道重放

- **OCR sidecar 接进生产路径**。`internal/captcha`（ddddocr 客户端）与
  `loginbrute` 的验证码逻辑都在，但引擎侧构造爆破参数时把 `CaptchaType`
  写死为 `"none"`、既不传 `OCRURL` 也不传图片拉取通道——**验证码表单
  的口令爆破从未真正启用过**。现在按 `loginbrute.captcha_ocr_url` 接线：
  配了地址才启用识别，每次尝试前重取验证码图（旧码提交后即失效）。
- **验证码重放/校验缺失**（`captcha-missing` / `captcha-replay`，侧信道，
  不需要 OCR）。DVWA Insecure CAPTCHA 的真正缺陷不是「图认不出来」，而是
  **校验结果可被跳过或重放**：前置步骤校验一次后，后续步骤不再校验。
  新增两条判定——同一步骤下同一份明显错误的验证码被稳定受理
  （`captcha-missing`，校验恒真）；后置步骤不提交有效验证码即被受理
  （`captcha-replay`，跨步骤绕过）。都做双确认。

### authbypass：越权（标识可控 + 无访问控制）

- 此前只有「SQLi 认证绕过」（登录表单注释截断），缺**授权层**的绕过节。
  DVWA Authorisation Bypass 与 Altoro 的账号枚举同属一类：请求里带
  客户端可控的身份/资源标识（`user_id` / `account` / `uid` …），服务端
  不校验当前会话对该资源的访问权。新增 `authz-bypass` 通道，三道误报
  防护——标识无效（不同取值响应相同）不报、目标本就 403/401/登录页
  不报、越权响应形态双确认；只在「标识确实决定内容」且「高权标识仍
  放行」时报。只读 GET，不改状态。

### cryptography：加密实现弱点

- **确定性加密**（`crypto-deterministic`）。同一明文多次加密得到**同一密文**
  → ECB 模式 / 固定 IV / 硬编码密钥，泄露明文相等性。判定先要求「换明文
  密文随之变化」（排除静态常量串），再要求两次同明文密文一致，避免把
  正常随机 IV 的 AEAD 误判。
- **弱加密/编码实现暴露**（`crypto-weak-algo`）。响应中出现无盐哈希 /
  可逆编码冒充加密的实现特征（`md5(` / `base64_encode` / `ecb` …）。
  与基线求差，页面本来就有的不算。

### api：开放 API（未授权读取 / IDOR）

- **未授权/过度暴露**（`api-unauth`）。API 端点无凭证即返回结构化数据，
  且含敏感字段（`password_hash` / `token` / `email` / `role` …）。
  判定要求响应是结构化数据（JSON/XML）而且命中**字段名**——单靠
  「返回 200」会漫天误报，公开 API 返回 200 是正常行为。
- **API 资源越权**（`api-idor`）。路径中的资源标识可替换，且跨主体
  仍返回含敏感字段的完整数据。与 `authz-bypass` 的区别：这里针对
  `/api/` 风格端点，要求同时验证「内容随标识变化」与「另一标识可见」。
- 配套修复：API 端点通常不带查询串（`/api/v2/user/1`），而 DAST 探测点
  只从**带参链接**收集——API 通道会永远空跑。现已把爬到的页面 URL
  一并登记，由通道自行筛出 API 风格路径。

### 配置与登记

- 新增 `[dast] captcha_replay / authz_bypass / api_audit / crypto_probe`
  四个通道闸（默认开，跟深度探测面总闸）；`[loginbrute] captcha_type`
  与既有 `captcha_ocr_url` 组成 OCR 接线。
- 新 check id 全部登记 CWE：`authz-bypass`(CWE-639/862)、
  `sqli-auth-bypass`(CWE-89)、`captcha-missing`/`captcha-replay`(CWE-804)、
  `crypto-deterministic`(CWE-329/780)、`crypto-weak-algo`(CWE-327/916)、
  `api-unauth`(CWE-306/200)、`api-idor`(CWE-639)。

### 验证

- `go test ./internal/...` 全绿；`gofmt` / `go vet` 干净；vendor 未动。
- 新增回归：验证码字段识别/受理判定/恒真与正常校验两态、越权（可控标识、
  403 拒绝、静态页三种反例）、确定性加密与随机 IV 反例、API 未授权与
  IDOR、非结构化响应不误报、受保护 API(401) 不报、总闸关闭不产出。
- 端到端实跑（本地模拟靶场 + 真引擎 CLI）：9 条 verified，含
  `captcha-missing` / `authz-bypass` / `crypto-deterministic` /
  `api-unauth` / `api-idor` 四条新通道；安全站（受保护 API + 正常校验
  验证码 + 随机 IV）四条新通道**零误报**。

## v5.1.0 增补：桌面自动更新 + 覆盖更新（同版首发，未单独发版）

> 用户提问（Issue #25）：「可以接自动更新，然后能不能覆盖更新」。
> 切 Wails 壳时这两块按设计**未接线**（desktop-wails/README「已知边界」写明）。
> 本轮补齐，并把「覆盖更新」拆成两件必须同时成立的事：**种子按版本覆盖** 与
> **静默就地覆盖安装**。

### 一、随包种子按版本覆盖（引擎新增 `update-seed` / `internal/seedrefresh`）

- **旧行为**（Electron 壳遗留）：首启把安装包内置种子（NVD 快照 / 情报行 /
  指纹规则）按**「用户区不存在才拷」**刷进用户数据区。保住了 update-* 成果，
  代价是**包内快照永远进不来**——用户没手动跑过 update-nvd 时，升级到带更新
  NVD 的版本，用户区那份旧副本仍是权威源：**升了版本，情报还是旧的**。
- **新行为**：每次启动按**包版本**交付。版本与上次不同才覆盖，相同即 no-op；
  交付版本 + 每份 sha256 落在 `data/.seed-manifest.json`，可复核。
- **覆盖边界写死在引擎侧白名单**（壳不重复实现）：可覆盖 = 情报快照
  `data/*.json[.gz]`、指纹/技术库/模型 `data/go/**`、推理运行时
  `data/onnxruntime/**`；**永不覆盖** = `state/`（扫描历史）、
  `pools/nuclei/`（模板池）、`plugins/`、`data/wordlists/`（用户可能自己加词）。
- 覆盖是**原子替换**（临时文件 + rename），失败留不下半截文件，也不阻断启动
  （引擎照常读用户区那份，`shell.log` 留痕）。
- 覆盖之后用户随时可再跑 `update-nvd` 等在线渠道拿最新版；**同版本启动不会再
  把它冲掉**（清单显示已交付）——「覆盖更新」与「不伤用户成果」两者同时成立。

### 二、Wails 壳自动更新接线（检查 → 下载 → 静默就地覆盖 → 重开）

- **检查**：启动静默一次 + 托盘「检查更新」。读更新源 `latest.yml`（与
  Electron 壳/发版脚本产出的同一格式，两条壳共用更新源与产物，发版侧零改动），
  比对版本（纯逻辑在 `desktop-wails/internal/updater`，含预发布/回滚语义）。
- **下载 + 校验**：安装包下到用户数据区 `updates/`（安装目录只读，不能当落点），
  sha512 与清单比对，截断/损坏当场发现，**不碰任何已安装文件**。
- **静默就地覆盖**：以 `/S` 拉起 NSIS 安装器——无向导页，按注册表 `InstallDir`
  就地覆盖原目录（升级不挪窝）；壳随即退出以释放待替换文件。
- **装完自动重开**：`/S` 没有完成页，`MUI_FINISHPAGE_RUN` 不生效，安装器
  Section 内显式 `Exec` 新版（否则「装完没窗口」，用户以为升级失败）。
- **已知限制（如实）**：安装器是机器级（`RequestExecutionLevel admin`），
  非提权进程拉起的自动更新**会弹一次 UAC**——是就地覆盖、无向导页，但不是
  零交互；零 UAC 需改用户级安装，另行评估。

### 三、顺带修掉一个真实缺陷：Wails 壳只写 `web.listen`

引擎以 cwd（安装目录 `engine/`）解析相对路径，壳此前只写 `web.listen`，
于是 `store.data_dir`（扫描历史）、`intel.overrides_path`、`checks.nuclei_dir`
全按默认相对路径解析，**写进 `$PROGRAMFILES64\SiteLens\engine\data`** ——
普通用户对该目录只读，写入即失败（Electron 壳 v3.0.0 首启 EPERM 的同一个坑）。
现在受管键把可写路径全部归到用户数据区（`internal/usercfg`，有跨平台单测），
只读资产仍留安装目录随包整体替换。

### 验证

- `internal/seedrefresh`：白名单（种子覆盖 / 词表·历史不碰）、版本相同整批跳过、
  版本变化重新覆盖、同版本二次启动不改用户新快照、源缺失时原子性不留半截。
- `cmd/sitelens`：`update-seed` 端到端（覆盖 + 清单落地 + 用户成果存活 + 幂等）。
- `desktop-wails/internal/updater`：版本比较（数值序 / 多段 / 预发布 / 回滚）、
  清单解析 → 判定 → 下载地址拼接、缺字段报错。
- `desktop-wails/internal/usercfg`：可写路径必落用户区、只读资产留安装目录、
  受管键名与引擎 yaml tag 逐字对齐、用户既有键不被抹。
- 实跑演示：包内 `nvd-new` 覆盖用户区 `nvd-old`（含 `data/go`、`onnxruntime`），
  用户历史原位存活；同版本二次调用 no-op。
- NSIS 脚本编译通过（`makensis -V2`，含 LogicLib 的 `${If} ${Silent}` 分支）。

## 上一轮（弱会话/存储型 XSS/缓存/命令注入回显：判定通道补齐）

> 上一轮（PR #35）拓宽了 CSRF / 弱会话 ID / CSP 三个检查类的判定面。
> 这一轮继续把「底座在、判定面窄」的同类漏报补掉，并补上两处
> **判定通道缺失**（不是探测面窄）的真漏报：命令注入只看时间差分、
> 存储型 XSS 只看同响应回显。

### 新增判定通道

- **命令注入回显通道**（`cmd-echo`）。此前只有 `sleep` 时间差分一条路，
  只看得到「盲」场景。DVWA 的 Command Injection 模块是把命令输出直接
  回显在响应正文里的，时间差分完全看不见。新增注入 `echo 算式` 的探针，
  以「运算结果出现在响应里、且基线里没有」判定。误报防护：反射回显型
  目标会把 payload 原样吐出（`;echo 15846`），此时响应里也含结果数字，
  判定必须逐处检查出现位置——**全部**紧邻命令/算式标记才算字面量回显，
  存在一处孤立出现才是真求值。URL 编码形态（`%3Becho+15846`）一并覆盖。
- **弱随机标识差分通道**（`weak-random-id`）。同一 URL 两次取样，比较
  会话类载体（csrf_token / nonce / viewstate / authenticity_token 等）的值。
  「每次刷新都变」且**形态本身低熵**（时间戳 / 短整数 / 近全数字短十六进制）
  才报。强随机串每次刷新当然也变，那是正常的——不做熵统计（单样本测不出
  分布，泛报就是误报）。时间戳型会话 ID 与无状态防缓存令牌是主要命中面。
- **存储型 XSS 通道**（`xss-stored` / `xss-stored-raw`）。反射通道看的是
  「同一响应回显」，存储通道看的是「写进去、别处读出来」——DVWA 的
  XSS (Stored) 模块（guestbook）对反射通道必然零命中。探针只写无害标记
  （随机段，不含脚本语法），判定标记是否跨请求持久化回显；再看回显
  上下文（`<script>` / 事件属性 / js 赋值）判可执行性。仅满足持久化、
  不可执行的按 `xss-stored-raw`（前置项）报 medium，不夸大成完整 XSS。
- **敏感页缓存卫生**（`cacheable-sensitive`）。会话 / 账户类页面缺
  `Cache-Control: no-store/private` 时，内容可被共享缓存或浏览器回退键
  命中。归 verified（CWE-525），不是 hygiene——它是对可见敏感页的实际
  暴露判定。同站同类只报一次。

### 修复

- **CSP 只评首页导致整块漏报**。`security.Assess` 此前只吃首页响应头，
  而 CSP 是**逐路径**策略——DVWA 只在 `vulnerabilities/csp/` 上设 CSP 头，
  首页没有。结果是「有策略但策略可绕过」这一类的漏洞在整站扫描里必然漏掉。
  改为首页无 CSP 时横扫已采集页面取首个带 CSP 的响应做指令级分析；
  同 URL 同指令去重，防多处追加刷屏。
- **无字段的 POST 表单被丢弃**。`collectFormSignals` / `collectForms` 此前
  在「无可注入字段且无文件字段」时直接跳过，而 DVWA Weak Session IDs 模块
  就是 `<form method="post"><input type="submit"></form>`——没有字段、
  没有密码框，提交后却下发 `dvwaSession=<递增整数>`。这类表单现在会进入
  状态变更探测队列。
- **`dast.Resp` 补 `SetCookies`**。httpx 有意把 Set-Cookie 单条保真存放、
  不并入 `Headers`，而引擎的 DAST 适配器只转发了 `Headers` ——弱会话 Cookie
  判定拿不到值。已补转发。

### 配置

- `dast.random_diff` / `dast.stored_xss` / `dast.cache_hygiene` /
  `dast.weak_cookie`（默认全开），与 `dast.deep_probes` 总闸联动。

### 回归

- 新增 `internal/dast/extend_test.go`：低熵形态 10 例、随机差分三形态
  （时间戳命中 / 强随机不报 / 稳定标识不报）+ 总闸关闭、命令注入回显
  命中与字面量回显不报、存储型 XSS 脚本上下文命中 / 纯文本不判可执行 /
  被过滤不报 / 总闸关闭。
- `internal/engine/cache_hygiene_test.go`：缓存判定与敏感页识别。
- 新增 check id 全部登记 CWE 映射。

### 覆盖率：探测点丢失修复 + 报错状态通道

> 靶场实扫暴露的两处「本该命中却没命中」，都不是探测面宽窄问题：
> 一是探测点被覆盖丢掉，二是报错只回通用 500 页（无数据库报错特征回显）。

- **修复：首页/种子采集的带参探测点被爬取结果覆盖丢失**。爬取分支里曾写
  `dastLinks = cr.ParamLinks`，覆盖了此前从首页 GET 表单合成、以及带参种子
  登记的探测点。`cr.ParamLinks` 只收被反解析为 `<a href>` 的链接，而
  「参数藏在 GET 表单里」的入口（Acunetix testasp 的 `Search.asp?tfSearch`）
  不在其中——首页采集完就在这一步被整块丢掉，参数级注入测不到。改为并入
  （append）而非覆盖。实测 testasp：`Search.asp?tfSearch` 从 0 命中到
  3 条（反射 XSS + 报错 SQLi + 布尔盲注）。DVWA 线上实测 9 条命中不变
  （其参数都在 `<a href>` 里，本就不受此 bug 影响）。
- **新增：报错状态差分通道**（`dast.error_status`，默认开）。注入引号后响应
  由 2xx/3xx 翻为 5xx 即判定报错型注入——覆盖只回一个通用 500 页、正文里
  没有任何 `sqlErrors` 特征的目标（特征表再宽也命不中的那类）。基线须健康
  （<400）才启用，站点本身 5xx 时不报，防漫天误报。

### 深度探测面：注入通道扩容

> 在 v5.0.1 主动探测面加深（PR #26：探针序列化 + 多形态 + 特征表 15→29 +
> 表单布尔盲注）之上的**纯增量层**：新增 SSTI（含表达式注入）/ 命令注入 /
> CRLF / NoSQL / XPath / LDAP / JNDI(Log4Shell) / XXE / 上传受理面 /
> Cookie-头注入通道，遍历编码扩到 6 形态 × 4 文件。由 `dast.deep_probes`
> 总控（默认开）。兼容性：原有 check id 与证据链字段不变；新增 check id
> 已登记 CWE 与 impact 归类。

### 新增注入通道（`deep_probes`）

- **SSTI**：四族模板语法探针（Jinja2/Twig、JSP EL、Ruby EL、ERB/EJS），
  唯一算术乘积回显确认；表达式注入（SpEL/OGNL/EL）另认解析报错特征。
- **命令注入**：分号/管道 sleep 形态**时间差分** + 双确认（critical），
  不执行破坏性命令，只 sleep。
- **CRLF 响应头注入**：判定只看响应头集合新增名，不看正文。
- **NoSQL / XPath / LDAP**：操作符或引号注入触发数据层 / 解析层报错回显。
- **JNDI（Log4Shell）**：`${jndi:}` 注入的解析特征。
- **XXE**：POST XML 体外部实体展开特征。
- **上传受理面**：提交无害文本文件判定是否受理（非绕过验证）。
- **Cookie / 头注入**：Cookie、User-Agent、Referer、XFF 通道的报错 SQLi / 反射 XSS。

### 遍历多形态扩面

- 文件面：`/etc/passwd`、`windows/win.ini`、`/etc/hosts`、`boot.ini` 跨平台。
- 编码面 6 形态：原生 `../`、双写 `....//`、URL 编码 `%2e%2e%2f`、绝对路径、
  混编 `..%2f`、双重编码 `%252e%252e%252f`。

### 请求有界

- 新增单类探针上限 `MaxProbesPerClass`（默认 12），核心四类的遍历与深度面
  各家族都按它截断；进度条总长与测试上界共用 `maxURLRequestsPerParam` /
  `maxFormRequestsPerField` 两个口径函数，避免探针表与预算两处漂移。


### 扫描型缺陷修复 + 探测面加深（v5.0.0 靶场评测驱动）

> 靶场基准评测（v5.0.0，460 条真值 / 6 TP / R_in 13.0%）暴露的扫描型缺陷
> 集中修复：SQLi 盲注通道失效、表单 POST 探测过浅、脏数据污染口径、
> 登录爆破不认表单。全部改动只影响探测面与结果分类，不改变已命中判定的
> 语义；`verified` 里不再混入配置卫生项（独立到 `extras.hygiene`）。

### 种子 URL 路径/查询串保留（带参入口可达性）

- **根因**：`engine.go` 扫描起点把入参 URL 退化为 `scheme://host`，
  路径与查询串被丢弃。以 `/Less-1/?id=1` 或 `/vuln.php?id=1` 这类带参
  页面为入口时，引擎实际只扫站点根，参数级注入在"单入口深扫"场景
  整块测不到（实测 sqli-labs 等靶场从此前 0 命中）。
- **改法**：保留种子 URL 的 path + raw query 作为首采目标 `seedURL`；
  种子带参时把自身登记为 DAST 探测点。`baseURL`（host 根）仍用于
  目录/指纹等宿主级检查，既有行为不变。
- 新增回归 `TestSeedPathQueryPreserved`：无修正时失败、修正后通过。

### DAST 布尔盲注：字符串型上下文可命中（sqli-labs 0/10 → 10/10）

- **根因一（通道单一）**：`boolPayloads()` 对纯数字原值只构造
  `1 AND 1=1` / `1 AND 1=2`，拼进字符串型上下文（`WHERE id='$id'`）后被
  MySQL 弱转为数字 1，真/假响应尺寸完全一致。改为多通道候选：数字型 /
  引号闭合型 / 乘法差分型（数字原值），单引号 / 双引号闭合型（字符串原值）。
- **根因二（阈值过严）**：`BoolBlindSizePct=10%` 判不出字符串型注入的真/假
  差异（实测 721B vs 670B = 7%）。相似阈值放宽到 15%，判别力改由
  「真/假离散度 ≥ 5%（`BoolBlindDiffPct`）」提供——真分支仍必须贴基线，
  内容随机化站点在第一轮就被否掉，误报防护不降级。
- 每次布尔探测改用 `chainEvidence()` 补齐 Request/Response/Signals，
  证据链与其余通道同规格。

### 表单探测加深（DVWA / pikachu 的 id 类参数）

- **首页表单即刻采集**：表单/链接采集此前困在 `deep` 分支内，quick /
  standard 档位下「首页就是注入表单入口」的站点（DVWA 登录页与
  SQLi/XSS 模块）攻击面完全不可见。现抽出 `collectFormSignals`，
  首页在任何档位都采集。
- 新增表单字段布尔盲注通道（`internal/dast/formblind.go`）：报错不回显的
  POST 表单此前零产出，现在走真/假尺寸差分 + 双确认，共用同一阈值语义。
- 表单探针从「单探针 × 4 类」扩到探针序列（XSS 3 条 / 报错 SQLi 4 条 /
  重定向 3 条 / 遍历 5 条），每类首个命中即短路。

### 探针面扩宽（提升覆盖率）

- 目录遍历：命中特征扩到 passwd / win.ini / 绝对路径多形态；探针加
  `....//` 双写、`%2e%2e%2f` 编码、绝对路径、`..%2f` 混编五种绕过变体。
- 报错 SQLi：特征表从 15 条扩到 29 条，覆盖 MySQL/MariaDB/PostgreSQL/
  Oracle/SQLite/MSSQL/PHP 警告七族。
- 开放重定向：探针加绝对 URL 与反斜杠变体（`\/\/`）。
- 反射 XSS：探针加 `<script>` 标签突破与 `javascript:` 协议突破。

### 深度探测面新增（v5.1 探测面家族扩容）

核心四类（XSS / SQLi / 重定向 / 遍历）之外，新增九类主动注入家族，
全部沿用同一套「探针序列 + 类内首个命中短路 + 证据链」语义：

- **SSTI**：四族模板语法（Jinja2/Twig、JSP EL、Thymeleaf、ERB/EJS）×
  唯一算术乘积 `7393*8453`，回显 `62500029` 即命中（区别于单纯回显原式）。
- **表达式注入**（EL/SpEL/OGNL）：求值回显 + 解析报错特征双通道。
- **命令注入**：分号/管道/反引号/`$()`/换行等分隔符 + `sleep` 时间差分
  **双确认**，critical 级；只 sleep，不执行任何破坏性命令。
- **CRLF 响应头注入**：参数注入 `%0d%0a` 后响应头集合出现注入头即命中。
- **NoSQL 注入**：操作符注入触发数据层报错（Mongo/BSON/Redis 特征）。
- **XPath 注入**：引号闭合触发 XPath 解析异常回显。
- **LDAP 注入**：通配/括号注入触发 LDAP 解析报错回显。
- **JNDI（Log4Shell）**：`${jndi:...}` 注入触发 JNDI 解析特征（critical）。
- **XXE**：POST XML 体引用外部实体，正文出现文件内容特征即命中。
- **文件上传受理面**：对 `input[type=file]` 表单提交无害文本文件，
  依据受理/拒绝信号判定上传面是否存在（**非绕过验证**，medium 级）。
- **Cookie / 头注入通道**：`Cookie` / `User-Agent` / `Referer` /
  `X-Forwarded-For` 值注入，命中报错 SQLi 或反射 XSS——补齐 sqli-labs
  Less-24/42~45 这类「注入点在头里」的入口。

防误报：报错特征一律与基线求差（页面固有回显不算）；标记匹配排除
「标记本就是探针自身字面量」（反射回显不再被误判为解析报错）。

总闸 `[dast] deep_probes`（默认开），命令注入单列 `cmd_inject` 可关，
单类探针上限 `max_probes_per_class` 防重类吃满预算。新增 check id 全部
登记 CWE 与 impact 映射。CLI `scan` 此前**漏开 DAST**（只有 serve 的
档位预设开了），命令行扫描永远拿不到参数级发现——一并修复。

### 表单弱口令审计（登录爆破不认表单的根因）

- `weak_audit` 此前只对目录探测发现的 HTTP Basic 401 路径爆破，**表单
  登录口令完全没覆盖**——DVWA / pikachu 的爆破因此零产出。现从爬取阶段
  收集含密码框的表单页，逐个走 `loginbrute.Brute`（`weak-login-form`）。
- `isSuccess` 强化：302/303/307/308 重定向优先判成功（DVWA 成功登录返回
  302 + 空正文），但跳回登录页（Location 含 login/signin）仍判失败。
- `Brute` 组合生成修溢出：内层 `break` 只跳出密码循环、外层继续叠加，
  实际请求数会突破 `MaxTries` 硬上限（安全护栏失效），两层都看预算。

### 脏数据清理：配置卫生与漏洞验证分离

- **跨页去重**（`passive.Deduper`）：`cookie-attrs` 与 `csrf-form` 是站点级
  配置事实，逐页上报在 24 页站点产出 48 条重复（实测 DVWA 52 条 FP 中的
  48 条）。现在同一 cookie / 同一表单全站只报一次。
- **`extras.hygiene` 独立成列**：配置卫生发现不再混进 `verified`，避免
  同时拉低严格口径准确率（当误报）与召回口径（稀释分母）。前端「配置卫生」
  区块、Markdown 报告同步分列。

### 兼容

- `verified` 键位与既有条目形态不变；`extras.hygiene` 为增量字段，旧消费方
  无感（不读即忽略）。ML 管线的 `src` 词表未变（hygiene 条目不再进
  `verified` 表，`prior_verified_count` 计数随之更干净）。
- 新增 `dast.bool_blind` / `dast.max_url_len` 显式出现在示例配置（此前
  有默认值未列出）。

## v4.0.1（2026-09-20，修复版）

> 纯修复版：四路代码评审（引擎与攻击链 / 服务端与前端 / 桌面壳与工具 /
> 近期改动走查）+ 分诊确认后修复 20 项。无新功能、无数据迁移、无配置变更。
> 已知未修（分诊判定收益/风险后暂缓）：applySettings 与进行中扫描对同一
> 配置对象的并发读写、多更新源场景下的下载源选择、Wails 启动页计时时基。

### 事实图与攻击链

- `evidence_link` 建边对 dataflow 端失效，白盒关联结果无法进入链视图。
- SSRF 出带命中产出零证据 positive vuln_node，违反「有节点必有证据」硬约束。
- 爬取阶段的带参链接与表单未进入入口点收集，入口点攻击面缺失。
- 历史归档淘汰与 ClearAll 空历史两条路径不清理 `graph/<id>`，图目录累积泄漏。

### 引擎与资源

- 内存超预算时 Nuclei 模板上限减半是空操作，降档实际不生效。
- ReleaseIntel 与在跑扫描 / 热替换对知识库无锁并发读写。

### 服务端与前端

- API Token 模式下审计上传、攻击链页、删除历史、导出按钮绕过鉴权头全部 401。
- 登录爆破作业取消不生效（进度回调覆写取消状态，且引擎侧无取消钩子）。
- 攻击链页首次进入不加载（默认选项只改标签未写入下拉值，刷新按钮同样失效）。
- 批量扫描取消按钮一次性失效（startBatch 不复位）。
- 设置页 OSV 轮询用 clearInterval 停包装句柄，1.5s 轮询永久泄漏。
- OSV 同步失败被 defer 覆写为「同步完成」，状态灯误报成功。
- 历史对比视图技术版本号未转义直接 innerHTML（XSS）。

### 源码审计

- 上传闸门 8MB 与规则扫描 512KB 不一致，中段文件计入「已扫描」却零发现。
- 目录拖拽 zip 顶层目录名重复，文件树出现双层同名目录。

### 桌面壳与工具

- Wails 壳退出不杀引擎进程树，log.Fatal 路径泄漏引擎进程。
- Wails 主窗口跨 goroutine 无同步读写（托盘「显示主界面」冷启动期失效）。
- writeUserConfig 在 YAML 损坏时整文件清空重写，用户引擎配置静默丢失。
- tools/release_upload.mjs 缺省版本号依赖运行目录，非仓库根运行即崩溃。

## v4.0.0（2026-09-18，黑白盒安全分析 + 攻击链还原）

> 4.0 主线：从「单点漏洞验证」升级为「黑白盒安全分析 + 攻击链还原」。
> 详细设计与逐阶段记录见 `docs/开发文档-4.0.md`（主基准文档）。

### 结构化事实模型（P1-P2）

- 新增 `internal/model`：统一数据模型十类实体（入口点 / 漏洞节点 / 证据 /
  黑白盒关联 / 数据流 / CWE 关联 / 链节点 / 链边 / 权限变化 / 影响），
  全部具备**确定性稳定 ID**（内容哈希，同事实重扫不变）与 schema 版本
  `sitelens.graph/v1`，可序列化为 graph JSONL。
- 黑盒结果结构化（opt-in，`scan.graph` / `-graph`）：扫描的入口点、各类命中
  （check / Nuclei / 被动 / DAST / JS）、证据链、影响，收集为图实体；
  **默认关，3.0 JSON 输出逐字节不变**。

### 白盒源码分析（P3）

- 新增 `internal/astx`：基于 tree-sitter 的 AST 分析（Python / JavaScript /
  PHP / Java / Go），产出函数清单、调用关系、source/sink 与**函数内数据流**。
  CGO 以 `//go:build cgo` 隔离：无 C 工具链时自动降级为行级规则（不报错）。
- 源码审计（`-ast`）在既有规则之上**附加** AST 污点发现，原规则保留兜底。

### 黑白盒证据关联（P4）

- 新增 `internal/correlate`：把黑盒发现与白盒数据流按 **参数名 / 路径 / 技术**
  建立 `evidence_link`（自动关联最高给 probable，不给 confirmed）。

### CWE 关联（P5）

- 新增 `internal/cwe`：check id / 规则 id / CVE 三源 → CWE 的统一映射。
- NVD 同步恢复 weaknesses 字段（CWE），新增**年度 feed 模式**
  （`update-nvd feed`，CI 无 key 限速下比逐页 API 快得多）。

### 攻击链 / 权限变化 / 影响（P6-P7）

- 新增 `internal/chain`：**证据驱动**建链——`sequence` 边只连「入口点 → 落在该
  入口上的发现」（真实因果），无证据的候选边不建（计入 skipped）；
  情报节点保留为上下文但不参与串联。不回显任何无证据的推测路径。
- 权限变化三类机制实体化：`bypass-403` / `credential` / `exploit-proven`；
  影响带 KEV/CVSS **先验标注**（仅解释、不参与建链）。

### Store / API / 视图（P8）

- 结构化事实图**独立落盘**（`data/state/graph/<id>/`），扫描历史
  `history.json` 格式不变。
- 新增 API：`GET /api/graph/{id}`（摘要）、`/jsonl`（导出）、`/chain`（攻击链视图）。
- 新增「攻击链」页（侧栏入口），可视化入口/发现/数据流/CWE/影响/权限变化与关系边。

### 数据接口（P9）

- Schema 契约文档 `docs/schema-graph-v1.md`；Go 参考读端 `sitelens graph-read`
  （摘要 / `--self-test` 契约自检）。graph JSONL 为语言无关的公开接口，
  供 5.0 ML 直接读取。

### 资源治理（Track A A1-A10，2026-09-16）

- A1 GC 软上限（`internal/resource`：SetMemoryLimit 1GiB + GOGC 70，幂等可关）；
  A2 NVD 条目瘦身（6 字段→仅 VP 区间，文件版本 v2→v3，版本边界字段核实零消费方）；
  A3 情报惰性解码（NVD 只记路径，首次取数才解码；HasNVD/NVDCount 不触发）；
  A4 扫描结束 `FreeOSMemory` 归还 OS；A5 惰性解码推广；A6 nuclei 编译缓存；
  A7 内存预算器（768MB 三级降档）；A8 驻留记录上限裁剪；A9 GUI 轮询治理
  （slPoll 降频）；A10 进程内情报释放（86→17MB）。
- **实测达标**：引擎空闲 RSS 977MB→**129MB**（目标 ≤300MB）；full 模式峰值
  934MB→**796MB**（目标 ≤800MB）；扫描时长 A/B（治理开/关同机 5 轮交替）
  13.90s vs 13.98s，差异在噪声带内，**≤5% 指标达标**。
- 真 bug 修复：情报库 Release 热重载丢数据（Load 无路径 + sync.Once 不可重入 +
  模板/覆盖不重放）——改双检互斥 + 重放，`TestReleaseReplaysTplAndOverrides` 锁死。
- 测量旁路：`SITLENS_RESOURCE_OFF=1`（仅 A/B 实测用，产品路径不感知）。
- **发版实测撤销 A9 的 `in-process-gpu`**：4.0.0 打包时 Electron 解析为新拉取的
  44.3.0，该组合在本机表现为「渲染层正常（CDP 截图/DOM 全对）但屏幕合成全白，
  且主进程随之静默退出」——正是 A9 注释里写明的取舍（GPU 崩溃带走主进程）。
  撤销后恢复独立 GPU 进程（进程 3→4，常驻 +37MB；GUI ≤250MB 目标本已按实测
  封存）。修复验证：物理屏幕窗口区域像素实测 12.9% 文字暗像素（白屏时 ≈0%）。

### P10 测试 / 回归 / 性能 / 靶场实扫

- 桌面引擎补齐 AST：build-engine 三级策略（本机 gcc→CGO；WSL+mingw 交叉；
  皆无则降级告警），包内引擎含 tree-sitter。
- graph 构建性能 −14.19%（`internal/engine/graph_perf_test.go` 中位数基准固化）；
  DVWA 实扫产图（58 技术 / 4 verified / 52 vuln_node / 18 cwe_rel / 2 链边，
  均带证据）；CI 增加 graph 契约断言；情报补账 priors 接入扫描主流程。

### 前端全站重构（25 系列，2026-09-16~17）

- **Turbo Drive SPA**：@hotwired/turbo 8.0.13 本地化，九页接入，页面切换
  零整页重载；common.js 分层重构（一次性区守卫 / 每渲染区重建 / slPoll 跨页清理）。
- **布局定稿（text-well 双区）**：单顶带（模式行+状态+被动页导航+亮暗+版本）+
  可拖分割条左控制栏 + 右画布；**同款侧边栏单一来源**（`modeRowHTML()` 一份数据
  渲染工作台与被动页）；窄左栏容器查询收纯图标；aria-current 无障碍态。
- **25A 源码审计升级**：Monaco Editor 官方 min vendor 入仓（零 CDN 零外网）+
  文件树（目录折叠/无预览置灰）+ findings 标注联动（severity 行标 + 波浪线 +
  点击跳行居中闪烁）；审计响应带 sources/contents **全量回传**（拒绝截断，
  二进制剔除，8MB 读入上限）；**文件夹上传**（选目录 + 拖目录，JSZip 页内打包，
  互斥 + 预加载 + settle 即作废重查 + 版本号击穿缓存的加载加固）。
- **25B 七页体验**：批量任务队列表格（后端逐 URL rows 实时）/ 网络层检测卡片网格 /
  历史统计卡+时间筛选 / 情报库防抖即搜+严重度筛选 / 登录爆破导出命中 CSV /
  攻击链复制 JSON / 设置搜索 + exploit 危险警示。
- **25C 动效基准（Corporate）**：全站动效 tokens（150/250/400ms +
  cubic-bezier(0.2,0,0,1)），列表级联入场、顶带下划线展开，
  `prefers-reduced-motion` 全站降级。
- **登录爆破**：实时尝试计数面板（引擎逐次上报 done/total，当前凭据打码显示）；
  三个存量 bug 修复——无验证码档误发 captcha_field 致全部尝试被跳过、
  pollJob 用 clearInterval 停不掉 slPoll 句柄（永续泄漏轮询）、
  命中表从不渲染（完成后再取 /results）。
- **视觉**：暗色中性化（slate 蓝调→中性灰阶 #0d0d0f 系，正文对比 16.49:1，
  辅助字 7.04:1）；冗余灰色提示精简 7 处；化石页收编（/audit、/batch 独立页
  删除，302 → 工作台页签，「载入演示样本」死按钮真除）。
- **启动页 v2「对焦」**：透明无底板挂件，准星环绕 logo 画出 + 四刻度落定 +
  描边字收紧至 0.9s + 两段式退场 + reduced-motion 终态直取（Electron 与
  Wails 壳同源双宿主）；**最低展示 1.9s**——暖启动引擎 ~300ms 就绪时动画
  不再被掐断（用户实测反馈），补齐入场全序列后才退场（实测生命周期 ~2.2s）。



### 桌面端安装修复（原 3.0.1，并入本版）

原计划的 3.0.1 补丁版两处修复并入 4.0.0 一起发布（下面两节）。

### 管理员安装后引擎启动失败（EPERM）修复

- **症状**：安装包装到 `D:\Program Files\SiteLens`（或任何受 ACL 保护的目录）后，
  用管理员安装的机器上启动即失败，日志只有一行
  `engine failed: Error: EPERM: operation not permitted,
  open '...
esources\engine\.sitelens.yml'`，引擎始终起不来。
- **根因**：桌面壳把**引擎配置** `.sitelens.yml` 写在**安装目录**里。程序文件目录
  本应只读（Program Files 对普通进程无写权限），首启写配置即被拒。
- **修复**：配置改落**用户数据目录**（`%APPDATA%\SiteLens\.sitelens.yml`），并以
  **绝对路径**经 `-config` 传给引擎；安装目录不再承担任何运行期写入。旧版遗留在
  安装目录的配置（带壳标记）自动迁移一次，用户改过的引擎键不丢。
- **配套**：`intel.overrides_path`（设置页保存 / `update-osv` 会写）默认值原为相对
  安装目录的 `data/intel_overrides.json`，一并归一到数据目录，消除同类隐患。
- **顺带修复**：开发模式（未打包）下引擎目录解析——旧实现只认仓库根，而
  `npm run engine` 的产物在 `desktop/engine/`，导致源码启动报「引擎程序缺失」；
  现优先仓库根（存在引擎程序时），否则回退 `desktop/engine/`。
- 回归：新增 `desktop/test/engine-config.test.js`（配置落点/旧配置迁移/引擎目录解析）
  与 `internal/config` 的 overrides 归一断言。

### 引擎构建平台修复 + 发版改本地（同批发现的更严重问题）

- **发现**：排查上述 EPERM 时发现，CI 的 tag 流水线跑在 Linux（`golang:1.26.8`），
  而 `desktop/build-engine.js` 执行的是**不带 `GOOS`** 的 `go build`——打出的
  「`sitelens.exe`」**实为 Linux ELF 二进制**（`^?ELF`，非 Windows `MZ`/PE）。
  装进 Windows 安装包后引擎根本无法运行。该问题被上面的配置写入错误掩盖。
- **修复**：`build-engine.js` 显式 `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`，
  并在构建后**校验 PE 魔数**（非 PE 直接失败）——错平台二进制不再能静默入包。
- **发版流程改本地**：CI 的 `v*` tag 自动构建已停用（原配置保留为注释）；
  统一走 `tools/release_local.sh`（构建引擎→PE 校验→打包 NSIS→可选上传 CNB）。
  本地在 Windows 构建，产物必为 PE 且可即时验证。
- 回归：`tools/ci_pipeline_guard.test.mjs` 感知流水线停用状态——停用时
  **明确跳过**（非静默通过），一旦重新启用断言立即恢复生效。

## v3.0.0（2026-09-12，利用器）

### 非 HTTP 协议检测（3.0 主项一）

- 新增 `internal/netx` 原始拨号层：TCP/TLS/UDP/DNS 收发，读写 deadline +
  单次读取上限 + send/recv 轮次上限；TLS 客户端基线最低 1.2
- `internal/target` 新增 ValidateHostPort 非 HTTP 协议闸：协议白名单
  （tcp/tls/udp/dns）+ 字面 IP 无条件拦截 + 域名受 resolve 开关逐 IP 校验
- 模板漏斗准入协议族：tcp（payloads/data+hex/banner 读取）、dns（name/type）、
  ssl（证书摘要串）三类形态转 NetCheck；匹配器支持 word/regex/binary/dsl
  （`response` 变量经 CompileWithVars 注入，零改 dsl 包）；索引缓存 v6 → v7
- `update-nuclei` 镜像范围扩 network/dns/ssl 顶层类别
- 引擎 stage9 接协议扫描段：serviceprobe 探得端口按「模板声明端口 = 探测
  端口」路由，dns 模板查目标域名；命中落 Extras["netproto"] 并入实时事件流

### 利用级无害验证（3.0 主项二）

- 新增 `internal/exploit`：对 DAST 已验证发现做「影响证明」，判定诚实分级
  none / observed / proven
- 四通道：回显（唯一标记未转义复现）、报错指纹（DBMS+版本提取）、时延差
  实测、出带回连（进程内 beacon）；LFI 泛化读取（/etc/hostname）
- 授权三重闸：请求开关 × config `exploit.enabled`（默认关）× 目标白名单
  （`*.domain` 只匹配子域不含父域，从严）；验收断言：未授权目标零请求
- 命中回填 verified 条目 impact / impact_evidence，汇总落 Extras["exploit"]

### 验证回归（3.0 主项三）

- 新增 `internal/replay`：按原 payload 单请求重放历史发现，present / gone /
  unsupported 三分，unsupported 不进回归分母
- `sitelens regression <scan_id>` 子命令：批量重放，退出码表达回归
  （0=无回归，1=存在回归）；`GET /api/replay/{id}` 端点同能力
- `tools/regression_nightly.sh` 加重放门禁，退出码并入总断言
- DAST verified 条目补 payload / replay 键（证据链完整化，重放输入就位）

### 数据规模全面扩容

- 模板池七来源：官方 http+协议族 / afrog / Wordfence / linuxadi 40k /
  coffinxp / 极致攻防 / 自研协议精选，全库可运行 **117,889 条**（cap 全量）
- 指纹库 372 → **13,727**：update-fp 并入 webappanalyzer（GPL-3.0）2,377 条
  + update-ehole 并入 EHole 中文产品 10,978 条（exact 字面量通道 +
  headers 通配 + 字面量前缀桶预筛，指纹匹配 413ms → 24.2ms/页）
- update-nvd：NVD CVE 字典 **371,755 条**全量镜像（评分补全 / CPE 检索）
- update-tplintel：模板情报行 **29,554 条**（覆盖 10,289 产品）并入三级判定
  主索引，漏洞情报合计 **31,539 条**，全部公开来源
- 自研协议模板精选包六件：memcached / ftp / ssh / vnc / smtp / mysql
  （banner 级只读，官方零重复）

### 桌面版（新增）

- Electron 壳（desktop/）：独立窗口 + 托盘常驻 + 单实例 + 自动更新
  （electron-updater generic 源，blockmap 差量下载，引擎二进制随包整体升级）
- 数据布局产品化：扫描历史/模板池/插件/可变情报全部落 %APPDATA%，
  安装目录只放只读资产——自动更新与卸载永不伤用户数据；
  首启按缺失补拷内置种子（NVD 全量 37MB + 情报行 + 指纹规则），
  首开即完整体验，仅模板池（719MB）在线拉取
- 可用性：控制台地址固定 127.0.0.1:5087（被占用才换并持久化）；
  引擎崩溃自动重启（5 分钟窗口 3 次上限 + 指数退避）；关窗收托盘
  继续扫描；托盘含打开数据目录 / 开机自启 / 检查更新
- 引擎零改动：全部行为经引擎既有配置面（默认值 + yml 部分覆盖）
  实现；子进程管理独立 engine.js（spawn 首参纯字面量，安全门槛达标）
- 排障面：壳与引擎输出分别落 desktop.log / engine.log（1MB 滚动）
- E2E 实测通过：3.0.0 → 3.0.1 本地 feed 全链路（检查→差量回退全量
  下载→静默安装→自动重启→版本递增→用户数据原位存活）
- CI：tag 推送自动出桌面包并双发布（版本 release + desktop-stable
  更新源），客户端自动更新链路通电

### Bug 修复

- dsl PositiveGround 回归：解析器把内置 host 变量误标为抽取变量，
  `contains(host,"x")` 被误判为正向命中依据（纯排除式模板漏进调度池空转）；
  known 现仅标抽取变量
- 指纹加载器加固：单条 RE2 不兼容模式跳过，不再中断整个扫描进程
- internal/rex 受限回溯正则引擎：RE2 拒收的 702 条服务指纹模式
  （环视 683 / 反向引用 16 / 超界重复 1）由 rex 兜底承接，匹配全程
  10 万步预算封顶防灾难性回溯；服务指纹恢复全量 11,966 条有效，
  与 python re 独立实现 golden 交叉验证 5,469 用例全一致
- 二轮复扫收口：软 404 基线剔除口径单点归一（探针侧路径补前导斜杠，
  catch-all 回显站残留 '/' 导致的前缀失配误报消除）；beacon 预订表
  封顶 FIFO + Reset 连带清空 + 回连记录 30 分钟 TTL（长驻进程内存
  有界、已重置 token 不能复活命中）；SSRF 收窗先查后睡、全命中即收；
  时间盲注证据链补 Request 字段与 boolBlind 同规格；验证码识别
  Health 探测双候选容错（不再依赖 /ocr 后缀猜测）；并发进度回调
  包内串行化（消费者无需自行加锁）
- 扫描热路径索引只读化（IndexCached）：模板情报挂载不再于扫描中触发全库
  漏斗重建（单次扫描超时修复）
- 指纹匹配性能：13,727 规则下 413ms/页 → 24.2ms/页（前缀桶单遍预筛 +
  ToLower 提升 + exact 关键词通道），bench 固化
- NVD 全量镜像进度按页粒度输出（长任务不再静默无输出）

## v2.0.0（2026-09-11，验证器 正式版）

### 前端扫描执行细节升级（正式版主项）

- 结果页新增「最值得关注」摘要卡：按严重度 × 二次确认 × 证据强度排序 Top3，证据 n/5 计数
- 已验证发现行升级为证据链面板：复现命令 / 请求 / 响应快照 / 信号 逐项展开 + 复制按钮
- 扫描执行阶段 7 → 11 段（Nuclei / DAST / 目录 / WebShell / 被动独立可见）
- 扫描选择器重构：范围（Web/子域/端口服务）× 验证（被动/主动/深度盲态）× 强度（快速/标准/完整）三维合成，apocalypse/stealth 等炫技预设退出 UI
- 实时动态面板：引擎事件流（命中/绕过/认证）扫描中实时滚动与计数

- **认证深化（P2）**：auth 配置段（login_url/user_field/pass_field/
  凭证/成功标记），扫描前自动登录并捕获会话 Cookie 全扫描复用
  （爬虫/DAST/目录探测共用认证态）；httpx 新增 SetCookie/SetTimeout
- **布尔差分盲注（P1）**：boolBlind——真 payload（AND 1=1）响应与基线
  相似 + 假 payload（AND 1=2）显著偏离，双向差分 + 双确认；数字型/
  字符串型双 payload；config dast.bool_blind 默认开。修复尺寸相似度
  整数除法截断（10.75% 被算成 10%）
- **SSRF 出带回调（P4）**：内置自托管 beacon（/b/<128 位随机 token>，
  进程内注册表），dast 把 beacon 地址注入候选参数，目标回连即出带确认；
  默认关（ssrf.beacon_enabled），base 指向目标可达的扫描器地址
- **靶场回归门禁（P3）**：tools/regression_nightly.sh——起农场→
  认证态矩阵跑批→零误报 + 真实命中双断言→拆场，退出码接入 CI
- **反序列化入口面探测（2.0 补缺）**：注入 Java 序列化魔数（aced0005），
  响应出现 StreamCorruptedException 等处理链特征即报低危面信号（保守判定）
- **DAST 证据链贯通**：dast Finding 新增 payload/replay 字段，全部探针
  命中（反射/盲注/SSRF/反序列化）带 curl 复现命令
- **docs 收敛为产品文档**：移除内部分析元数据（对比借鉴/迁移对照/
  矩阵报告/靶场明细 6 件），仅保留产品说明与开发文档
- **README 重写**：beautify 风格（居中头部/徽章/emoji 分区/能力矩阵/
  模式表/路线图/合规声明）
- **证据链（2.0 地基，第一块）**：每条验证发现新增四件套——重放请求文本
  （HTTP 报文形态）、响应快照（状态码/尺寸/命中正文摘要）、通道命中信号明细
  （词/正则/头/dsl 逐项）、curl 一键复现命令（POSIX 单引号转义，与引擎
  -sk --path-as-is 姿态一致）；Hit.confirmed 标记二次确认语义。证据链贯穿
  JSON 导出/HTML 报告（复现命令折叠块）/结果页（复现折叠）。运行时头
  （UA/Cookie）不落证据，避免会话敏感信息进报告

- **403/401 绕过探测升级**（吸收同类作品思路后重设计）：目录探测命中 403 时
  从"单次伪造来源头重试"升级为变体表——路径变异（尾斜杠/点段/双斜杠/..;/
  尾空格/尾点编码）× 信任头（X-Forwarded-For/Host、Client-IP、
  X-Custom-IP-Authorization、Referer）× 改写头（X-Original-URL/X-Rewrite-URL，
  请求根路径+声明真实路径，正文含路径段关键词且异于根页才算）× 只读方法
  （HEAD/OPTIONS）。命中技术记入 PageHit.bypass，可绕过路径独立成
  extras.bypass 区块。无害化红线：仅 GET/HEAD/OPTIONS，不发写方法；
  单扫描绕过请求总量硬上限 60。防御强化：path/header 变体命中须异于根页
  尺寸（catch-all 站点回根页不算绕过）
- **favicon mmh3 指纹（FOFA icon_hash 通道）**：murmur3 x86_32 纯 Go 实现
  （与官方 mmh3 C 实现逐位锚定）+ FOFA base64 换行语义（codecs.encode
  等价，76 字符换行）；指纹规则新增 icon_hash 通道，内置 GitLab/Grafana/
  Jenkins/Tomcat/WordPress 五条真实哈希；引擎每扫描采集一次 /favicon.ico
- **模板漏斗三前端**：path 形态（原有）+ **raw 请求形态**（官方 nuclei 库
  大量模板/新版 afrog/TscanPlus POC——此前全部静默拒收）+ **afrog 经典
  形态**（rules+expression，纯 && 链同请求合并/纯 || 链拆分/混合逻辑拒收，
  多请求 AND 链无法诚实降为单请求 → 宁少报拒收）。修复 path 字段 string
  单值写法被 yaml 层整模板拒收的真实漏检面（strList 双形态兼容）。
  索引缓存 schema v4→v5
- **update-afrog 子命令**：镜像 afrog 社区 POC 库（codeload zip）到
  nuclei_dir/afrog，zip-slip 防御 + 条目/单文件双上限
- **报告导出新增 Markdown 格式**（/api/export/{id}?fmt=md，历史页与结果页
  同步加按钮）；修复 lite/linux 阶段缺 jq 上传静默失败（CI 假绿）与
  full 阶段情报库改源（本仓库 Release 私有资产自取）

### Bug 修复

- **漏检面**：模板 path 字段 string 单值写法被 YAML 解析整模板静默拒收
  （官方模板库大量使用该写法），三前端重构后修复
- **误报**：布尔差分尺寸相似度整数除法截断（10.75% 被算成 10% 越过阈值），
  改乘法比较
- **回归**：主动扫描路径上被动检测与 TLS/DNS 评分模块缺席（重构引入），已补回
- **安全**：govulncheck 扫描出的 8 项依赖漏洞清零（Go 标准库 7 项 + x/text 1 项）
- **流程**：CI 发行说明自动写入（此前为空说明）；NSIS 中文文件名构建崩溃修复

## v1.0.0（2026-09-09，正式版）

- **DVWA 官方镜像认证扫描实测**（ghcr 双容器 + 认证断言门）：full 模式
  命中 LFI（读到 /etc/passwd）与 phpinfo 真实缺陷；apocalypse 9 verified
  残余噪声仅 1 条（已知上游模板问题），矩阵报告更新至 docs/

- **1.0.0 校准基建第一轮**：误报/漏报矩阵报告（docs/误报漏报矩阵报告.md）
  ——干净站零误报断言×2 通过；DVWA 官方镜像认证扫描命中 LFI→/etc/passwd
  与 phpinfo 真实缺陷；修复重定向逐跳校验写死 resolve=true（本地靶场
  一跳即拦的历史遗留）；update-nuclei 子命令（codeload 镜像官方模板库，
  按 HTTP 类别收录约 4355 条）；guard 常量时间比较；连接错误带出底层原因
- 已知差距（1.0 前）：认证态爬虫覆盖（DVWA 仅回 1 页）、第二公开靶场
  镜像获取、上游模板 ID 黑名单

## v0.0.2（2026-09-08）

dsl 安全子集 / 7 扫描模式 / 靶场校准三轮收敛 / 图形安装向导 /
Evidence 自解释等全部条目见下。

## v0.0.2 内容（原"未发布"条目）

- **图形安装向导**：SiteLens-Setup.exe 双击安装——品牌化 WinForms
  向导（选目录→进度条→完成页，深板岩头带+呼吸点词标），--silent
  静默模式供脚本；零第三方工具（.NET 自带 csc 编译），构建链见
  tools/build_installer.py
- **靶场规模回归（lingyun，7 模式全量）揪出并修复两类误报**：
  ① AND-merge 丢弃 status 的"宁少报"写法方向反了——exposure 模板在
  404 回显页仅凭路径子串即误中（apocalypse 单次 15 条假阳性，修复后
  -11）；② 纯状态码组不再转换（任意路径即可命中，漏斗仅 -5：
  5412→5407）；③ stripEcho 补剔去 query 路径变体（Apache 404 回显
  不含 query，路径关键词残留喂给词匹配）
- **Evidence 自解释**：每条命中标注命中原因（词/正则/响应头/dsl
  命中了什么），误报定谳有取证依据（如 zenscrape 的 `[0-9a-z-]{36}`
  万能正则、acme-xss 的 `/html` 子串词，均为上游模板质量问题）
- **扫描模式扩展 4→7**：新增 资产测绘（assets：子域名+接管+目录，
  发现面不跑验证）、隐匿（stealth：浏览器 UA 穿透 WAF+被动检测）、
  **毁天灭地**（apocalypse：全部主动模块+checks:all+nuclei_cap 6000
  全量模板验证，仅限授权目标，UI 红字警示）。`level` 参数服务端落地
  （预设先套、显式键逐项覆盖，与前端 LEVELS 同语义），API/批量用户
  同样可用
- **修复：nuclei_cap 请求参数从未被解析**——api-docs 早已宣称支持
  "调大覆盖全部模板"，服务端却静默忽略（文档-实现漂移）；现请求级
  覆盖真实生效
- **DAST 表单探测**：爬虫采集的表单字段（每表单截取前 16 个字段名）
  纳入参数级无害探测——反射 XSS / 报错 SQLi / 开放重定向 / 目录遍历
  四类判定与 URL 参数同语义（基线求差，页面天然特征不算命中）；
  字段预算并入 dast.max_params；时间盲注暂不覆盖表单（无计时报文，
  如实留作边界）
- **验证引擎同路径请求聚类（§12 P1 落地）**：Method+Path+Body+
  ContentType 相同的 check 共享一次请求，命中后按组一次独立重放完成
  全组二次确认（每条命中仍经独立重放验证，语义不变）。请求数从
  O(模板数) 降到 O(路径数)——Nuclei 子集大量模板探测同一路径，300
  模板典型场景降至 ~30 次请求；对目标更友好，扫描更快
- **子域名接管探测（takeover，opt-in）**：18 服务 CNAME+边缘 404 特征
  双条件判定（GitHub Pages/Heroku/S3/Azure/CloudFront/Shopify/Fastly/
  Netlify 等，取 can-i-take-over-xyz 核验子集）；随子域名枚举产出候选，
  每候选 1 次请求、总量 `active.takeover_max`（默认 50）封顶；命中即
  高/中危发现并给处置建议。§12 改进路线 P1 落地
- Env 接口精简：删除从未被求值器调用的 HeaderValues（头 map 整体包含
  非子集语义，类型错误路径保持不变）
- **修复：htmlx script 块解析 panic（fuzz 实测）**——畸形标签
  `<sCript</sCript>` 使 `</script>` 闭合下标落进标签文本内，
  数据岛切片反向越界（body[16:7]）。爬虫会解析任意站点页面，
  此类输入即可让扫描进程崩溃；现要求闭合下标严格位于标签之后。
  崩溃语料入库作回归；htmlx fuzz 第二轮 8 分钟零失败
- **服务器浸泡 12 连扫**：RSS 38.8→67.3MB 后进入平台期（末三次
  增量 <0.4MB），无泄漏迹象；环回目标被 SSRF 校验正确拦截
  （「目标解析到内网/保留地址，已拦截」）
- **dsl 求值器模糊测试加固**：Go 原生 fuzz 15+8+8 分钟三轮（峰值
  ~30 万 exec/s，累计 >2 亿次执行）。第二轮揪出 worker 进程消亡：
  regex/prog 双缓存对不可信输入无限膨胀致内存耗尽；现已加
  4096/16384 上限（生产端模式来自有限模板库，上限只影响对抗场景），
  另加括号嵌套 ≤64 层与表达式 ≤8192 字符准入。第三轮 8 分钟零失败
  通过，两枚崩溃语料入库作回归
- **修复：MS 公告关联误配洪泛**——cve_ms 34931 条中 1545 条组件名为空，
  反向包含 `Contains(技术名, "")` 恒真，任意技术都能匹配全部空组件
  公告（实测 tools 扫描 21 条漏洞里 20 条是无关 Windows 公告）；
  现要求组件名 ≥4 字符且双向包含均有长度下限，实测同目标 21→1 条
  （保留的一条为真实 Nginx UI CVE 的 possible 提示）
- 爬虫 `crawler.headless_all_pages` 开关：无头渲染默认仅首页，开启后
  扩展到全部已爬页（JS 路由二级页也贡献链接/路由；每页一次浏览器
  渲染，页面多时显著变慢，故默认关）
- 指纹×情报命名对齐 `internal/intel.lookupAliases`：全量比对 370 指纹
  名 × 6511 情报产品名，仅收录经核实同属一个软件的三对别名
  （Microsoft IIS/Yoast SEO/Akamai Bot Manager），命中 91→94，其余
  276 项未命中经核实为情报未覆盖而非命名缺陷
- **dsl 安全子集求值器（internal/dsl，新增第 17 个包）**：Nuclei dsl
  表达式的词法/递归下降解析 + 求值，支持 status_code/body/headers/host
  变量与 contains 族/regex/tolower/len 等函数、比较与逻辑运算；准入
  即拒子集外形态，求值失败一律不命中（宁少报不误报）；纯排除式
  （如 !contains(host,…)）静态判定不转换，杜绝恒真空转 check
- **可运行模板 4701 → 5412（+15%）**：dsl 安全子集接入后全库实测
  5412/11306（其中 768 条含 dsl 匹配器）；累计较原版同漏斗 2613 翻倍
- **修复（latent）：regex 匹配器从未装配**——36c3f8e 起模板的 regex
  matcher 被解析并转换进组，但 g.rx 漏写入 Match.RegexBody，纯 regex
  模板转成无条件 check（对任意响应恒真）；混合模板正则条件静默丢失
- **修复：模板索引缓存永不命中**——缓存有效性误拿「漏斗通过数」与
  「文件总数」比对（5412 ≠ 11306），每次扫描提交都全量重建索引；
  现缓存记录 Files 总数，命中后 3.0s → 0.44s
- MoE 三路调度完整回归 Go 版：tag 硬匹配置顶 + TF 余弦相似度路由
  （与原版 embedding 余弦同构，无模型依赖）+ 持久化 LRU 公平调度
  （跨重启保持轮转进度，⌈C/N⌉ 次扫描完成全量轮换）
- **可运行模板 2613 → 4701（+80%）**：漏斗大扩展支持 POST 模板/
  regex 匹配器/头匹配/根探测/多组 AND 合并；全库 11306 条经漏斗
  实测可运行 4701 条（原版同漏斗约 2613）

- 爬虫现代化四连：sitemap 种子（robots Sitemap 声明 + /sitemap.xml）、
  jsmap API 端点回灌爬虫、SPA 路由提取（__NEXT_DATA__/__NUXT__）、
  无头渲染（chromedp，crawler.headless 开关默认关，浏览器缺失自动降级）
- 修复：NUXT 路径提取正则字符类缺少斜杠导致恒空（细分诊断定位）

## v0.0.1-preview（预览版，2026-09-07）

Go 全量迁移完成：单二进制、零外部依赖（弃 PostgreSQL），Python 全量实现存档于 `python` 分支。

### 新增
- **内置 Web 服务**：`sitelens serve`，go:embed 嵌入前端单二进制交付；
  20 个 REST API 端点契约对齐 Flask 版，前端零改动迁移
- **验证型 check 扩展**：`Match.StatusAny/ContainsAny`（Nuclei 组语义，
  对 41 条内置规则向后兼容）
- **Nuclei 子集装载**：模板库索引（头部快扫 + 缓存）+ 两路调度
  （tag 硬匹配置顶、词面相关度排序、轮转覆盖三路调度）；漏斗对齐
  import_nuclei.py（单 GET/{{BaseURL}}/status|word，interactsh 跳过）
- **主动模块**：目录探测（软404 基线 + 403 绕过重试）、子域名枚举
  （DNS 并发、解析器可注入）、WebShell 探测、FingerDir 主动指纹
  （38 条精编 spec 全条件判定）、端口服务识别（11966 条 banner 指纹，
  TLS 自实现证书校验不跳过校验）
- **JS 攻击面**（internal/jsmap）：SourceMap 泄露检测 + bundle 内
  API 端点枚举
- **基础认证弱口令审计**：401 路径 Basic 字典尝试（凭据全部来自
  外部字典文件，代码不内嵌凭据）
- **KEV 情报自动更新守护**：CISA 公开源拉取，本地缓存
  data/state/kev_extra.json，间隔可配（intel.update_hours，0=关）
- **源码审计 / 登录爆破**：16 条 SAST 规则与宽容表单爆破从 Python
  移植；验证码识别能力缺失时明确报错拒绝而非静默误打
- **HTML 报告导出**：/api/export?fmt=html 自包含报告
- **性能**：指纹匹配字面量门控 + 正则 gate 预筛，13.6ms → 5.3ms/页（2.6x）
- **配置化**：全项目阈值统一 `.sitelens.yml`（示例 .sitelens.example.yml），
  零值/负值回退默认，布尔 false 是合法的"关"

### 修复
- **状态码比对缺失**（严重）：checks.matchBody 从未将 Match.Status 与
  实际响应状态码比较，纯状态码 check 会对任何响应命中；
  现按原版语义严格等值比较（含双确认路径）
- **批量扫描死锁**：runBatch 在 JobManager 写锁回调内调用
  CancelRequested（RWMutex 不可重入）导致永久挂起；
  改为回调外先取状态，并在 Update 注明非重入契约
- **HTML 解析越界崩溃**（模糊测试发现）：strings.ToLower 改变非
  ASCII 字节长度使索引错位，特殊 Unicode 页面可打崩扫描器；
  全部替换为长度保持的 asciiLower，120 秒 8700 万次 fuzz 零崩溃
- **协议校验绕过**：`ftp://x` 被盲补 https:// 前缀后放行为主机名
  "ftp"，现显式非 http(s) 协议直接拒绝
- **插件链路断开**：RegisterPlugins 从未被调用，用户插件端到端失效；
  ConfigurePlugins 幂等挂载，server/CLI 接入
- **指纹库形状 bug**：370 条精编指纹中 194 条 html 通道为历史对象
  形状，加载失败被静默丢弃；加载器双形状兼容，并恢复嵌套 dom 数据
- **仓库卫生**：.gitignore 裸写 `sitelens` 曾把 internal/sitelens 包
  整体挡在版本库外，改根锚定 `/sitelens` 并补录

### 变更
- 历史存储：PostgreSQL → 文件式 JSON（data/state/history.json，
  tmp+rename 原子写），API 字段契约不变
- Set-Cookie 逐条保真（Go http.Header 天然分离），替代 Python 版
  合并头启发式切分
- 爬虫：robots.txt Disallow 解析；非 2xx 页不入结果页
- 引擎取消：作业取消标志在阶段边界与 check 循环轮询生效

### 已知差距（详见 docs/Go迁移对照表.md）
验证码 OCR（ddddocr）、AST 级污点分析（已以 TAINT-lite 行级近似替代）、
dsl 匹配器。
