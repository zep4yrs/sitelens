# SiteLens 5.2.3 发行说明（v1.1，自 5.1.0 升级）

> 状态：v1.1（2026-11-02）。安装包已构建并回填体积/SHA256；`latest.yml` 已生成。
> **版本说明**：5.2.0 / 5.2.1 / 5.2.2 均未单独发版；本版是 5.1.0 之后的**唯一正式发布**，
> 合并原 5.2.0（代码库体检修复 35/36）、5.2.x 第二/三批、以及 5.2.3 收尾（G09/G10、
> 企业化 6.x、MCP/辰极、URL 自动修正）。下文「自 5.1.0 升级」列出累计变更；
> 发布欠账与检查清单见 [`../release-5.2.3-发布欠账.md`](../release-5.2.3-发布欠账.md)。

## 版本摘要

- **自 5.1.0 累计**：5.2.0 的 36 条体检修复（结论正确性/误报收缩/性能/限速/交互），
  5.2.x 第二/三批（源码审计、网络层、登录爆破护栏、批量定时、SARIF/合规报告、
  前端无障碍/i18n、桌面托盘/快捷键、基准评测、爬虫深度、指纹置信度等），
  以及 5.2.3 收尾；
- **高级 Web 检测全量接线**（G09/G10）：越权矩阵 / 业务逻辑 / 上传绕过 / 反序列化入口 /
  WebSocket 明文与 h2c·HTTP2 协议面，默认关、授权目标专用；
- **企业化 6.x 基座**：SQLite/PostgreSQL 存储、RBAC/租户、worker 池，默认不启用、行为 additive；
- **生态与体验**：MCP stdio 接口（辰极 Lodestar 可接入）、URL 输入自动修正；
- **质量**：目录探测 WAF/兜底 200 页误报、CSRF GET/跨源表单误报、CLI `[modules]`
  配置不生效等问题修复；`-race`/`govulncheck` 与两套本地靶场已跑。

## 自 5.1.0 升级：累计变更（本版合并 5.2.0 / 5.2.x 批次）

> 下面是 5.1.0 之后所有内容的一页摘要；逐条明细见 `CHANGELOG.md` 的
> 「附：5.2.0 代码库体检修复集」与「附：5.2.x 第二批 / 第三批」章节。

### 工程体量（5.1.0 → 5.2.3，可核对）

| 指标 | 数值 |
|---|---|
| 提交 | **58**（feat 22 / fix 9 / docs 10 / perf 2 / 其他 15） |
| 非 vendor/ML/data 变更 | **472 文件，+73,229/−1,613 行** |
| 产品代码（含测试/benchmark） | **约 6.5 万行**（internal +5.15 万；web +5,067；cmd +1,677；benchmark +2,704；desktop/tui/scripts +3,759） |
| 新增 | 8 个内部包、190 个 Go 文件、22 条 HTTP API、37 个配置键、11 个前端文件、28 个 benchmark 文件、32 篇文档 |

> 另有 `web/vendor` 1,880 个文件 / 366 万行三方依赖、`ml/`+`data/` 约 4.4 万行模型与知识库资产，
> 单独计算、不算“手写增量”。完整清单与统计口径见
> [`功能增量清单-5.2.3.md`](功能增量清单-5.2.3.md)。

### 5.2.0 代码库体检修复集（36 条修 35 条）

- **结论正确性**：CVSS v3.1 计分与 NVD 官方向量 100% 对齐（29 万条逐条对拍，
  不符率 41.42% → 0，并固化门禁）；四段版本号不再误判「确认受影响」；
  复现命令 shell 转义、表单证据链改 POST 语义、URL 通道预编码载荷不再二次编码；
  云 metadata 永久阻断 + DNS 重绑定封堵（一次解析→全量校验→按已校验 IP 拨号）；
  afrog 模板 expression 接线，通过率 0/1,699 → 878/1,699（51.7%），模板多 path 覆盖；
- **稳定性与并发**：KEV/漏洞表/CVE 公告表加锁与副本换代，`techIDs`/`apiToken` 原子换枪，
  403 绕过计数原子化，重定向中间响应体正确关闭；启动增量情报不被覆盖、空闲释放后
  重载不丢增量、残缺历史不再 panic；
- **交付与体验**：包体瘦身阶段 1（ONNX 退出默认分发，ML 资产 748.9 → 约 106 MiB，
  引擎载荷 173.8 MB，可选高级包回退）；ML 数据快照刷新（NVD 398,118 条）、
  查表优先 + 指纹先验；引擎与 CLI 拆成两个二进制；CLI 收口 TUI 单一入口；
  前端失败分级/引擎不可达态；应用内反馈页 + 本机脱敏诊断包；安全收紧
  （配置权限 0600、更新通道 HTTPS+校验、`migrate-pg` 口令走环境变量）；
  Dockerfile 补齐情报资产；Go 1.26.10 修复 `crypto/x509` 漏洞；
- **性能（实测）**：指纹匹配 24.7ms → 5.3ms（4.7×）、多页端到端 102ms → 6.2ms（16.4×）、
  模板索引热路径 1.1s → 6ms、冷构建 35–57s → 8s；HTTP 拨号 Happy Eyeballs
  （首地址黑洞场景从 20s 超时降到 ≈250ms）；
- **WAF-aware 限速 + 请求去重**：per-host 共享令牌桶，`balanced` 默认 400ms 起、
  硬下限 125ms（≤8 req/s/主机）；429/503/Retry-After/WAF 特征自动降速，被拦响应不参与判定；
  4 页带 DAST 实测 775 请求/155.1s → 771 请求/98.1s（-36.8%），结果等价；
- **交互反馈**：扫描前预检 + 建议卡 + 扫描计划；扫描中 `OnLive` 实时阶段/请求/被拦/
  速率/ETA 面板（全部 additive，不改结果格式与扫描行为）；
- **5.2 新增能力**：预检、网络层（证书/DMARC/SPF/HSTS/跳转）、登录爆破安全护栏、
  源码审计 SARIF、批量扫描逐行档位/重试/串行并行/断点续跑。

### 5.2.x 第二 / 第三批

- **源码审计**：基线/忽略（只报新增）+ 报告 diff；Java/Go/TS（JSX/TSX）+ OWASP Top10
  映射；云厂商 key 前缀 + 高熵密钥扫描（不落密钥值）；go.mod/package-lock/requirements SCA；
- **网络层**：证书资产线索、cipher 分级、ALPN/HTTP2、端口/服务探测（默认关）、多主机批量；
- **登录爆破/授权护栏**：多步登录、失败原因分类、跨目标总尝试上限、
  `scan.allow_hosts` 授权白名单（零请求拒绝越权目标；SSRF/gov.cn 硬闸门不受影响）；
- **批量与定时**：cron 定时任务（持久化/恢复）、与上次结果 diff、tag 分组、
  完成后 webhook 摘要（不含证据链与凭据）；
- **报告与合规**：扫描结果 SARIF 2.1.0 导出；等保 2.0 三级 / OWASP ASVS 4.0.3
  合规评估报告（提示性映射，未命中≠合规）；既有 JSON/CSV/宽表/HTML/MD 导出不变；
- **前端**：无障碍（地标/焦点陷阱/快捷键/IME 守卫）、动效（尊重 reduced-motion）、
  质量门禁（frontend-check/a11y-smoke/i18n 进 CI）、中英 i18n、Monaco 懒加载、
  窄屏响应式/打印、作业状态机 + 取消部分结果落库 + ResumePlan；
- **桌面（Wails）**：托盘快速扫描剪贴板 URL、`Ctrl+Shift+S/Q` 全局快捷键、
  Win11 Mica/深色标题栏、快速扫描走既有 API 并通知；
- **对标补课**：爬虫深度/SPA 路由发现、认证矩阵（Header/Bearer/Basic/Cookie）、
  基准评测体系（`benchmark/`）、性能分片 checkpoint、文件分层归档、UI triage/白名单、
  模板治理统计、指纹置信度。

## 5.2.3 收尾新增

### 高级 Web 检测（默认关）

- 越权矩阵：IDOR/水平/垂直，需调用方提供多角色会话（`Options.Sessions`）；
- 业务逻辑：数量/价格/优惠券/幂等，默认 **dry-run 只出计划**，显式授权才发请求；
- 上传绕过：危险扩展名 / 伪造 MIME / 双扩展名；
- 反序列化入口：Java/PHP/.NET/Python 标记识别，只识别不做利用；
- 协议面：WebSocket 明文 / 未校验 Origin、h2c / HTTP2 ALPN；
- 配置：`dast.proto` / `dast.deser` / `dast.logic` / `dast.upload` / `dast.idor` / `dast.max_requests`。

### 企业化 6.x（additive）

> **注意**：默认构建已编入 sqlite（modernc，纯 Go）与 postgres（pgx stdlib）驱动；
> `store.driver=sqlite` 已实测建表/落库/历史读取，PostgreSQL 需自备实例（驱动与 DDL 已就绪）。

- `store.driver=json|sqlite|postgres` + `store.dsn`，自动迁移，失败回退 JSON；
- `web.auth_mode=token` + `web.auth_secret`：HMAC-SHA256 令牌、`X-Tenant-ID` 租户隔离、
  RBAC（viewer/operator/admin）；
- `batch.use_worker_pool=true`：`MemoryQueue + WorkerPool`（同 host 串行/重试/进度/取消/Webhook）。

### 生态与体验

- `sitelens mcp`：MCP stdio server（13 工具），辰极通过 `CHENJI_MCP_SERVERS` 接入；
- URL 自动修正：补协议 / 去标点 / hxxp·[.] 还原 / 全角转半角 / 默认端口 / 去锚点与内嵌凭据；
  **只改格式、不改目标**，修正留痕；`target.auto_normalize: false` 可关闭。

## 修复

- 目录探测不再把 WAF/兜底 200 页当成真实文件（xgzwk 类站点误报修复）；
- ML 资产诊断假缺失：诊断与引擎统一按「配置 → cwd → 可执行文件相对」解析
  ML 资产目录，CLI/壳从非安装目录启动不再误报缺失（实际预测未跳过）；
- `csrf-form`：GET 搜索表单只认强状态字段，跨源表单（文章内嵌 jsfiddle/codepen）不再误报；
- CLI `scan` 补齐 `[modules]` 配置接线（目录/子域/WebShell/指纹/端口/敏感信息，默认关）；
- 安装器写入 `InstallLocation` 并兼容旧安装升级目录；
- benchmark `score.mjs` 不再把 `verdict=possible` 的 CVE 情报计为检出；
- 5.2.0 的 36 条体检修复（CVSS/版本比较/证据链/SSRF/afrog/稳定性）见上文「自 5.1.0 升级」。

## 兼容与升级

- **升级路径**：5.1.0 → 5.2.3 直接覆盖安装（5.2.0/5.2.1/5.2.2 未发版，无需中间版本）；
  安装器已兼容旧目录与缺 `InstallLocation` 的升级场景；
- 不启用新配置时扫描行为与 5.1.0 基本一致；但 5.2.0 的结论修正会改变部分历史判定
  （误报收缩、指纹置信度、严重度口径），升级前请读 5.2.0 章节与「升级前必读」；
- 企业能力与 G09/G10 均默认关（additive）；
- URL 自动修正默认开（仅格式归一），严格旧行为设 `target.auto_normalize: false`；
- SQL 后端：`Import` 不支持（用 `store.MigrateFromJSON` 一次性迁移）、`Verified` 暂不提供；
- 升级前建议备份 `data/state/`；桌面端支持自动覆盖升级。

## 验证口径

- 已跑：`go build ./...`、`go test ./internal/... ./cmd/...`、`go vet ./...`、
  `CGO_ENABLED=1 go test -race ./internal/... ./cmd/...`（全包通过）、
  `govulncheck ./...` 与 `govulncheck -tags onnx ./...`（均 No vulnerabilities found）、
  前端语法/门禁/i18n、`benchmark/score.mjs --selftest`、URL 归一化单测；
- 真机（Windows 11，非虚拟机）：5.2.0 开发版→5.2.3 静默覆盖安装、启动（引擎 API 返回 5.2.3、
  WebView2 工作台渲染、Ctrl+Shift+S/Q 全局快捷键注册）、静默卸载、重装均通过；
  **修复**：旧安装缺少 InstallLocation 时升级会落到默认目录形成双安装，安装器已补
  InstallLocation 与卸载表回退解析；
- 靶场：本地两套验收——
  ① 自建合成靶场（10 目标：SQLi/XSS/CSRF/路径穿越 + 安全×2）：P=1.0 R=1.0 F1=1.0、FP=0、FN=0；
  ② WSL2 标准靶场子集（Ubuntu 24.04 + DVWA low / xss-labs / upload-labs，7 目标）：
  P=R=F1=0.8333（DVWA SQLi/XSS/LFI/CSRF 与 xsslabs 全中；upload-labs `file_upload`
  默认 dry-run 未检出，上传表单报 csrf）；
  两套均**不是完整 DVWA/pikachu 矩阵**，完整矩阵（pikachu/sqli-labs/bWAPP/Juice Shop/WebGoat）待补；
  明细见 [`benchmark-selfhosted-2026-11-01.md`](benchmark-selfhosted-2026-11-01.md)、
  [`benchmark-wsl-standard-2026-11-01.md`](benchmark-wsl-standard-2026-11-01.md)；
- 待补：完整标准矩阵、SARIF GitHub code scanning 解析；
  安装包体积 / SHA256：135,605,744 字节（约 129.3 MiB）/
  `32ACC9113B722E6B3992C34CE6336060C8F00C50BD3BE3674947D5F4053C5104`。

## 已知限制

- 高级 Web 检测默认关；IDOR 需显式会话；logic/upload 默认 dry-run；
- 企业化“已接线、待规模验证”：无 SSO/HA/多节点/审计日志；
- 召回只有本地子集基线（合成 + DVWA/xsslabs/upload-labs）；完整标准矩阵/授权站点未跑；
- 无埋点/遥测；诊断包不含日志全文；更新通道无官方 checksum；
- 白盒污点无 sanitizer；非 HTTP 协议通道 DNS 重绑定缺口未修；ML 排序模型未交付；
- 正式交付仅 Windows；品牌更名暂缓；a11y 20 项允许例外计划 5.3 补；
- 安装包使用**自签名**证书（内部验收口径，CN=SiteLens Internal Self-Signed，
  RSA3072/SHA256 + DigiCert 时间戳；安装器/壳/引擎均已签）：公网用户会看到
  “未知发布者”，正式发布前需替换为受信任代码签名证书；
- 标准矩阵只跑通 DVWA/xss-labs/upload-labs 子集（WSL2 本地），pikachu/sqli-labs/bWAPP/
  Juice Shop/WebGoat 未部署（sqli-labs 依赖 PHP 5 `mysql_*`）；upload-labs 的主动上传默认 dry-run。

## 下载

- 桌面安装器（推荐，全能力）：`SiteLens-Setup-5.2.3.exe`
  135,605,744 字节（约 129.3 MiB），SHA256
  `32ACC9113B722E6B3992C34CE6336060C8F00C50BD3BE3674947D5F4053C5104`
  —— **只含引擎与界面，不含命令行工具**；已自签名（证书见上）
- 命令行工具（CLI，独立分发）：`npm install -g @fengqiao666/sitelens-cli`
- 升级：桌面端自动覆盖升级；离线环境下载安装器覆盖安装。
