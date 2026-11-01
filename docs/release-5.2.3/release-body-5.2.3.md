# SiteLens 5.2.3 发行说明（v1.0，已出包回填）

> 状态：v1.0（2026-11-01）。安装包已构建并回填体积/SHA256；`latest.yml` 已生成。
> 发布欠账与检查清单见 [`../release-5.2.3-发布欠账.md`](../release-5.2.3-发布欠账.md)。

## 版本摘要

- **高级 Web 检测全量接线**（G09/G10）：越权矩阵 / 业务逻辑 / 上传绕过 / 反序列化入口 /
  WebSocket 明文与 h2c·HTTP2 协议面，默认关、授权目标专用；
- **企业化 6.x 基座**：SQLite/PostgreSQL 存储、RBAC/租户、worker 池，默认不启用、行为 additive；
- **生态与体验**：MCP stdio 接口（辰极 Lodestar 可接入）、URL 输入自动修正；
- **质量**：目录探测 WAF/兜底 200 页误报修复；5.2.x 第二/三/四批收尾合并。

## 新增功能

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
  **只改格式、不改目标**，修正留痕；`target.auto_normalize: false` 可关闭；
- 5.2.x 第二/三/四批：爬虫深度、认证矩阵、API spec 解析、triage、SARIF、合规报告、
  分片/续跑、归档、模板治理、指纹置信度、无障碍/i18n/桌面快捷扫描。

## 修复

- 目录探测不再把 WAF/兜底 200 页当成真实文件（xgzwk 类站点误报修复）；
- 5.2.x 历史修复项见 `CHANGELOG.md` 与 5.2.0 发行说明。

## 兼容与升级

- 不启用新配置时行为与 5.2.0 等价；企业能力与 G09/G10 均默认关；
- URL 自动修正默认开（仅格式归一），严格旧行为设 `target.auto_normalize: false`；
- SQL 后端：`Import` 不支持（用 `store.MigrateFromJSON` 一次性迁移）、`Verified` 暂不提供；
- 升级前建议备份 `data/state/`；桌面端支持自动覆盖升级。

## 验证口径

- 已跑：`go build ./...`、`go test ./internal/... ./cmd/...`、`go vet ./...`、
  `CGO_ENABLED=1 go test -race ./internal/... ./cmd/...`（全包通过）、
  `govulncheck ./...` 与 `govulncheck -tags onnx ./...`（均 No vulnerabilities found）、
  前端语法/门禁/i18n、`benchmark/score.mjs --selftest`、URL 归一化单测；
- 真机（Windows 11，非虚拟机）：5.2.0→5.2.3 静默覆盖安装、启动（引擎 API 返回 5.2.3、
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
  安装包体积 / SHA256：135,597,192 字节（约 129.3 MiB）/
  `531F2361B6E3317768B4C330E5D48B33F3A832EAA9FE725883045AD1AAF9E833`。

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
  135,597,192 字节（约 129.3 MiB），SHA256
  `531F2361B6E3317768B4C330E5D48B33F3A832EAA9FE725883045AD1AAF9E833`
  —— **只含引擎与界面，不含命令行工具**；已自签名（证书见上）
- 命令行工具（CLI，独立分发）：`npm install -g @fengqiao666/sitelens-cli`
- 升级：桌面端自动覆盖升级；离线环境下载安装器覆盖安装。
