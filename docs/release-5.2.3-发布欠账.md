# SiteLens 5.2.3 发布检查与欠账清单

> 基线：HEAD `f7c4e0a` + 本地未提交（SQL 驱动、版本号、测试、文档）
> 检查时间：2026-11-01
> 用途：发版前逐项勾销；P0 不清零不发布，P1 尽量清零，P2 必须写进发行说明。
>
> **收尾状态（2026-11-01）**：P0-1/2/3/5/6 已清零；P0-4 自动化、真机、自建合成靶场均已完成，
> 仅剩标准 DVWA/pikachu 矩阵、请求级/UI 人工走查、CLI 五平台包、PG 真实实例。
> `check.ps1 -ExpectedVersion 5.2.3 -Strict -RequireSigned` = **PASS=12 / WARN=0 / FAIL=0 / SKIP=1**
> （SKIP=CLI 五平台包未构建；安装器/壳/引擎已自签名）。

## 0. 当前自动化检查结果

| 检查 | 结果 | 证据 / 备注 |
|---|---|---|
| `go build ./...` | ✅ PASS | 无输出 |
| `go test ./internal/... ./cmd/...` | ✅ PASS | 全包 ok（含 engine/server/store/worker/mcp/target） |
| `go vet ./...` | ✅ PASS | 无输出 |
| `node --check web/js/{common,i18n,app}.js` | ✅ PASS | 语法通过 |
| `scripts/frontend-check.mjs` | ✅ PASS | 错误 0 / 警告 20 / 允许例外 21 |
| `node --test scripts/i18n.test.mjs` | ✅ PASS | fail 0 |
| `benchmark/score.mjs --selftest` | ✅ PASS | 36 条断言，P=0.8 R=0.6667 F1=0.7273 |
| `go test ./internal/target`（URL 归一化） | ✅ PASS | 28 组表驱动 + 幂等 + host 不变量 |
| `scripts/release/check.ps1 -ExpectedVersion 5.2.3 -Strict -RequireSigned` | ✅ PASS=12 / WARN=0 / SKIP=1 | 版本/安装包/latest.yml/发行说明/CHANGELOG/签名全过；SKIP=CLI 包未构建 |
| 自签名 | ✅ 安装器/壳/引擎均 `Valid` | CN=SiteLens Internal Self-Signed（RSA3072/SHA256 + DigiCert 时间戳）；内部信任，公网需换证书 |
| 真机 | ✅ 安装/升级/启动/卸载/重装 | 注册表 5.2.3、InstallLocation 正确、引擎 API 5.2.3、WebView2 渲染、快捷键注册；修复旧安装缺 InstallLocation 的双目录问题 |
| 靶场（自建合成） | ✅ P=1.0 R=1.0 F1=1.0（10 目标/4 类型） | SQLi×4 / XSS×2 / CSRF / 路径穿越 / 安全×2；TP=8 FP=0 FN=0；目录覆盖 13.3%（4/30） |
| 靶场（WSL 标准子集） | ✅ P=R=F1=0.8333（7 目标） | DVWA low/xsslabs/upload-labs；DVWA SQLi/XSS/LFI/CSRF + xsslabs 全中；upload-labs `file_upload` dry-run 未检出、上传表单报 csrf；CSRF GET 误报已修（FP 3→1） |
| benchmark 口径 | ✅ 修复情报污染 | `score.mjs` 排除 `verdict=possible`；36 断言 selftest PASS |
| `govulncheck -tags onnx ./...` | ✅ PASS | `No vulnerabilities found`（MinGW gcc 16.1.0 + CGO_ENABLED=1） |
| `CGO_ENABLED=1 go test -race ./internal/... ./cmd/...` | ✅ PASS | 全包 race 通过（server 132s / intel 64s / engine 34s；MinGW gcc 16.1.0） |
| `gofmt -l internal cmd` | ⚠ 本机大量命中 | 原因：工作区部分文件 `w/crlf`（`git ls-files --eol` 可见），非代码问题；以 **CI Linux 的 gofmt 阶段**为准 |
| SQL 后端实测（sqlite/postgres） | ✅ SQLite E2E 通过 / 🟡 PG 未连真实实例 | `store.driver=sqlite`：启动日志“历史存储：SQL 后端”、扫描落库、`/api/history` 与 `/api/history/1` 正常；PG 驱动与方言 DDL 已就绪 |

---

## 1. P0：发布阻断项（必须清零）

### P0-1 版本号未升到 5.2.3（✅ 已修复）

- `internal/server/server.go`：`const Version = "5.2.0"` → `"5.2.3"`
- `desktop-wails/version.go`：`const Version = "5.2.0"` → `"5.2.3"`
- 两处必须一致（`tools/release_local.sh` / `check.ps1` R1–R3 会硬校验）。
- 同步检查 `internal/server/scan_sarif.go` 的 SARIF 版本串、`internal/protochk` 的 UA
  （`SiteLens/5.2.0`）是否要跟着改（建议改，避免报告里版本对不上）。

### P0-2 发行说明与 CHANGELOG 缺失（✅ 已修复）

- 缺 `docs/release-5.2.3/release-body-5.2.3.md`；`CHANGELOG.md` 还没有 `## v5.2.3` 段
  （R9/R10 会报）。
- 内容必须覆盖：5.2.2/5.2.3 第二/三/四批、G09/G10 全量接线、企业化 6.x 基座、
  MCP/辰极接口、URL 自动修正、WAF 兜底页误报修复。
- 所有 `【待发布：体积/SHA256】` 必须在出包后回填。

### P0-3 产物未构建 / 未校验（✅ 安装包/latest.yml 已出；CLI 五平台包未构建）

- `dist/release/SiteLens-Setup-5.2.3.exe` 不存在（R4 FAIL）；`dist/wails/SiteLens/` 暂存目录不存在（R6 FAIL）。
- 执行 `tools/release_local.sh`（版本取自 `desktop-wails/version.go`），产出：
  - 安装器 `SiteLens-Setup-5.2.3.exe`（NSIS，PE 头校验）；
  - 暂存 `sitelens.exe` + `engine/sitelens.exe` + `engine/data/`；
  - `latest.yml` + `.blockmap`（GitHub desktop-stable 三件套）；
  - 若发 CLI：`tui/packages` 五平台引擎包（R12 当前 SKIP）。
- Authenticode 仍是占位（R8 SKIP/WARN）；若要签名，需接入证书后再跑
  `check.ps1 -RequireSigned -Strict`。

### P0-4 验收报告未回填（✅ 自动化+真机+自建靶场已回填；标准矩阵/人工走查待补）

`docs/验收报告-5.2.x.md` 仍是骨架（全部“待实测”）。发版前至少回填：

1. 构建/单测/前端门禁/基准 selftest（本次已跑，可直接记）；
2. `-race`（CI 或有 cgo 机器）；
3. `govulncheck -tags onnx`（CI 门禁）；
4. 桌面 Windows 真机：安装/覆盖升级/卸载/托盘/快捷键/通知/Mica（FE-08 此前标注“未真机”）；
5. SARIF 被 GitHub code scanning 解析一次；
6. 合规报告条款映射抽样；
7. SCA 有/无 OSV 库两态；
8. URL 自动修正 + G09/G10 默认关/dry-run 的行为抽查。

### P0-5 CI 复核项（✅ 本地全绿；CI 二次确认）

- `gofmt` 门禁：本地 CRLF 噪声不代表 CI 失败，但必须在 CNB 上确认 “gofmt 格式检查” 阶段绿；
- `go vet`/`go test`/前端门禁/benchmark selftest 已在本地通过，CI 再确认一次；
- `-race` 与 `govulncheck -tags onnx` 已用 MinGW（`F:\dev\tools\msys64\ucrt64\bin`，CGO=1）本地跑通，
  CI 作为第二道门再跑一次即可（不再是无环境阻塞项）。

### P0-6 SQL 驱动未编入默认构建（✅ 已修复：SQLite 实测通过，PG 驱动/DDL 就绪）

- **现象**：配置 `store.driver=sqlite`（`store.dsn` 任意值）启动，日志报
  `sql.Open(sqlite)：sql: unknown driver "sqlite" (forgotten import?)；回退 JSON 文件存储`（已实测）。
- **根因**：`go.mod` 无 sqlite 驱动依赖；postgres 使用 `jackc/pgx/v5` 但未注册 `pgx/v5/stdlib`
  （且驱动名需 `postgres`→`pgx` 映射）。`store.SQLStore` 适配层本身有测试（测试用 fake driver），
  但**生产二进制没有任何真实驱动**。
- **影响**：对外宣称“支持 SQLite/PostgreSQL”不成立；`store.MigrateFromJSON` 无 CLI 也无法落地。
- **二选一（发版前必须决定）**：
  1. **补驱动**（推荐）：加 `_ "github.com/jackc/pgx/v5/stdlib"` + `postgres`→`pgx` 映射（无新依赖、体积增量小）；
     sqlite 用 `modernc.org/sqlite`（新依赖、纯 Go、体积增量较大）或 build tag 可选包；
  2. **降级口径**：发行说明/产品说明改为“SQL 适配层已就绪，默认构建回退 JSON，驱动在 5.2.4 提供”，
     并把企业维度分从 3.30 再下调。
- 未决前，所有对外材料不得写“开箱可切 SQLite/PG”。
- **✅ 修复（2026-11-01）**：新增 `internal/store/drivers.go` 注册 modernc sqlite + pgx stdlib；
  `openSQLScanStore` 把 postgres 映射到 pgx，并按方言执行迁移（PG 自增主键转 IDENTITY）。
  SQLite 已 E2E：启动日志“历史存储：SQL 后端（driver=sqlite）”→ 扫描落库 → `/api/history`、
  `/api/history/1` 正常；`internal/store` 新增驱动注册/真实 sqlite/SQLStore 用例，
  `internal/server` 的 fake driver 测试改为真实 sqlite。PostgreSQL 未连真实实例，留待 5.2.4 验证。

---

## 2. P1：发布前应完成（不阻断，但影响质量/口径）

1. **真跑 benchmark**（G01/G02）：✅ 已用自建合成靶场（10 目标，P/R/F1=1.0）与
   WSL 标准靶场子集（DVWA/xsslabs/upload-labs，7 目标，P/R/F1=0.8333）完成首轮验收；
   **完整标准矩阵（pikachu/sqli-labs/bWAPP/Juice Shop/WebGoat）+ 20 个授权样本仍未跑**，
   对外“更准”只能写“子集已过，完整矩阵待补”。
2. **文档同步**：本次已更新 `竞品对标与追赶方案`（v1.1，3.68）、`产品说明`（v5.2.3）、
   `企业版-6.x`（v0.2 已接线）；还需同步：
   - `README.md` 的“为什么是 SiteLens”与下载入口（版本号/能力描述）；
   - `docs/新功能路线图-5.2.md` §9：XC-01/CP-09/FE-10 仍写“待接线”，实际已接线；
   - `docs/验收报告-5.2.x.md`（P0-4）；
   - `CHANGELOG.md`（P0-2）。
3. **G09/G10 发布说明写清边界**：默认关；IDOR 需 `Options.Sessions`；logic/upload 默认 dry-run；
   配置键见 `.sitelens.example.yml`。避免用户开启后误以为“全自动”。
4. **企业化配置可操作性**：
   - `sitelens token issue`（HMAC 令牌签发 CLI）**尚未提供**——企业用户目前无法自助签发；
     要么本次补一个最小命令，要么发行说明写明“需自行用 `authz.IssueToken` 生成/后续版本提供”；
   - `store.MigrateFromJSON` 有函数、无 CLI（`migrate --to`）；发行说明要写清；
   - SQL 后端限制：`Import` 不支持、`Verified` 暂不提供（见 `store_backend.go` 注释）；
   - 回退语义：driver 连接/迁移失败自动回退 json（要不阻断启动，但要有日志提示）。
5. **a11y 例外收敛**：前端门禁仍有 20 项“允许例外”（设置/历史/情报/反馈页标签），
   发行说明注明“计划 5.3 补”，避免被当成合规缺陷。
6. **品牌**：FE-13「晦明」更名仍暂缓，发行说明与 README 保持一致（仍用 SiteLens/站点透视）。

---

## 3. P2：已知限制（可带病发布，但必须写进发行说明）

沿用 5.2.0 已知限制，并新增 5.2.3 的边界：

- 常驻埋点/匿名统计/崩溃上报：无（用户协议承诺）；诊断包不含日志全文；
- 模板索引目录 mtime 校验有极端时序窗口；指纹正则旧字面量门控有既有误提取；
- 更新通道无官方 checksum（HTTPS + SHA256 留痕 + 可选钉值）；
- 白盒污点无「净化器」；非 HTTP 协议通道的 DNS 重绑定缺口未修；
- ML 排序模型（verify-rank/find-rank）未交付；ONNX 严重度模型降为可选资产；
- CNB tag 自动发版流水线停用，发版走本地 `tools/release_local.sh`；
- `apocalypse` 全量模板档位未验证；模板来源通过率基线仅 afrog 固化；
- 正式交付仍 Windows-only，macOS/Linux 桌面未交付；
- 企业化：无 SSO/HA/多节点/审计日志/规模压测；RBAC 实际三档（viewer/operator/admin）；
- 高级 Web 检测默认关；IDOR 需显式会话；logic/upload 默认 dry-run；
- 召回只有本地子集基线（合成 10 目标 + WSL 标准子集 7 目标）；完整矩阵未跑；
- 企业化：SQL 驱动已编入默认构建（SQLite 已 E2E；PostgreSQL 未连真实实例验证）；无 SSO/HA/多节点/审计日志；
- 品牌更名暂缓；a11y 20 项允许例外。

---

## 4. P3：发版后欠账（登记，不阻塞 5.2.3）

| 欠账 | 说明 | 建议批次 |
|---|---|---|
| `sitelens token issue` | 企业 HMAC 令牌自助签发 | 5.2.4 / 6.0 |
| SQL 驱动注册 | ✅ 已完成（modernc sqlite + pgx stdlib；SQLite E2E） | 5.2.3 |
| PostgreSQL 真实实例验证 | 驱动/DDL 已就绪，需连真实 PG 跑迁移/落库/历史 | 5.2.4 |
| `migrate --to sqlite|postgres --dry-run/--verify` | JSON→SQL 迁移 CLI 与校验 | 6.0 |
| job/队列持久化 + audit_log | 当前 job 内存、队列内存、无审计表 | 6.1 |
| SSO（OIDC/SAML） | 设计稿已完成（§6） | 6.2 |
| 多节点 worker / lease / 死信 / HA | 设计稿已完成（§4） | 6.3 |
| benchmark 真实跑 + 季度复评 | 决定对外“准”的数字 | 5.2.4 |
| API spec 接进扫描计划 | 解析已交付，未接扫描 | 5.2.4 |
| a11y 标签补齐 | 设置/历史/情报/反馈页 20 项例外 | 5.3 |
| 品牌「晦明」更名 | 暂缓 | 待定 |
| 插件市场 / SLA / 0day | 设计稿（`docs/生态-插件市场-SLA-情报.md`） | 6.x |
| macOS/Linux 桌面 | 仅 Windows 正式交付 | 6.x |
| README/路线图/CHANGELOG 校准 | 本次只改了三份核心文档 | 随 5.2.3 |

---

## 5. 发版操作清单（按顺序）

- [x] 1. 改版本：`internal/server/server.go` + `desktop-wails/version.go` → `5.2.3`；
      `scan_sarif.go` / protochk UA 版本串同步；
- [x] 2. 写 `docs/release-5.2.3/release-body-5.2.3.md` + `CHANGELOG.md` 的 `## v5.2.3`；
- [x] 3. 本地：`go build ./...`、`go test ./internal/... ./cmd/...`、`go vet ./...`、
      前端三件套、`benchmark/score.mjs --selftest`；
- [ ] 4. CI：gofmt / vet / test / 前端 / `-race` / `govulncheck -tags onnx` 全绿（本地已全绿，待 CI 二次确认）；
- [x] 5. 出包：本机手工等价步骤（Wails shell `go build` + `node tools/build-engine.js --target=engine`
      + NSIS `makensis`；ASCII staging 规避中文路径）；产物已过 PE 校验；
      **前置：构建机需联网一次**——`desktop-wails` 是无 vendor 的独立 module，首次需解析 wails 依赖
      （`(cd desktop-wails && go mod download)` 预热，详见 `desktop-wails/README.md`「构建与发版」）；
- [x] 6. 回填发行说明的体积/SHA256；生成/校验 `latest.yml`；
- [x] 7. `pwsh scripts/release/check.ps1 -ExpectedVersion 5.2.3 -Strict -RequireSigned`：
      PASS=12 / WARN=0 / FAIL=0 / SKIP=1（SKIP=CLI 包）；
- [x] 8. 桌面真机冒烟：5.2.0→5.2.3 安装/升级/启动/卸载/重装通过；托盘/Mica/通知为目视项；
      真机发现旧安装缺 InstallLocation 导致双目录，安装器已补写入与卸载表回退解析并重签；
- [ ] 9. CNB Release：上传安装器 + 发行说明（不上传 latest.yml/blockmap，防双源漂移）；
      GitHub desktop-stable 上传 exe + blockmap + latest.yml；
- [ ] 10. 若发 CLI：`npm publish` `@fengqiao666/sitelens-cli` + 五平台引擎包；
- [ ] 11. 打 tag、发公告、回填验收报告与路线图状态；
- [ ] 12. 发版后 48h：监控下载/安装失败/崩溃反馈（仅用户主动提交的诊断包）。

---

## 6. 一句话结论

**发布物已就绪（内部验收口径）**：版本号 5.2.3、CHANGELOG/发行说明、安装包
`SiteLens-Setup-5.2.3.exe`（**135,590,048 字节 / SHA256 `8081E3E9…AD0C436`**，已自签名）、
`latest.yml` 均已生成；`check.ps1 -Strict -RequireSigned` = **PASS=12 / WARN=0 / FAIL=0 / SKIP=1**。
代码层面 `build/test/vet/race/govulncheck` 全绿，SQLite 后端 E2E 通过；
真机安装/升级/启动/卸载/重装通过；自建合成靶场 P/R/F1=1.0；WSL 标准子集 P/R/F1=0.8333
（CSRF GET 误报已修，file_upload 默认 dry-run 未检出）。
**剩余非阻断项**：自签名证书非公信（公网发布需换受信任证书）、完整标准矩阵、
CLI 五平台引擎包（R12 SKIP）、PostgreSQL 真实实例验证、请求级/UI 人工走查。
这些完成前，对外材料不要宣称“已公信签名/标准矩阵实测召回”。
