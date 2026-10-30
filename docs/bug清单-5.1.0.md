# SiteLens Bug 修复清单（5.1.0 快照）

> **这份文档是什么**：可直接当 TODO 用的修复队列。每条含**位置 / 现象 / 根因 / 修法 / 验收标准**，按严重度排序。
>
> **快照基准**：commit `0986a3f`（main / 5.1.0）· 核对于 2026-10-28
> **证据分级**：✅ 实测复现 · 🔍 代码读证（未执行） · 📄 代码注释/文档口径 · ❓ 未验证
> **配套文档**：[交接文档-5.1.0.md](交接文档-5.1.0.md)（架构与子系统背景）· [小白说明-5.1.0.md](小白说明-5.1.0.md)（面向使用者的风险解读）
>
> **总计 31 条**：P0 严重 3 · P1 高 5 · P2 中 13 · P3 低 10；另附 13 条文档漂移（DOC-xxx）与 9 条已排除误报（排除项）。
> **规划期追加**（2026-10-28 用户反馈，编号续排）：5 条缺陷（BUG-032 ~ BUG-036）+ 2 条需求项（FEAT-001 ~ FEAT-002），见 §4.5。
> **5.2 修复集状态**（2026-10-29，分支 `feat/sitelens-5.2.0`）：36 条缺陷中 **35 条已修**（BUG-035 为包体瘦身专项，待实测拍板）；13 条文档漂移已对齐；另新发现并修复 4 条同类静默缺陷（NEW-001~004）。**完整修复实录、分批证据与遗留见 §0.5**。

---

## 0. 修复前必读：四条不可放松的红线

本项目的立意是**「宁少报不误报」**。下列红线在修 bug 时**不能为了"提高通过率/覆盖率"而放松**：

| 红线 | 落位 | 相关条目 |
|---|---|---|
| 模板 DSL 编译是**整模板级一票否决** | `internal/nuclei/nuclei.go:737-759` | BUG-016 |
| 证据链四件套必须**真的可复现** | `internal/dast/dast.go:818-827` | BUG-002 / BUG-018 |
| `gov.cn` 代码级硬保护，**无任何配置可关** | `internal/target/validator.go:44-49` | BUG-003 |
| 单次扫描全程用**同一份数据快照** | `internal/engine/engine.go:129-134` | BUG-004 / BUG-013 / BUG-014 |

### 修复通用要求

1. **每修一条，补一条回归断言**（表里已给出建议断言）。本项目已有 `-race` 门禁，但本清单里多条竞态**门禁抓不到**（因为测试没并发执行），必须补并发用例。
2. **不要顺手重构**。本清单每条改动面都已收敛，重构会扩大回归面。
3. **改完跑**：`go build ./cmd/sitelens` + `go test ./internal/... ./cmd/...` + `go test -race ./internal/...` + `gofmt -l internal/ cmd/`（应为空）。
4. ⚠️ **本机 `core.autocrlf=true`**，工作区文件是 CRLF，`gofmt -l` 会把每个文件都标红——**这是本地假阳性**，CI 在 Linux 上跑的是 git blob（LF）。判定格式问题请在 Linux 容器或 `git config core.autocrlf false` 后再跑。

---

## 0.5 5.2.0 修复实录（2026-10-29）

> 本节是 **5.2.0 修复集**的实测记录。工作快照：分支 `feat/sitelens-5.2.0`（检查点 commit `2d03f01` 之后）。
> 证据分级沿用全文口径（✅ 实测 · 🔍 读证 · 📄 口径 · ❓ 未验证）；逐条根因/修法/验收标准见后文各条目。
> 本轮另**新发现 4 条同类静默缺陷**（NEW-001~004），一并修复记录。

### 0.5.1 修复状态总览

| ID | 状态 | 验证方式与结果 |
|---|---|---|
| BUG-001 | ✅ 已修 | `internal/intel/cvss_nvd_parity_test.go`：**292,036 / 292,036（100.00%）** NVD 官方向量逐条一致（1.99s），另含顺序无关性 / AV:L 断言 |
| BUG-002 | ✅ 已修 | `internal/dast/replay_test.go` 以 POSIX 引号往返解析验证转义可逆；表单证据链 POST 语义由 BUG-018 用例覆盖 |
| BUG-003 | ✅ 已修 | metadata IP 在 `allow_private` × `resolve` 四组合全拒；BUG-021 的拨号层再做二次收口 |
| BUG-004 | ✅ 已修 | `intel` KEV 表加 `RWMutex`；`TestMergeKEVIsKEVConcurrentSafe`（写 500 轮 + 2 读线程，末态全可见） |
| BUG-005 | ✅ 已修 | 子命令后补扫全局开关（`-config/-env/-version/-graph/-ast`）；`TestRescanGlobalFlags` / `TestGlobalFlagPrefixSuffixEquivalent`；二进制端到端两种写法均监听 cfg 端口；引擎二进制同型修复 + `TestRescanConfigFlag` |
| BUG-006 | ✅ 已修 | `overrides_path` 限定数据目录内（`filepath.Rel` 判界）；4 类越界 400 且配置不变、目标文件未创建 + 合法用例 |
| BUG-007 | ✅ 已修 | `Parse` 改不定长、逐段比较（公共前缀相等时短者为小 = Python 元组语义）；清单 3 条验收用例 + 边界用例 |
| BUG-008 | ✅ 已修 | 重定向中间跳 `drainAndClose`；8 轮 × 5 跳新增连接 ≤1（修前 +40），goroutine 不增长 |
| BUG-009 | ✅ 已修 | `TopTechs` nil 守卫 + `/api/stats` 兼容 `result:null`；临时回退守卫验证必 panic |
| BUG-010 | ✅ 已修 | `techIDs/techCnt` → `atomic.Pointer[techMeta]` 整体换枪；并发 reload × categories 用例 |
| BUG-011 | ✅ 已修 | `apiToken` → `atomic.Pointer[string]`；并发设置保存 × `/api` 鉴权用例 |
| BUG-012 | ✅ 已修 | `nuclei_schedule.json` 的 null / 损坏 / 空文件三态都落可写空表 |
| BUG-013 | ✅ 已修 | 插件索引改版本化原子快照（pluginGen）；热加载后 `IsExtended` 命中用例 |
| BUG-014 | ✅ 已修 | `vulns/cveMs/index` 加 `RWMutex`，覆盖合并副本上完成再换代；并发合并 × 扫描一致性用例 |
| BUG-015 | ✅ 已修 | 403 绕过请求计数改原子；并发下不超硬上限 |
| BUG-016 | ✅ 已修 | afrog rule 级 expression 接线（`internal/afrogx` 编译/求值 + `checks.Match.Expr`）；真实语料 **878/1699（51.7%）通过**、转出 1,051 条 check（修前 0）；12 条真实模板夹具判定断言 + 来源覆盖门禁 |
| BUG-017 | ✅ 已修（URL + 表单通道） | `rawSetParam` 原始注入 + 表单侧原始表单体通道 `PostFormRawSmall`；真实 httptest 服务端**字节级断言**（收到真 CR/LF 与 `aced0005`），证据链 Request/Replay 与真实请求体逐字节一致；表单通道残留已收口（见 0.5.6） |
| BUG-018 | ✅ 已修 | `chainEvidence` 不再覆盖表单 POST 语义；`TestRunFormsEvidenceStaysPOST` |
| BUG-019 | ✅ 已修 | ONNX 资产路径改 `ml.LocateAssetsDir` 同源候选；`TestSevAssetsDir*`（本机无 CGO 未跑真实推理，见 0.5.5） |
| BUG-020 | ✅ 已修 | Dockerfile 补 `intel_dump / nvd_cves / tpl_intel`；模板池与 ML 资产按体积走挂载，文件头写明降级矩阵；`/api/diagnostics` 可查资产就位 |
| BUG-021 | ✅ 已修（httpx） | `Transport.DialContext` 一次解析→全量校验→按已校验 IP 拨号，Host/SNI 保持；6 条用例（`.invalid` 注入解析、混合答案整体拒绝、字面私网拒绝、逐跳校验）；netx CNAME 缺口保留（已知限制） |
| BUG-022 | ✅ 已修 | path 列表展开（上限 4，check id 带 `~pN` 后缀）；4 条用例；分层抽样实测展开后请求量 +17%~36% |
| BUG-023 | ✅ 已修 | 强制 https + 实测 sha256 留痕 + 可选 `SLENS_UPDATE_SHA256` 钉值硬校验；先下载校验再解包；4 条用例（上游无官方 checksum，见 0.5.6） |
| BUG-024 | ✅ 已修 | history / archive / 配置写回 0644→0600（并对遗留文件 `Chmod` 收紧）；Linux 严格断言、Windows 分支注明 |
| BUG-025 | ✅ 已修 | `.gitattributes` 加 `* text=auto eol=lf`；`git check-attr` 验证生效 |
| BUG-026 | ✅ 已修 | 删除 `versioncmp.Round1` 死代码；build / vet / grep 验收 |
| BUG-027 | ✅ 已修 | rex 预算改为全次调用共享（单次查找总步数 ≤ Budget）；golden 702 模式 / 5,469 用例 0 差异 |
| BUG-028 | ✅ 已修 | `ml/requirements.txt` 补 torch/transformers；训练与导出脚本路径改「环境变量优先 + 相对仓库默认」（见 `ml/README.md`） |
| BUG-029 | ✅ 已修 | 表单 probeURL 按表单编码规则构造；`TestFormProbeURLEncodesQuery` |
| BUG-030 | ✅ 已修 | DSN 不再含口令（经 `*pgx.ConnConfig.Password` 注入）、sslmode 走 `SLENS_DB_SSLMODE`（默认 prefer）；3 条用例 |
| BUG-031 | ✅ 已修 | `Store.flush` 三处失败告警 stderr（成功零输出）；同名目录占位注入故障用例 |
| BUG-032 | ✅ 已修 | 壳拉引擎 `CREATE_NO_WINDOW` + `HideWindow`；引擎保持控制台子系统（CLI 要 stdout） |
| BUG-033 | ✅ 已修 | 树杀 `taskkill` 同样 `CREATE_NO_WINDOW`；种子交付子进程一并处理 |
| BUG-034 | ✅ 已修 | 前端三类失败分级 + 11 处静默 catch 收口 + 「引擎无响应」界面态；`web/js/api-error.test.mjs` 5 例 |
| BUG-035 | ⏳ 待实测拍板 | 包体瘦身：体积逐文件实测（`ml_assets` 合计 748.93 MiB，4 个 ONNX 643.29 MiB = fp32 511.05 + int8 132.24）+ 三方案对比与决策矩阵（`docs/release-5.2.0/ML-包体瘦身实测方案-5.2.0.md`）+ int8 vs fp32 一键实测脚手架（`internal/ml/sev_onnx_int8_test.go`，build tag onnx）。关键发现：**引擎 glob 已是 fp32→int8 回退，只带 int8 零 Go 改动**（891.4 → ≈380 MiB）；**需 CGO + onnxruntime 环境实测精度后才能拍板**，打包脚本一行未改 |
| FEAT-001 | ✅ 已落地 | `internal/diag` + `/api/diagnostics` + `/api/feedback` + `web/feedback.html`；脱敏守卫测试 |
| FEAT-002 | ✅ 定案 | 不做常驻埋点；`feedback.endpoint` 默认空（用户自建端点，默认只能复制到 Issue） |
| NEW-001 | ✅ 本轮新发现并修复 | 启动期 `MergeKEV(kev_extra)` 被首次解码换表覆盖 → 首次扫描前 KEV 标注丢失；换表前并入旧表 + `TestLoadLazyPreservesPreDecodeKEV` |
| NEW-002 | ✅ 本轮新发现并修复 | `techCPE` 同型：解码把启动期 `AttachTechCPE` 挂载清空 → CPE possible 通道静默失效；改为仅新表非 nil 时覆盖 + 用例 |
| NEW-003 | ✅ 本轮新发现并修复 | `Release()` → 重载丢 KEV 增量；`pendingKEV` 重放 + `TestReleaseReplaysKEVExtras` |
| NEW-004 | ✅ 本轮新发现并修复 | `MatchCVEMs` 无锁读 `cveMs`；纳入 `vulnsMu` 读锁 + 重载前后自洽用例 |

### 0.5.2 分批实测证据（摘要）

**批次 A（engine / intel / versioncmp / rex）**：BUG-004/007/012/013/014/019/026/027 + NEW-001~004。
`go test ./internal/{intel,versioncmp,engine,checks,rex}` 全绿（intel 11.5s / engine 10.0s）；并发用例按 race 友好设计。

**批次 B（dast / httpx / target）**：BUG-008/017/021/029。三条做了「临时回退 → 测试必红 → 恢复 → 绿」实测：
BUG-017 修前服务端只收到 `q=%250d%250a…`、BUG-008 修前 5 跳 × 8 轮新增 40 条连接、BUG-021 修前 `GetDirect` 能直连回环字面 IP。

**批次 C（server / store / cmd）**：BUG-005/006/009/010/011/023/024/025/030/031。
二进制端到端：`sitelens serve -config cfg` 与 `sitelens -config cfg serve` 都监听 cfg 里的端口（修复前后置写法会用默认 5000）；`sitelens scan ftp://x -config cfg` 与前置写法行为一致。

**模板层（BUG-016 / BUG-022）**：见 0.5.3 两组实测数据。

**交付与前端（已有 P0 + 桌面 + FEAT）**：exe 拆分、TUI 单入口、诊断反馈、前端错误分级；`web/js/api-error.test.mjs` 5/5、`tui` esbuild + `--version`/`--help`、desktop-wails 模块测试均通过。

### 0.5.3 关键实测数据

**BUG-001（CVSS）——三处缺陷叠加的量化归因**

用仓库自带 `data/nvd_cves.json.gz`（NVD 官方分 + 向量，292,036 条 v3 向量）全量对拍：

| 状态 | 与官方分不符 | 占比 |
|---|---|---|
| 修复前 | 120,952 | **41.42%** |
| 修复后 | **0** | **0.00%** |

三处缺陷的单独贡献（按「只修其中一处」时分数变化的向量数）：

| 缺陷 | 位置 | 单独贡献 |
|---|---|---|
| `AV:L` 权重误用 CVSS **v2** 的 0.39（应为 **0.55**） | `internal/intel/cvss.go:13` | 23.29% |
| Scope Changed **漏 ×1.08 系数** | `internal/intel/cvss.go:122` | 19.92% |
| PR 权重依赖**向量串书写顺序** | `internal/intel/cvss.go:77-81` | 11.10% |

顺序 bug 为何必现：NVD 规范向量顺序恒为 `AV:AC:PR:UI:S:C:I:A`——**S 永远在 PR 之后**。实测全部 292,036 条中 **100% 是 S_after_PR**，故每个 `S:C` 向量都误用了 PRu 权重。

**为什么 CI 之前是绿的**：仓库自带的 `internal/intel/cvss_test.go` 把**错误输出写成了期望值**（`AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` 期望 4.8，官方 5.4；`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` 期望 4.9，官方 5.5）。断言已按 NVD 官方分订正，并**新增 29 万条对拍门禁**——这类「整体偏移」靠抽样测试发现不了。

**BUG-016（afrog 来源）——修复前后**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 通过漏斗 | **0 / 1,699** | **878 / 1,699（51.7%）** |
| 转出 check | 0 | 1,051 |
| 拒收 | 1,699 | 821 |

821 条拒收分布：AND 链某 rule 归一化失败 676（表达式编译失败/不可判定/无内容判定/路径占位符）、文档级表达式非纯 `rN()` 链 49、OR 全部分支拒收 48、多请求 AND 无法降为单请求 41、YAML 解析失败 4、文件过大 2、引用不存在的 rule 1。

**误报评估**（放行前必做）：放行集合全部含**正文内容判定**（编译期 `PositiveGround`：纯状态码/纯响应头/纯取反一律拒收）；单 rule 放行模板的最短正文 needle 中位 **12 字符**（p10=5），仅 4.4% 含 ≤3 字符短词且多在 AND 链中——无系统性泛匹配风险；仍待靶场回归复核。

**BUG-022（path 列表）——预算评估**（模板包分层抽样各 3,000 条）

| 来源 | 多 path 模板比例 | 最长列表 | 展开后请求量 |
|---|---|---|---|
| community-wordfence | 10.0% | 4 | 1.30× |
| community-40k | 7.1% | 64 | 1.30× |
| http（官方库） | 14.4% | 64 | 1.36× |
| legacy | 9.0% | 57 | 1.17× |

→ 展开上限取 **4**：覆盖 wordfence 全部形态与其余来源主流形态；长尾截断是覆盖率损失（宁少报），不是误报风险。

### 0.5.4 本轮新增的回归门禁

| 门禁 | 文件 | 作用 |
|---|---|---|
| CVSS × NVD 全量对拍 | `internal/intel/cvss_nvd_parity_test.go` | 计分偏移零容忍（1.99s） |
| KEV / vuln 表并发安全 | `internal/intel/kev_test.go`、`internal/intel/concurrency_test.go` | map 并发读写 / 覆盖合并竞态（-race 目标） |
| 惰性解码挂载不丢 | `internal/intel/lazy_attach_test.go` | KEV / techCPE / Release 重放 |
| 四段版本号 | `internal/versioncmp/versioncmp_test.go` | 清单 3 条验收 + 边界 |
| ONNX 资产路径 | `internal/engine/ml_test.go`、`internal/engine/nuclei_schedule_test.go` | 路径回退 / 调度表 null |
| 插件热加载索引 | `internal/checks/hotreload_test.go` | 新插件不被静默漏检 |
| rex 共享预算 | `internal/rex/rex_test.go` | 步数上界 |
| 复现命令 shell 转义 | `internal/dast/replay_test.go` | 往返解析验证可逆性 |
| 证据链 POST 语义 | `internal/dast/replay_test.go` / `preencoded_wire_test.go` | 表单语义 / 原始字节注入 |
| 重定向连接不泄漏 | `internal/httpx/client_test.go` | 5 跳 × 8 轮连接数 |
| DNS 重绑定拨号层闸 | `internal/httpx/client_test.go`、`internal/target/validator_test.go` | 一次解析/全量校验/按 IP 拨号 |
| metadata 永久阻断 | `internal/target/validator_test.go` | 四个开关组合全拒 |
| 任意文件写 | `internal/server/settings_test.go` | overrides_path 越界 400 |
| server 并发快照 | `internal/server/*_test.go` | techIDs / apiToken 换枪 |
| 历史残缺记录 | `internal/store/*_test.go` | `result:null` 不 panic |
| 更新通道 https | `cmd/sitelens/*_test.go` | http:// 拒绝 + sha256 钉值 |
| CLI 全局 flag 位置等价 | `cmd/sitelens/main_test.go`、`cmd/sitelens-engine/main_test.go` | 前置/后置同效 |
| 诊断包脱敏 | `internal/diag/diag_test.go` | token/凭证/绝对路径零泄露 |
| 前端错误分级 | `web/js/api-error.test.mjs` | 三类失败必须带上下文 |
| afrog 表达式求值 | `internal/afrogx/expr_test.go` | 支持/拒收/缓存 |
| afrog 接线与真实模板 | `internal/nuclei/afrog_rule_expr_test.go` | 12 条真实模板判定 + 来源覆盖门禁 |
| path 列表展开 | `internal/nuclei/path_expand_test.go` | 展开/上限/去重/缺省 |
| 模板来源归一 | `internal/nuclei/source_test.go` | afrog 独立来源 |
| 运行时 Match.Expr | `internal/checks/expr_match_test.go` | 表达式不命中/编译失败不误报 |

### 0.5.5 执行结果与环境限制

- `go build ./...` ✅ 通过；`go test ./internal/... ./cmd/...` **40 个包全绿** ✅（engine 10.0s / intel 11.5s / nuclei 8.5s / server 11.4s / cmd/sitelens 5.2s / cmd/sitelens-engine 4.4s）。
- `go build -o bin/sitelens.exe ./cmd/sitelens` → `SiteLens 5.2.0` ✅；`cmd/sitelens-engine` 构建 ✅。
- `web/js/api-error.test.mjs` 5/5 ✅；`tui` esbuild 构建 + `--version`/`--help` ✅；desktop-wails 模块测试 ✅。
- ⚠️ **本机 CGO_ENABLED=0、无 gcc/mingw**：`go test -race` 与 `-tags onnx` 无法在本地执行。并发用例按 race 友好设计，需 CI / 有 CGO 的环境复核 `CGO_ENABLED=1 go test -race ./internal/intel ./internal/server`；ONNX int8/fp32 精度实测需 `CGO_ENABLED=1` + `onnxruntime.dll`。
- ⚠️ 本机 `core.autocrlf=true` 的 gofmt 假阳性：格式判定在 LF 归一化副本上完成；`.gitattributes` 已修（BUG-025）。
- **第二轮（性能优化 + 表单 CRLF 收尾）复跑**：`go build ./...` + `go vet ./internal/... ./cmd/...` + `go test ./internal/... ./cmd/...` **40 包全绿**；`BenchmarkMatch` 5.3ms / `BenchmarkMultiPageScan` 6.2ms（详见 §0.6）；`web/js` 5/5、TUI 构建冒烟、desktop-wails 模块测试通过；全部改动 Go 文件 gofmt clean（LF 归一化副本）。

### 0.5.6 遗留与已关闭项（本版收尾）

| 项 | 状态 | 说明 |
|---|---|---|
| **BUG-035 包体瘦身** | ⏳ 待实测拍板 | 待有 CGO + onnxruntime 的机器跑 int8/fp32 对拍后拍板；本轮交付实测脚手架 + 方案对比 + 决策矩阵，未改打包脚本 |
| **表单侧 CRLF 探针** | ✅ 已关闭（第二轮） | engine `dastFetcher` 新增可选「原始表单体」通道 `PostFormRawSmall`（body 由 dast 按表单编码纪律显式构造：其余字段照常编码，仅目标字段值原样保留预编码字节）；`dast` 表单 CRLF 探针改走该通道，拿不到通道时跳过（宁少报，不发无效请求），其余表单探针仍走 `url.Values.Encode` 不变。验证：真实 httptest 服务端断言单次解码拿到真 CR/LF（非 `%25` 字面）+ 证据链 Request/Replay 与真实请求体逐字节一致 + 无通道时跳过；engine 端到端 `TestDastFormCRLFRawChannelEndToEnd`；修复前临时回退必红 |
| **多 IP 串行拨号** | ✅ 已关闭（第二轮） | `internal/httpx` 在「一次解析 → 全量校验 → 只拨已校验 IP」语义不变前提下实现轻量 Happy Eyeballs（RFC 8305：250ms 错峰、先成功者胜出并取消其余、候选上限 8）。首地址黑洞场景从「请求超时失败」变为 ≈250ms 成功；单 IP 快路径不变 |
| **netx CNAME→私网** | 遗留 | 已知缺口（代码注释自认），release-body 已列为已知限制，未动 |
| **上游更新无官方 checksum** | 遗留 | 无官方校验值时只强制 https + 实测 sha256 留痕 + 可选钉值，不伪造校验 |
| **两处行为变化** | 发版提示 | `overrides_path` 收紧到数据目录内（旧配置指向目录外时设置页保存 400）；`sslmode` 默认 `disable`→`prefer`（本地无 TLS 自动回退） |
| **模板索引目录戳时序** | 说明（宁少报） | 热路径用目录 mtime 判断模板池是否变化；NTFS 目录 mtime 是毫秒级懒写、网络盘/粗粒度文件系统属性缓存等原因，极端时序下变更可能延后一次扫描被感知（只会少跑新模板，不会误报）；in-place 覆盖写与 5.1 判定同缺口，可删 `data/state/nuclei_index.json` 强制重建 |
| **literalGate 转义误提取** | 后续（语义变更） | 旧字面量门控把 `\s`/`\d` 等转义当字面量（如 `WordPress\s*` 提取成 `wordpresss`，导致该规则在本可命中时被跳过——少报方向）。本轮**保持 5.1 语义未借优化改召回**；meta 通道已改挂新语法树门控避免 WordPress 类漏检；修正属提升召回的语义变更，另行评估 |

### 0.6 第二轮：性能优化实录（2026-10-29，同机同语料交错实测）

> 目标：把「每扫一次都要付」的 CPU 与 IO 固定成本压下来。所有优化**检测语义不变**，
> 以「旧语义参照逐字段等价」测试 + 全语料差分兜底；性能基准已固化为可重复 benchmark。

#### 0.6.1 前后数字

| 场景 | 优化前 | 优化后 | 变化 |
|---|---|---|---|
| 指纹匹配（40KB 页 × 13,727 指纹） | 24.7 ms / 4,381 allocs | **5.3 ms / 194 allocs** | **4.7×**，分配 -95.6% |
| 4 页 × 40KB 端到端扫描 | ≈102–123 ms | **≈6.2–6.4 ms** | **16.4×**（同树交错测） |
| 模板索引热路径（每扫一次；20k 语料实测） | 97.7–99.5 ms | **7.3–7.7 ms** | **≈13×**；144k 真实目录结构折算 **≈6 ms/次**（原 ≈1.1 s/次） |
| 模板索引 `IndexCached`（每扫 2 次） | ≈26 ms/次 | **<1 ms** | 20×+ |
| 模板索引冷构建（5,094 文件语料） | 1.215 s | **268 ms**（同语料 Lead 复测） | **4.5×**；144k 折算 ≈35–57 s → **≈8 s** |
| HTTP 拨号（首地址黑洞、后一可用） | 请求超时失败（默认 20 s） | **≈250 ms 成功** | 从失败变成功 |

#### 0.6.2 改了什么

- **指纹（internal/sitelens）**：`litindex.go` 重写为滚动 4 字节小写 key + 开放寻址表（单页正文单遍扫描）；新增 `gate.go` 用 `regexp/syntax` 从正则推导「必含字面量」AND/OR 条件树（可证明不匹配才跳过，拟真页 436 条正文正则实际只执行 2 条）；加载期按 raw intern 正则（1,980→1,759）+ 单次 Match 内正文通道结果缓存；`Evidence` 正文小写惰性缓存（Body 改写自动失效）；`Matcher` 名称 map（同名取首条）。
- **引擎（internal/engine）**：第 4 阶段多页指纹识别页间并行（worker ≤ min(4,页数)；命中按页序串行累加，favicon 只取一次，progress 回调不进并行区）。
- **模板索引（internal/nuclei）**：新增 `front_shape.go` 字节级前端形状预筛（afrog 模板 3 次 YAML 解析 → 1 次；path/raw 共享一次解析；结论是超集，不确定一律全试）；`Index` 两段式段内并行转换（cap 8，结果按原下标回填、entries 顺序/legacy 去重语义不变）；新增 `index_hot.go` 目录 mtime 戳 + 进程内单条 memo + `IndexCached` 接入；`cacheSchema` **v9→v10**。
- **拨号（internal/httpx）**：轻量 Happy Eyeballs（IPv6/IPv4 交错、250ms 错峰、先成功者胜出并取消其余、候选上限 8；SSRF 全量校验前置不变）。
- **表单 CRLF**：见 0.5.6（原始表单体通道）。

#### 0.6.3 新增门禁 / 基准（长期跑）

| 门禁 | 文件 | 作用 |
|---|---|---|
| 指纹匹配基准 | `internal/sitelens/bench_test.go`（`BenchmarkMatch`） | 发布前记录数字，防回退 |
| 多页扫描基准 | `internal/engine/engine_parallel_test.go`（`BenchmarkMultiPageScan`） | 同上 |
| 指纹语义等价（旧语义参照） | `internal/sitelens/prescreen_equiv_test.go` | 22 份真实/fuzz/合成页 × 全库逐字段比对 |
| 门控健全性 | `internal/sitelens/gate_test.go` | 「门控跳过 ⇒ 正则确实不匹配」 |
| 预筛等价性 | `internal/sitelens/litindex_test.go`、`evidence_test.go`、`matcher_test.go` | 字面量集合/正文缓存/名称表 |
| 模板转换等价 | `internal/nuclei/index_equiv_test.go`、`front_shape_test.go` | 旧实现差分 + 首前端优先级 + 超集 fuzz |
| 索引热路径 | `internal/nuclei/index_hot_test.go` | memo 命中不读文件、目录增删改名感知、schema 升级失效 |
| 拨号 Happy Eyeballs | `internal/httpx/client_test.go` | 黑洞首 IP/全失败/全量校验零拨号/resolve=false 不变/端到端 Host 保留 |
| 表单 CRLF 原始体 | `internal/dast/form_crlf_raw_test.go`、`internal/engine/dast_form_crlf_test.go` | 真实服务端字节级断言 + 证据链一致 |

#### 0.6.4 遗留

- 指纹旧 `literalGate` 对 `\s`/`\d` 的既有误提取未修（改召回属语义变更，见 0.5.6）。
- 模板索引目录戳在非本地文件系统/极端时序下的漏检窗口（宁少报，见 0.5.6）。
- `-race` 仍需 CGO 环境（本机无 gcc；新增并行代码建议 CI 补 `go test -race ./internal/{sitelens,engine,nuclei,httpx}`）。
- 仍可继续做的：litindex 换 AC 自动机再省 ~1ms/页；`convertMeta` 的 `(?i)` CVE 正则（冷构建剩余最大单文件开销 ~30µs）；src/header 通道接条件树。

### 0.7 第三轮：效率轮实录（2026-10-30，WAF-aware 自适应限速 + 请求去重）

> 目标：第二轮把 CPU 成本压掉后，扫描墙钟 ≈99.6% 是限速睡眠（本地 775 请求 /
> 400ms 配置 155s、1ms 后 0.6s）——从「算得快」转向「单位时间产出更多，且不伤害
> 被扫目标」。完整设计与实测见 `docs/release-5.2.0/效率轮-5.2.0.md`。

#### 0.7.1 前后数字（同 fixture：4 页带表单/带参 + 2 个可命中点，deep+DAST）

| 组 | 请求数 | 墙钟 | findings |
|---|---|---|---|
| 旧实现 af60716（worktree 独立测） | 799 | 159.95s | 2（sqli-error / xss-reflect） |
| 新 balanced（默认 `scan.rate_mode`） | **776（-2.88%）** | **156.09s（-2.4%）** | 2，逐字节等价 |
| 新 polite | 776 | 310.01s | 2，逐字节等价 |

- balanced vs 新 polite 墙钟 **↓49.6%**（自适应 400ms→200ms 硬下限）。
- 相对旧实现墙钟只快 2.4%：旧 `wait()` 的 pairing 缺陷让实际速率恰好 ≈5 rps，与
  balanced 下限同速——墙钟收益只能来自请求数下降，这是「不伤害目标」前提下的必然结果。
- 目标侧负载：balanced 平均 **≤5 req/s/主机**（峰值 1s=6，与旧实现同口径）、
  最大并发 1（未增加并发）；RTT 恶化/WAF 信号自动退避并锁定低速。
- 想要更快：`scan.rate_max_rps` 可调高（如 8 → 约 -35% 墙钟、平均 8 req/s），
  **默认 5 保持保守，只建议自控靶场调高**。

#### 0.7.2 改了什么

- **httpx**：旧 `wait()`（先设 last 再睡 → 并发齐发 N/interval）重做为 **per-host 共享
  令牌桶**（容量 1、全进程共享、空闲 5min TTL）；polite 档语义修正为真实固定间隔
  （400ms=2.5 rps）；balanced 档 400ms 起步→连续成功减半→**硬下限 200ms**（间隔高于
  下限才 ±20% 抖动）；RTT EWMA 恶化自动退避；429/503/Retry-After/WAF 特征头/挑战页/
  2xx→403 降级 → `Resp.Blocked/BlockReason` + 锁定低速（400ms→1s→2s 只增不减）；
  `Stats()` 指标；SSRF/解析链路零改动。
- **engine/dast/crawler**：DAST benign 基线跨通道复用（payload 绝不复用；时间差分复用
  携带真实 RTT 防误报）、只读页面响应单扫描复用、crawler additive `SetPageHook` 逐页
  流式指纹/被动（默认 nil 逐字段等价）、主页/robots/favicon/种子页去重、blocked 隔离
  （首页被拦终止/爬取页不进分析集/jsmap 拦截隔离/DAST 被拦不判定/checks 命中按 URL 过滤）、
  `Result.Diagnostics` 诊断账本（additive）。
- **config**：`scan.rate_mode: balanced|polite`（默认 balanced；未知值按 polite 保守
  处理）、`scan.rate_max_rps`（默认 5）；`.sitelens.example.yml` 同步。

#### 0.7.3 新增门禁

| 门禁 | 文件 | 作用 |
|---|---|---|
| 令牌桶/上限/polite 不夹 | `internal/httpx/ratelimit_test.go` | 跨 Client 共享、目标侧峰值、polite 0/1ms 不被夹、WAF 识别、RTT 退避 |
| 基线复用等价 | `internal/dast/baseline_reuse_test.go` | 同一请求只发一次 + 复用 vs 不复用 findings 等价 |
| 流式/blocked/账本 | `internal/engine/efficiency_test.go`、`engine_parallel_test.go` | 页序一致/回调串行/favicon 一次/blocked 不判定/diagnostics additive |
| crawler hook 等价 | `internal/crawler/pagehook_test.go` | 默认 nil 逐字段等价 + 零额外请求 |

#### 0.7.4 遗留

- 模板/DAST 未并行：共享令牌桶下并行不提高 RPS，却引入 Verified 合并顺序与 `-race`
  风险，收益为 0，故保持串行。
- blocked URL 过滤覆盖 checks/nuclei；默认关闭的目录/子域模块内部请求未做 URL 过滤
  （其响应不进 DAST 判定，影响面小）。
- 本机无 CGO/gcc，`-race` 需 CI 复核（本轮新增共享令牌桶/流式并发，CI 会跑）。
- 目录探测/登录爆破沿用各自模块限速节奏，未纳入 host 令牌桶语义变更。

---

---

## 1. P0 — 严重（3 条，建议第一批处理）

### BUG-001 🔴 CVSS 计分三处缺陷 → 41.42% 的向量分数与官方不符

**位置**：`internal/intel/cvss.go`
**证据**：✅ 实测（用仓库自带 `data/nvd_cves.json.gz` 的 292,036 条 NVD 官方分 + 向量全量交叉验证）

**现象**：SiteLens 算出的 CVSS v3.1 基础分与 NVD 官方分在 **120,952 / 292,036（41.42%）** 的向量上不一致，且会**跨严重度等级**（high↔critical、medium↔high、low↔medium）。

**根因（三个叠加）**：

| # | 缺陷 | 位置 | 单独贡献 |
|---|---|---|---|
| a | `cvssAV["L"] = 0.39`，**应为 0.55**（0.39 是 CVSS **v2** 的值，误用进 v3.1 表） | `cvss.go:13` | 23.29% |
| b | **Scope Changed 缺 ×1.08 系数**（规范：Base = 1.08 × (Impact + Exploitability)） | `cvss.go:122` | 19.92% |
| c | **PR 权重依赖 token 顺序**（`S` 在 `PR` 之后才用 Changed 权重） | `cvss.go:77-81` | 11.10% |

**为什么 b 和 c 必然同时发作**：NVD 规范向量顺序恒为 `AV:AC:PR:UI:S:C:I:A`，**S 永远在 PR 之后**。实测全部 292,036 条中 **100% 是 S_after_PR** → 每个 `S:C` 向量都用错了 PR 权重。

**实例**：

| CVE | 向量 | NVD 官方 | SiteLens 现状 |
|---|---|---|---|
| CVE-2009-3616 | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | **9.9 critical** | 8.9 **high** |
| CVE-2001-0006 | `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | **7.1 high** | 6.5 **medium** |
| CVE-1999-0524 | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | **4.0 medium** | 3.2 **low** |

**⚠️ CI 为什么是绿的**：`internal/intel/cvss_test.go:20` 断言
`{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.8, "medium"}`
—— **官方值是 5.4，测试把 bug 的输出写成了期望值**。修 bug 必须同时改这条断言，否则测试会红。

**修法**：

```go
// cvss.go:13 —— 修 a
var cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}

// cvss.go:42-107 —— 修 c：先解析出 scope，再决定 PR 权重（与 token 顺序无关）
// 最小改法：循环前置一个预扫描，把 S 提前解析
scopeChanged := false
for _, part := range strings.Split(v, "/") {
    if strings.HasPrefix(part, "S:") && strings.HasSuffix(part, "C") {
        scopeChanged = true
    }
}
// 之后原循环里的 S 分支只做 continue，不再改 scopeChanged

// cvss.go:122 —— 修 b
base := impact + exploitability
if scopeChanged {
    base = 1.08 * base          // CVSS v3.1 规范：Scope Changed 的 1.08 系数
}
score := roundup1(math.Min(base, 10))
```

顺带（可选，低优先级）：`cvss.go:114` 的 `3.257` 应为规范值 `3.25`（差异 <0.01，不影响 0.1 粒度）。

**验收标准**：
1. 修完后，用 `data/nvd_cves.json.gz` 全量重算，**292,036 / 292,036（100%）** 与 NVD 官方分一致，零反例。
2. `internal/intel/cvss_test.go:20` 的期望值改为 **5.4**。
3. 补一条**顺序无关性**断言：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` 与 `CVSS:3.1/AV:N/AC:L/S:C/PR:L/UI:N/C:H/I:H/A:H` 必须同分（当前分别得 8.9 / 9.2）。
4. 补一条 AV:L 断言：`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` == **8.4**。

**影响面**：所有漏洞的严重度评分、情报关联的 `confirmed` 展示、报告导出的 CVSS 列、ML 的 `sev_score` 旁证。

---

### BUG-002 🔴 复现命令的 Shell 注入 → 打穿「证据链可复现」红线

**位置**：`internal/dast/formblind.go:129-132`
**证据**：🔍 代码读证（`action`/`field` 的目标可控性已追到 `htmlx.go:196` 与 `crawler.go`）

```go
func formReplay(action, field, payload string) string {
	return "curl -sk --path-as-is -d '" + field + "=" +
		strings.ReplaceAll(payload, "'", `'\''`) + "' '" + action + "'"
}
```

**现象**：`payload` 被转义了，**`field` 和 `action` 裸拼**。而两者都来自**被扫站点的 HTML**：
- `action` ← 表单 `action` 属性（`internal/htmlx/htmlx.go:196` 原样取值）
- `field` ← 表单控件 `name` 属性（`internal/crawler/crawler.go:211-214,230-231`）

恶意站点放 `<form action="/x' ;id > /tmp/pwn;echo '">` → 生成的"一键复现"命令变成
`curl -sk --path-as-is -d 'field=value' '/x' ;id > /tmp/pwn;echo ''`
→ 分析员复制粘贴到 shell 即执行任意命令。

**调用点**：`formblind.go:115`、`authbypass.go:109`、`deep.go:333`。

**修法**（3 行，复用项目里已有的助手）：

```go
// internal/checks/runner.go:612 已有正确实现，请复用（导到共享位置或复制）
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// internal/dast/formblind.go:129 —— 改法
func formReplay(action, field, payload string) string {
	return "curl -sk --path-as-is -d " + shellQuote(field+"="+payload) + " " + shellQuote(action)
}
```

**验收标准**：
1. 补单测：`formReplay("/x' ;id ;echo '", "q' ;id ;echo '", "1")` 的输出中，**单引号数量必须成对**（每处 `'` 都变成 `'\''`）。
2. 同一 shellQuote 助手应被 `internal/checks` 与 `internal/dast` 共用（避免两份实现漂移）。
3. 人工核对一条表单类发现的 `replay` 字段：粘贴到 cmd.exe / bash 都不应报语法错误。

---

### BUG-003 🔴 `allow_private` 打开后云 metadata IP 不再阻断

**位置**：`internal/target/validator.go`
**证据**：🔍 代码读证 + 与代码自身注释矛盾

**现象**：代码注释（`validator.go:51-54`）承诺：

> 开启后仅放宽私网/保留地址与本地主机名校验——云厂商 metadata 端点与 gov.cn 硬保护**不受本开关影响、永不放宽**。

但实际代码：

```go
validator.go:143   if !allowPrivate && isBlockedIP(addr) {   // 开关一开，整段 IP 阻断被跳过
validator.go:167   if !allowPrivate && isBlockedIP(addr) {
validator.go:20    var alwaysBlockedHosts = map[string]bool{"metadata.google.internal": true}  // 只有主机名
```

**永久名单只有主机名 `metadata.google.internal`，没有 `169.254.169.254`**（AWS/GCP/Azure 标准元数据地址）与 `100.100.100.200`（阿里云）。

**后果**：开启 `target.allow_private`（授权内网扫描的正常操作）后，
`http://169.254.169.254/latest/meta-data/iam/security-credentials/` 可被扫描器拉取，
**响应体进入证据快照与 `data/state/history.json`** → 扫描机若跑在云主机上，**IAM 临时凭据泄露**。

**修法**：

```go
// validator.go:20 附近 —— 把 metadata IP 段从 allowPrivate 里拆出来
var alwaysBlockedIPs = []netip.Prefix{
    netip.MustParsePrefix("169.254.169.254/32"),   // AWS/GCP/Azure
    netip.MustParsePrefix("100.100.100.200/32"),    // 阿里云
    netip.MustParsePrefix("fd00:ec2::254/128"),    // AWS IPv6
}

// validator.go:143 / 167 —— isBlockedIP 拆成两层
if !allowPrivate && isBlockedIP(addr) { ... }        // 私网/保留地址：受开关控制
if isAlwaysBlockedIP(addr) { return "", "", 0, &Error{...} }  // metadata：永不放宽
```

**验收标准**：
1. 补单测：`target.Validate("http://169.254.169.254/latest/meta-data/", ...)` 在 `allow_private=true` 时**仍必须报错**。
2. `metadata.google.internal` 的现有行为不变。
3. `gov.cn` 现有行为不变。

---

## 2. P1 — 高（5 条，建议第二批）

### BUG-004 🟠 KEV map 无锁并发读写 → 整个 serve 进程崩溃

**位置**：`internal/intel/kev.go:60`（写）、`internal/intel/kev.go:111`（读）
**证据**：🔍 代码读证

**现象**：`MergeKEV` 原地写 `k.kev[key] = true`（`:60`）**无锁**；`IsKEV` 读 `k.kev[...]`（`:111`）**无锁**。
KEV 守护 goroutine（`internal/server/server.go:309-316`，启动即跑 + 每 `update_hours`）调 `MergeKEV`，同进程扫描线程在 `internal/intel/intel.go:450` 读 `k.kev`。

**后果**：Go 的 `fatal error: concurrent map read and map write` —— **不可 recover，整个 serve 进程崩溃**（不只是单次请求失败）。`Engine.activeScans` 只保护 `Release()`，管不到 `MergeKEV`。

**修法**：`KB` 内给 `kev` 加 `sync.RWMutex`（或改 copy-on-write：合并到新 map 再整体替换指针）。
**验收**：补并发用例——一个 goroutine 循环 `MergeKEV`，另一个循环 `IsKEV`，`-race` 下必须干净。

---

### BUG-005 🟠 CLI 全局 flag 放在子命令后被静默忽略

**位置**：`cmd/sitelens/main.go:76`（`flag.Parse()`）
**证据**：✅ 实测（A/B 对比）

```
A) sitelens -config <cfg> scan <target>   →  ✅ 扫描成功
B) sitelens scan <target> -config <cfg>   →  ❌ exit 1
   "error": "目标解析到内网/保留地址，已拦截"   ← cfg 里的 allow_private:true 完全没生效
```

**根因**：Go 的 `flag.Parse()` 遇第一个非 flag 参数即停止解析，`serve` / `scan` 之后的 `-config` / `-graph` / `-ast` 全部落进 `flag.Args()` 被丢弃。

**作者已知但没推广**：`main.go:86-97` 为 `update-seed` 单独补了局部 `FlagSet`（`--seed-dir` / `--user-dir`），同样手法没用到全局 flag。

**影响**：所有按"子命令 + 参数"自然直觉写命令的用户，配置**静默失效且不报错**。

**修法**：在 switch 之前对 `flag.Args()` 做一次已知全局 flag 的补扫（复用 `update-seed` 的局部 `FlagSet` 模式）。
**验收**：补 `cmd/sitelens/main_test.go` 用例——`-config` 前置与后置必须产生相同 cfg。

---

### BUG-006 🟠 任意文件写

**位置**：`internal/server/settings.go:102`（写入点）→ `internal/intel/overrides.go:47`（落盘点）
**证据**：🔍 代码读证

**现象**：`settings.go:102` `s.cfg.Intel.OverridesPath = v.Intel.OverridesPath` —— **零路径校验**（该文件全文没有 `filepath.Abs` / `HasPrefix` / `underDataDir` 任何一处）。
`settings.go:138` 还把它持久化进 `.sitelens.yml`（重启后依然生效）。
随后 `POST /api/osv-sync` → `intel.SaveOverrides(path, ov)` → `os.WriteFile(path, data, 0o644)` → **写到任意路径**。

**修法**：`overrides_path` 限定在固定数据目录内（`filepath.Abs` + 前缀校验），或从远程可写键集中移除。
**验收**：补 API 用例——`PUT /api/settings` 传 `overrides_path: "../../evil.json"` 必须被拒。

---

### BUG-007 🟠 版本区间判定截断 4 段版本号 → 误报 confirmed

**位置**：`internal/versioncmp/versioncmp.go:17-27`
**证据**：✅ 实测（8 个用例，3 个错）

**现象**：`Parse` 只取前 3 段（`if i >= 3 { break }`），导致 4 段版本号与 3 段版本号**判为相等**。

```
1.2.3.4         <=1.2.3       实际 true   期望 false   ★不符
10.0.19041.1234 <=10.0.19041 实际 true   期望 false   ★不符
4.17.3.0        <=4.17.3      实际 true   期望 false   ★不符
```

**后果**：4 段版本号（Windows 补丁号 `10.0.19041.1234`、Java/Oracle 方案）在「受影响区间」判定中被误判为**受影响** → 情报三级判定产出**误报 confirmed**。这是产品最忌讳的错误类型。

**修法**：`Parse` 改为返回不定长切片（或至少 4 段），`Cmp` 逐段比较并补齐长度。
**验收**：补上表三个用例的断言；另加 `10.0.19041.1234` vs `>=10.0.19041` 应为 true。

---

### BUG-008 🟠 重定向循环中间跳的 response body 不关闭

**位置**：`internal/httpx/client.go:161-192`
**证据**：🔍 代码读证

**现象**：重定向循环里每跳 `resp, err = c.http.Do(req)`（`:169`），若是 30x 且 Location 有效则进入下一跳，**上一跳的 `resp` 既没读也没关**。只有最后一跳走 `toResponse(resp, cur)`（`:192`）才有 `defer resp.Body.Close()`（`:351`）。

`:188` 的 SSRF 拒绝路径 `return nil, verr` 同样漏关当前 body。

**后果**：每跳泄漏 1 个连接 + 1 个 transport readLoop goroutine → 长扫描下 fd/goroutine 单调增长 → `too many open files`。
**修法**：循环内进入下一跳前 `resp.Body.Close()`（建议 drain 后关闭以便连接复用）。
**验收**：补用例——重定向 5 跳后统计 transport 的连接数不增长。

---

## 3. P2 — 中（13 条，第三批）

| ID | 位置 | 现象 | 修法要点 | 验收 |
|---|---|---|---|---|
| **BUG-009** | `internal/store/store.go:268` `TopTechs` | `s.h.Scans[i].Result.Technologies` 无 `Result == nil` 判定 → `GET /api/stats` panic。可达性由**仓库自有注释**证实（`internal/server/export_test.go:14-18`："result 为 null 的历史记录会 nil 指针 panic…该形态被视为可达（导入迁移/写库中断均可产生）"）。当时只修了 export 路径，漏了这里 | 加 `if r.Result == nil { continue }` | 补用例：导入一条 `result:null` 记录后 `GET /api/stats` 返回 200 |
| **BUG-010** | `internal/server/reload.go:93` + `server.go:458,473-474,879,886` | `s.techIDs, s.techCnt = m.cats, m.count` **无锁换枪**，并发读 `len(s.techIDs)` / `range s.techIDs` → slice header 撕裂 → 越界 panic | 改 `atomic.Pointer[[]string]` 整体换枪 | 补并发用例：`reloadIfDataChanged` 与 `/api/categories` 并发 |
| **BUG-011** | `internal/server/settings.go:81`（写，持 `cfgMu`）vs `server.go:325-326`（读，**无锁**） | `apiToken` 是 string（2 字 header），写加锁读不加锁 → 字符串头撕裂 → 切片越界 panic，或鉴权旁路 | 读侧也取 `cfgMu`，或换 `atomic.Pointer[string]` | 补并发用例：设置页保存与 `/api/*` 请求并发 |
| **BUG-012** | `internal/engine/engine.go:1323` `loadNucleiLRU` | `m := map[string]int64{}` + `json.Unmarshal(data, &m)`：**JSON `null` 会把 map 置 nil 且 err 为 nil**（✅ 实测确认）→ `e.nucleiLRU = nil` → 后续 `e.nucleiLRU[ent.Path] = now` → `panic: assignment to entry in nil map` | 解包后判 `if m == nil { m = map[string]int64{} }` | 补用例：`nuclei_schedule.json` 内容为 `null` 时不 panic |
| **BUG-013** | `internal/checks/prior.go:68-80` | `checkIndex` 由 `sync.Once` 建一次，但 `ConfigurePlugins`（`checks.go:170-179`）热重载 `userPlugins` 时**不失效 checkIndex** → `IsExtended`（`engine/mlprior.go:62`）对新插件永久返回 false → **静默漏检** | `ConfigurePlugins` 里失效 `checkIndex`（或改带版本号的 atomic 快照） | 补用例：先触发一次建索引，再投放插件，断言新插件能被 `IsExtended` 命中 |
| **BUG-014** | `internal/intel/osv.go:132` 经 `overrides.go:38` | `MergeOverrides(k.vulns, ov)` 原地 `sort.Slice(k.vulns, ...)`，而 OSV 同步 goroutine（`server/settings.go:216`）执行、扫描线程正在 `intel.go:414` 遍历 `k.vulns` → **CVE 与情报错配（静默错误结论）** | 覆盖写在新副本上，再整体替换 `k.vulns` | 补并发用例：同步与扫描并发时结果不串 |
| **BUG-015** | `internal/modules/modules.go:240,286-287`（配合 `:151,157`） | `attempts` 取址 `&attempts` 传给 `tryBypass403`，被 8 个 dirWorker 各自 `*attempts++` → 丢更新 → **突破 `bypassMaxAttempts` 硬上限** | 改 `atomic.Int64` | 补并发用例：403 场景下实际请求数 ≤ 上限 |
| **BUG-016** | `internal/nuclei/afrog.go:24-36`、`:93`、`:103` | `afrogRule` **没有 `expression` 字段**（yaml.v3 静默忽略未知字段），而 afrog 模板的判定全写在 rule 级 `expression` 里 → `afrogNorm` 拼不出 matcher → 整条拒收。✅ 实测 `packs/nuclei-templates.tar.gz`：**1,699 条 afrog 模板，100% 过不了漏斗**（1,687 条有 rule 级 expression，0 条有 `response:` 块） | 补 `Expression` 字段 + 实现其求值（`response.status == N` / `response.body.bcontains(...)` / `&&` / `||`） | ⚠️ **放行前必须评估误报**——这 1,699 条会真正开始产出发现。补夹具：至少 10 条真实模板的判定结果 |
| **BUG-017** | `internal/dast/dast.go:865-874`（`setParam`） | `url.Values.Encode()` 把 `%` → `%25`，预编码载荷被**编码两次**。✅ 实测：`%0d%0a...` → `%250d%250a...`、`%AC%ED%00%05sl` → `%25AC%25ED...` → 服务端单次解码拿到**字面文本**而非 CR/LF 字节/序列化魔数 → **CRLF 与反序列化两条通道实际不注入**。单测绿是因为桩件按头名子串匹配（`deep_test.go:53-58`），从不校验真字节 | 这类"要注入原始字节/控制符"的探针**不能走 `setParam`**，需一条原始注入构造路径 | 补用例：起一个真服务器，断言注入后**真的收到 CRLF**（字节级断言，不是子串） |
| **BUG-018** | `internal/dast/dast.go:627-630` + `:818-827` | `hit.Replay = formReplay(...)`（POST 语义）下一行被 `chainEvidence` 覆盖成 `curlReplay(probeURL)`（**GET 风格**），且 `probeURL` 是裸拼未 URL 编码 → 表单类发现的复现命令**复现不了真实请求** | 调换 629/630 顺序，或让 `chainEvidence` 不覆盖已有值 | 补用例：表单命中的 `replay` 必须含 `-X POST`/`--data-raw` |
| **BUG-019** | `internal/engine/ml.go:69` | `assets := e.cfg.ML.AssetsDir`（默认 `data/go/ml_assets`，**仓内不存在**），而资产在 `models/go/ml_assets`（✅ 实测存在，16 个文件含 4 个 ONNX）→ glob 落空 → **ONNX 通道恒不可用**，恒回退 NVD 先验。⚠️ 该文件 `:39-41` 注释原文写着"曾因两处各自维护、测试漏跟迁移而恒读不到资产"——**同一类 bug 原样复发** | 改用 `ml.LocateAssetsDir(...)` 同源候选（`:42` 的线性模型路径已正确） | 补用例：`sev_onnx` 开启时能加载到 `models/go/ml_assets` 的 ONNX |
| **BUG-020** | `Dockerfile:26-28` | 镜像只 COPY 了 `data/go` + `data/affected_ranges.json` + `data/wordlists`。**缺** `data/intel_dump.json.gz`（含 KEV 表）、`data/nvd_cves.json.gz`（37.8MB）、`data/tpl_intel.json.gz`、`data/state/kev_extra.json`、**模板池**（`packs/`）、**ML 模型**（`models/`）→ 容器里情报关联/KEV/CVSS 补全/模板子集/ML 预测**全部静默降级**。注释只提了 `intel_dump.json.gz` | 要么补 COPY，要么把缺失清单写进镜像文档。⚠️ 单文件挂载陷阱：宿主文件不存在时 Docker 会创建**目录**，`intel_dump.json.gz` 变目录 → 加载失败 | 补检查脚本：构建镜像后跑 `docker run ... /app/sitelens -version` + 抽查各能力是否降级 |
| **BUG-021** | `internal/target/validator.go:157-172` + `internal/httpx/client.go:85-90` | `ensurePublicHost` 用 `net.LookupHost` 校验后即释放；`httpx.Client` 未设 `Transport.DialContext`，实际连接由系统解析器**二次解析** → **DNS 重绑定**绕过 SSRF 闸。`internal/netx/netx.go:118-124` 同样"先校验后拨号"，且该包 `:11-12` 注释**已自认此缺口** | 一次解析、校验 IP 集合、按**已校验 IP** 拨号（保留 Host/SNI），重定向逐跳重复 | 补用例：DNS 返回不同 IP 的桩服务 |

---

## 4. P3 — 低（10 条，第四批 / 随手做）

| ID | 位置 | 现象 | 修法要点 |
|---|---|---|---|
| **BUG-022** | `internal/nuclei/nuclei.go:552-555` | `path = req.Path[0]` —— path 列表只取第一项。✅ 实测：wordfence 模板 path 列表有 **11 个**候选路径，只探测第 1 个（覆盖率损失 11→1，非"退化成根探测"） | `normFromTpl` 支持多 path，或在 `Entry` 层展开。⚠️ 需评估预算影响（82,710 条 × 11） |
| **BUG-023** | `cmd/sitelens/update_nuclei.go:25`、`update_afrog.go:28`、`update_fp.go:28`、`update_ehole.go:28` | 更新通道**无 sha256/签名校验**；`update_ehole.go:28` 显式允许 `http://` 前缀 | 固定 URL + 校验 sha256；禁用 `http://` |
| **BUG-024** | `internal/store/store.go:329,144`、`internal/server/settings.go:149` | `history.json` / `history.archive.jsonl` 以 **0644** 落盘（含目标响应片段、登录爆破命中）；配置写回同样 0644（新文件时含 `web.api_token`） | 改 0600 |
| **BUG-025** | `.gitattributes` | 全文只有 2 行 LFS 规则，**缺 `* text=auto eol=lf`**。本机 `core.autocrlf=true` → 工作区 CRLF → `gofmt -l` 把每个文件都标红，Windows 开发者会误判自己改坏了格式 | 补 `* text=auto eol=lf` |
| **BUG-026** | `internal/versioncmp/versioncmp.go:152-154` | `Round1` 用 `math.Round`（四舍五入），CVSS 3.1 规范要求 **Roundup**（向上取整）。且**全仓无调用方**（死代码） | 删除，或改名并改用 `intel/cvss.go` 的 `roundup1` |
| **BUG-027** | `internal/rex/exec.go:90-103` | 10 万步预算按"每个起始位置"重置 → 总开销可达 预算 × 输入长度 | 改为全次调用共享预算（需评估误报率变化） |
| **BUG-028** | `ml/requirements.txt`、`ml/train_cwe.py:140`、`ml/train_sev_v31_deploy.py:34` | `requirements.txt` 只有 numpy/pandas/scikit-learn/pytest，**缺 torch/transformers**（sev 训练要用）；训练脚本**硬编码绝对路径** `D:\fengqiao\Desktop\26-08python实训\...` → 本仓无法重训 | 补依赖；路径改环境变量/配置文件 |
| **BUG-029** | `internal/dast/dast.go:627`、`formblind.go:129-132` | 表单路径的 `probeURL` 是裸拼 `action + "?" + field + "=" + value`，**未 URL 编码**；`formReplay` 里 action 的单引号未转义 | 与 BUG-002 一并修 |
| **BUG-030** | `cmd/sitelens/migrate_pg.go:132` | DSN 含**明文口令**且 `sslmode=disable` | 改从环境变量读；`sslmode` 走配置 |
| **BUG-031** | `internal/store/store.go:323-332` | `Store.flush()` 写失败**静默**（磁盘满时历史静默丢失，无日志无告警） | 写失败打 stderr 或计入 metrics |

---

## 4.5 用户反馈新增项（2026-10-28 规划期收集，均已在代码中核实根因）

> 以下 5 条缺陷 + 2 条需求项来自 5.2 规划期的用户反馈，**已逐条在代码中核实**。
> 与 §1~§4 的 31 条是**独立增量**，编号续排。

### BUG-032 🟠 桌面端启动时弹出控制台窗口

**位置**：`desktop/build-engine.js:29`、`desktop-wails/main.go:114-117`
**证据**：🔍 代码读证（构建脚本 + 壳侧拉起逻辑）

**根因（两个叠加）**：

```javascript
// desktop/build-engine.js:29 —— 引擎缺 -H windowsgui
const LDFLAGS = '-s -w';          // 对比：壳侧 desktop-wails/main.go:14 是 "-s -w -H windowsgui"
```

```go
// desktop-wails/main.go:114 —— 拉引擎时未设 HideWindow
cmd := exec.Command(engineExe, "-config", cfgPath, "serve")
cmd.Dir = engineDir
cmd.Stdout = nil
cmd.Stderr = nil
// ← 缺 cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
```

**说明**：`cmd.Stdout = nil` **不能**阻止控制台窗口出现（那只是不接管输出流）；`HideWindow` 才是控制台子系统的开关。对比同文件 `update.go:115` 拉起 NSIS 安装器时**是设了** `HideWindow` 的——引擎这条路径漏了。

**修法**：
1. `desktop/build-engine.js:29` → `const LDFLAGS = '-s -w -H windowsgui';`
   ⚠️ 注意：引擎的 `serve` 模式若依赖 stdout 打印日志，需先确认——桌面形态下日志应走文件（`shell.log`），不能靠 stdout。
2. `desktop-wails/main.go:114` 之后补 `cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}`（Windows 专用，需 build tag 或按 `runtime.GOOS` 分支）。

**验收**：启动与退出全程无控制台窗口（录屏或任务管理器确认无 `conhost.exe` 子进程）。

---

### BUG-033 🟠 桌面端退出时闪现控制台窗口

**位置**：`desktop-wails/main.go:269-277`
**证据**：🔍 代码读证

```go
func killEngineTree(p *os.Process) {
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(p.Pid), "/T", "/F").Run()
	}
	_ = p.Kill()
}
```

**根因**：`taskkill` 是**控制台程序**，`exec.Command` 拉起它会闪一个黑窗。

**修法**（三选一，从优到劣）：
1. **Windows Job Object**：把引擎放进作业对象，退出时 `TerminateJobObject` 一次性回收整棵树——不需要外部命令，也不闪窗（推荐）；
2. `exec.Command("taskkill", ...)` 补 `SysProcAttr{HideWindow: true}`（治标，且仍有短暂闪烁）；
3. 只用 `p.Kill()`（**会留下子进程**，引擎自己派生的子进程可能残留——不推荐）。

**验收**：退出后 `tasklist` 无残留 `sitelens.exe` / `conhost.exe`；退出全程无窗口闪现。

---

### BUG-034 🟠 前端失败只有一句 "Failed to fetch"，且异常被静默吞掉

**位置**：`web/js/common.js:249-267`（`asJson` / `window.api`）
**证据**：🔍 代码读证

```javascript
function asJson(r) {
  return r.json().then(function (j) {
    if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
    return j;
  });
}
window.api = {
  get: function (u) { return fetch(u, { headers: tok() }).then(asJson); },
  ...
};
```

**三个叠加问题**：

1. **不区分失败类型**：
   - 网络层失败（引擎未起 / 端口不通 / 进程已退出）→ `r.json()` reject，抛浏览器原生 `TypeError: Failed to fetch`，**不带 URL、不带状态码、不带原因**；
   - 响应非 JSON（如引擎返回 HTML 错误页）→ 抛 `Unexpected token '<'`，同样无上下文；
   - 只有 `!r.ok` 且响应是 JSON 时，才有可读信息（`j.error`）。
2. **异常被静默吞掉**：大量调用点写成 `.catch(function () {})`，例如 `common.js:458` 的 `fillVersion` —— 界面**什么都不显示**，只在开发者控制台留一行红字。
3. **无"引擎不可达"的界面态**：引擎退出或端口变更后，页面所有请求都失败，但页面还停在旧内容上，用户只看到"什么都点不动"。

**修法**：
1. `asJson` 改为**先判 `r.ok` 再解析**，并把三类失败包成带上下文的错误：
   ```javascript
   function asJson(r, url) {
     return r.text().then(function (txt) {
       var j = null;
       try { j = JSON.parse(txt); } catch (e) { /* 非 JSON */ }
       if (!r.ok) throw new Error((j && j.error) || ("HTTP " + r.status) + " @ " + url);
       if (j === null) throw new Error("响应非 JSON（可能被网关/代理替换）@ " + url);
       return j;
     }).catch(function (e) {
       if (e instanceof TypeError) throw new Error("无法连接引擎服务（引擎可能未启动或已退出）@ " + url);
       throw e;
     });
   }
   ```
2. `window.api` 各方法传 `u` 进 `asJson`。
3. 加**全局失败提示**：`window.addEventListener("unhandledrejection", ...)` → toast；并把关键调用点的空 catch 改成"至少提示一次"。
4. 加"引擎不可达"界面态：连续 N 次失败后显示"引擎未就绪 / 已退出（原因）"，并提供重试按钮。

**验收**：
1. 单测：mock `fetch` 分别返回网络失败 / 500 JSON / 200 HTML，三种情况的错误信息都必须**含 URL 或原因**，不得出现裸的 "Failed to fetch"。
2. 人工：杀掉引擎进程后，界面应出现明确提示而非静默无反应。

---

### BUG-035 🟠 安装包过大（模型资产整套随包分发）

**位置**：`models/go/ml_assets/`、`desktop/build-engine.js`、`tools/wails_build.sh`、`desktop-wails/main.go`（种子交付）
**证据**：✅ 实测（本地逐目录统计）

**实测构成**：

| 组成 | 体积 | 占比 |
|---|---|---|
| **ML 模型资产** | **748.9 MB** | **84%** |
| 情报与指纹库（`data/`） | 51.7 MB | 6% |
| 模板包（`packs/`） | 46.8 MB | 5% |
| 前端（含 Monaco，12.1MB） | 12.1 MB | 1% |
| 依赖 + 图标 | 32.0 MB | 4% |
| **合计** | **891.4 MB** | |

**ML 资产明细**（4 个 ONNX 合计 **643.3MB**）：

| 文件 | 体积 |
|---|---|
| `sev-prior-v3.1-a.onnx` | 255.5 MB |
| `sev-prior-v3.1-b.onnx` | 255.5 MB |
| `sev-prior-v3.1-a-int8.onnx` | 66.1 MB |
| `sev-prior-v3.1-b-int8.onnx` | 66.1 MB |
| `cve-tech.coef.f32` | 89.7 MB |
| `cwe-type.coef.f32` | 11.4 MB |
| 其余（词表/idf/meta/fixtures） | ≈ 4.3 MB |

**根因**：fp32 与 int8 **两套全量同时随包分发**，而推理只需其中一套；线性模型系数未做量化。

**修法（按收益排序）**：
1. **int8 优先**：只带 int8（132MB），fp32 移入可选高级包。⚠️ 需先实测 int8 的 MAE 损失（当前 fp32 的 test MAE 为 1.07）。
2. **模型资产按需获取**：安装包只带轻量线性模型（`cve-tech` + `cwe-type` ≈ 103MB），ONNX 严重度模型首次使用时按需下载（注意 `desktop-wails` 的种子交付机制与 `update-seed` 子命令已具备按目录投放的能力，可复用）。
3. **线性模型系数压缩**：`cve-tech.coef.f32` 89.7MB（196 类 × 特征数 × 4B）做量化（如 fp16）或稀疏化。
4. **Monaco 按需加载**：`web/monaco/` 11.6MB 目前全量嵌入，且 `//go:embed monaco` 进二进制——可改为按需下载或裁剪子集。

**验收**：出包后统计安装包体积，相比 5.1.0 的 744MB 有明确下降；且**安装后全部模型能力仍可用**（含 onnx 通道，需回归 `ml_sev` 相关用例）。

---

### FEAT-001 📋 应用内反馈页（需求项，非缺陷）

**现状**：仅 `web/settings.html:361-374`「帮助与反馈」节给了一个**外部** Issues 链接，用户需自行整理版本号、复现步骤、环境信息。

**拟做**：
- 新增 `web/feedback.html` + 注册路由（`internal/server/server.go:173-178` 的 `pages` map）+ 导航项（`web/js/common.js` 的 `NAV` / `ICONS` / `I18N`）
- 新增 `POST /api/feedback`：接收**脱敏诊断包**（引擎版本、引擎日志、错误栈、耗时曲线），**默认不含目标地址与响应片段**，用户可预览/删减后再提交
- 复用 `internal/store` 的诊断信息采集；注意 `guard` 中间件只保护 `/api/` 前缀，反馈接口同样需要 Token（`server.go:325`）

**验收**：应用内可提交反馈；诊断包内容在提交前可见可删；不含未经脱敏的目标数据。

---

### FEAT-002 📋 埋点 / 崩溃上报（**产品决策项，需拍板后再实施**）

⚠️ **这一条与现有产品承诺直接冲突，实施前必须由产品侧拍板。**

**现状**：`web/settings.html:454`（《用户服务协议》）明确声明：

> 「本软件无账号体系、**无埋点**、无遥测、无崩溃上报、无广告组件。开发者的服务器不接收您的任何扫描数据、目标信息、机器信息、网络拓扑、使用行为或崩溃信息。开发者因此在技术上**不具备**收集或回溯您任何使用行为的能力。」

这是**写进用户协议的合规卖点，不是遗漏**。

**若要引入，需同步完成**：
1. 修订《用户服务协议》与设置页隐私声明（当前声明具法律效力）
2. 决定采集范围与**默认开关**（建议默认关闭 + 明确征得同意）
3. 明确数据保留期与删除机制
4. 重新评估"可追溯/可评估"与"不采集用户数据"之间的张力

**推荐折中（本次规划采用）**：**不做常驻埋点**，改为「本地诊断包 + 用户主动提交」（即 FEAT-001 的实现）。既满足"失败有信息、可反馈"的诉求，又不破坏隐私承诺。

---

## 5. 文档漂移（13 条，随代码修一并改）

代码与文档不一致会持续误导接手人。建议在对应代码修复的同一个 MR 里一起改。

| ID | 文档说法 | 代码实际 | 位置 |
|---|---|---|---|
| **DOC-001** | README「非 localhost 必须配 API Token，否则进程直接退出」 | **只打一条 warning，照常启动** | `internal/server/server.go:276-278` |
| **DOC-002** | README「零依赖零构建」 | 前端硬编码 Google Fonts CDN + jsDelivr 注入 turbo.js | `web/app.html:8-9`、`web/js/common.js:17` |
| **DOC-003** | `开发文档.md:79,136` 索引缓存 "schema v5" | **`cacheSchema = 8`** | `internal/nuclei/nuclei.go:51` |
| **DOC-004** | `开发文档.md:224` "索引缓存 v7" | 同上，v8 | 同上 |
| **DOC-005** | `开发文档-4.0.md`「同 host 归组 + 稳定 ID 相邻连边」 | 代码里**没有 host 分组**，实际是 `EntryID` 因果 | `internal/chain/chain.go` |
| **DOC-006** | 配置注释「`rate_interval_ms: 0` = 不限速」 | `fillInt` 把 0 也回退成 400，**写 0 达不到不限速** | `internal/config/config.go:414-421` |
| **DOC-007** | 同上，`crawler.timeout_sec: 0` = 不限 | 恒回退 60 | 同上 |
| **DOC-008** | 同上，`intel.update_hours: 0` = 关闭 KEV 自动更新 | 恒回退 24 | 同上 |
| **DOC-009** | 模型卡写 sev-prior v2 / acc 0.5221 / 产物在 `data/ml/` 不进 git | 名册是 **v3.1 / MAE 1.07** / 资产**已进仓** `models/go/ml_assets/` | `ml/model_registry.json` vs `docs/5.0-模型卡.md` |
| **DOC-010** | README「ML 预测不改变任何扫描判定」 | `mlPrior` 把产品先验转成 **check 提权表并新增 check id** → 会改变本次执行的 check 集合 | `internal/engine/engine.go:493-497` → `internal/engine/mlprior.go:32` |
| **DOC-011** | `internal/astx/astx_cgo.go:26-29` 注释「PHP 未纳入」 | 同文件 `:37-38` 已接 `phpgram.GetLanguage()` | `internal/astx/` |
| **DOC-012** | `desktop-wails/README.md:83`「自动更新已接线（v5.2）」 | `desktop-wails/version.go` 仍是 5.1.0 | — |
| **DOC-013** | `docs/产品说明.md` 是 v3.0.0 版本 | 未覆盖 4.0 事实图 / 攻击链 / 5.0 ML | — |

---

## 6. 已排除的误报（**不要去改这些**）

扫描过程中出现过、但经核查**确认为误报或非缺陷**的项，列此避免重复排查：

| 项 | 结论 | 依据 |
|---|---|---|
| HTML 报告 XSS | **无此问题** | `internal/server/report.go` 全部经 `html.EscapeString` |
| CSV 公式注入 | **无此问题** | 单元格均为固定前缀（"Server="、"meta "、"cookie "）或数字开头（`internal/sitelens/fingerprint.go:288-294` 要求版本首字符为数字），无 `= + - @` 起始 |
| 解压穿越 / zip slip | **无此问题** | `internal/server/helpers.go:66-72` 拒 `..`/绝对路径并跳过符号链接；`internal/nuclei/sync.go:57-77` 同样安全 |
| 证据链泄露凭据 | **无此问题** | `internal/checks/runner.go:581-608`、`internal/dast/dast.go:793-805` 的请求文本不含 Cookie/Authorization；弱口令在 Verified 中已掩码（`engine.go:896`） |
| IPv4-mapped IPv6 绕过 SSRF | **无此问题** | Go `net/netip` 的 `IsLoopback/IsPrivate/IsLinkLocalUnicast` 均先 `Unmap` |
| ReDoS | **无此问题** | 用户可达正则均为 RE2（线性）；`internal/rex` 有 10 万步预算；`internal/dast/deep.go:416` 插值的 key 是硬编码列表 |
| 前端 XSS | **无此问题** | `web/js/common.js:238` 的 `esc()` 转义 5 个危险字符；`app.js:324` 的 `regEv` 用注册表 + 序号键，目标内容**不进** HTML 属性；`common.js:399` 的 `safeLink` 限制 http/https |
| `Store.ClearAll` 死锁 | **无此问题** | `internal/store/graph.go:128` 的 `GraphIDs()` 不取锁，无锁序冲突 |
| `JobManager` 竞态 | **无此问题** | 同一 `RWMutex` 保护；⚠️ 但注意 `Update` 持写锁执行回调，**回调内不得再调 `Get/Update/CancelRequested`**（RWMutex 不可重入，代码里已有踩坑注释 `server.go:787-789`） |

---

## 7. 建议排期

| 批次 | 条目 | 理由 |
|---|---|---|
| **第一批** | BUG-001、BUG-002、BUG-003 | 三条 P0 各自独立、改动面小（3 行 / 3 处 / 2 段），且都能立刻验证 |
| **第二批** | BUG-005、BUG-007、BUG-016、BUG-017、BUG-018、BUG-019、**BUG-032**、**BUG-033** | 用户可感知的效果类：配置失效、误报 confirmed、通道不生效、**桌面弹窗**（启动 + 退出两个根因，改动都很小） |
| **第三批** | BUG-004、BUG-008、BUG-009 ~ BUG-015、BUG-021、**BUG-034** | 并发与安全加固，建议合并成一个「并发与一致性」专题 MR；**BUG-034** 是前端错误可观测性，可并行 |
| **第四批** | BUG-006、BUG-020、BUG-022 ~ BUG-031 + DOC-001~013 | 打包、资产、清理与文档对齐 |
| **专项（需拍板/实测）** | **BUG-035**（包体瘦身）、**FEAT-001**（应用内反馈页）、**FEAT-002**（埋点，需产品拍板） | BUG-035 需实测 int8 精度损失后再定方案；FEAT-002 涉及用户协议修订，**不可由实现侧自行决定** |

---

## 8. 建议新增的回归门禁

本次 31 条里有 **6 条竞态类**（BUG-004、010、011、013、014、015）CI 的 `-race` 抓不到——因为**测试没有并发执行**。建议补：

1. **CVSS 对拍门禁**：用 `data/nvd_cves.json.gz` 抽样 5,000 条（按年份分层）重算，与官方分逐条比对，差异必须为 0。
2. **并发用例组**：`internal/intel`（KEV merge vs read）、`internal/server`（reload vs read、settings vs guard）、`internal/engine`（LRU 落盘 vs 调度）、`internal/checks`（插件热加载 vs 索引）各补一条 `-race` 用例。
3. **NVD 官方分回归**：把 BUG-001 的 292,036 条比对固化成 CI 步骤（可只跑抽样版以控制时长）。
4. **证据链可复现门禁**：对每类发现（checks / dast-url / dast-form / exploit）断言其 `replay` 命令在 shell 语法上合法，且 `field`/`action`/payload 中的单引号已转义。
5. **模板来源覆盖门禁**：统计各来源（nuclei / raw / afrog / protocol）的**实际通过率**，任一来源通过率为 0 即告警——这类"整源失效"靠单测很难发现（BUG-016 就是这样潜伏的）。

---

*本文档由 2026-10-28 的全代码库 bug 扫描产出。所有 ✅ 标记项均在本地克隆上实际执行验证（构建 / 40 包测试 / 全量 NVD 交叉比对 / 独立复现程序）。修复任一条后，请在本文件对应条目下追加「修复前 / 修复后」实测记录，保持证据链完整。*
