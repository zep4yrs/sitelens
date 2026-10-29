# SiteLens Bug 修复清单（5.1.0 快照）

> **这份文档是什么**：可直接当 TODO 用的修复队列。每条含**位置 / 现象 / 根因 / 修法 / 验收标准**，按严重度排序。
>
> **快照基准**：commit `0986a3f`（main / 5.1.0）· 核对于 2026-10-28
> **证据分级**：✅ 实测复现 · 🔍 代码读证（未执行） · 📄 代码注释/文档口径 · ❓ 未验证
> **配套文档**：[交接文档-5.1.0.md](交接文档-5.1.0.md)（架构与子系统背景）· [小白说明-5.1.0.md](小白说明-5.1.0.md)（面向使用者的风险解读）
>
> **总计 31 条**：P0 严重 3 · P1 高 5 · P2 中 13 · P3 低 10；另附 13 条文档漂移（DOC-xxx）与 9 条已排除误报（排除项）。
> **规划期追加**（2026-10-28 用户反馈，编号续排）：5 条缺陷（BUG-032 ~ BUG-036）+ 2 条需求项（FEAT-001 ~ FEAT-002），见 §4.5。

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

## 0.5 本轮已修复项的实测记录（2026-10-29）

> 本节记录**已落地并验证**的修复。逐条的根因/修法/验收标准见后文各条目。
> 所有 ✅ 均为本地实跑结果，非推断。

### 修复状态总览

| ID | 状态 | 验证方式与结果 |
|---|---|---|
| BUG-001 | ✅ 已修 | 新增门禁 `internal/intel/cvss_nvd_parity_test.go`：**292,036 / 292,036（100.00%）** NVD 官方向量逐条一致，耗时 1.99s。顺带补了顺序无关性与 AV:L 两条断言 |
| BUG-002 | ✅ 已修 | 新增 `internal/dast/replay_test.go`：以 **POSIX 引号往返解析**验证转义可逆——含注入的 action/field/payload 均原样还原为单个引号参数，参数数恒为 6（逃逸即多参） |
| BUG-003 | ✅ 已修 | 新增 `internal/target/validator_test.go`：metadata IP 在 `allow_private` × `resolve` 四种组合下**全部被拒**；`allow_private` 仍正常放宽普通私网/本机 |
| BUG-018 | ✅ 已修 | 同上文件：表单通道的 POST 语义 Request/Replay 不再被 `chainEvidence` 覆盖 |
| BUG-032 | ✅ 已修 | 壳侧拉引擎加 `CREATE_NO_WINDOW` + `HideWindow`；引擎保持控制台子系统（CLI 要 stdout） |
| BUG-033 | ✅ 已修 | 树杀用的 `taskkill` 同样加 `CREATE_NO_WINDOW`；种子交付子进程也一并处理（启动期第三个弹窗源） |
| BUG-034 | ✅ 已修 | 新增 `web/js/api-error.test.mjs`（5 例）+ 11 处静默 catch 全部改为 `window.slReportError`；新增「引擎无响应」界面态 |
| FEAT-001 | ✅ 已落地 | 新增 `internal/diag`（本机脱敏诊断包）+ `internal/server/feedback.go` + `web/feedback.html`；含脱敏守卫测试 |
| FEAT-002 | ✅ 定案 | **不做常驻埋点**，走 FEAT-001 的「本地诊断包 + 用户自建端点」；新增 `feedback.endpoint` 配置（默认空=不提交） |

### 关键实测数据

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

### 本轮新增的回归门禁

| 门禁 | 文件 | 作用 |
|---|---|---|
| CVSS × NVD 全量对拍 | `internal/intel/cvss_nvd_parity_test.go` | 计分偏移零容忍（1.99s） |
| CVSS 顺序无关性 | `internal/intel/cvss_test.go` | 向量串换序必须同分 |
| 复现命令 shell 转义 | `internal/dast/replay_test.go` | 往返解析验证可逆性 |
| 表单证据链不被覆盖 | `internal/dast/replay_test.go` | POST 语义必须保留 |
| metadata 永久阻断 | `internal/target/validator_test.go` | 四个开关组合全拒 |
| 诊断包脱敏 | `internal/diag/diag_test.go` | token/凭证/绝对路径零泄露 |
| 前端错误分级 | `web/js/api-error.test.mjs` | 三类失败必须带上下文 |

### 同时落地的架构改动：exe 拆分 + CLI 融入 TUI

**动机一（exe 拆分）**：此前**一个 exe 既是引擎又是 CLI**，导致 ① 桌面壳拉起它时必弹控制台窗口；② CLI 能力被整个塞进桌面安装包。

**动机二（CLI 融入 TUI）**：拆分后发现 npm 线有**两个 CLI**——Node 的 `sitelens`（只有 scan/serve）与平台包里的 Go 二进制（十四个子命令），用户面对两个入口、两套帮助、两处数据目录。

**落地结果**：

| 层 | 职责 |
|---|---|
| `tui/`（Node + Ink 7） | **唯一用户入口**：交互式 TUI（首屏「选功能」）+ 全部非交互命令；命令表 `src/commands.mjs` 是唯一事实源，`--help` 由它生成 |
| `cmd/sitelens`（Go） | 退回**内部实现**（npm 平台包装它），用户不再直接面对 |
| `cmd/sitelens-engine`（Go） | 桌面线内部引擎：`serve` + `update-seed`；未知子命令**直接报错退出 2**（此前会静默当 serve 跑） |
| `~/.sitelens/` | npm 线的统一用户区：`config.yml`（TUI 管理）· `data/`（资产）· `data/state/`（历史） |

命令实现分两种形态：**编排型**（TUI 起 serve 走 HTTP API：scan / doctor / history / verified）与**直通型**（spawn 引擎执行原生命令，stdio 与退出码透传：serve / audit / correlate / graph-read / regression / migrate-pg / update-*）。

### 本轮连带修掉的两处既有缺陷

| 缺陷 | 位置 | 说明 |
|---|---|---|
| **退出时 libuv 断言** | `tui/src/engine.mjs` `stop()` | Windows 上必现：`Assertion failed: !(handle->flags & UV_HANDLE_CLOSING)` → 进程以 0xC0000409 中止、**退出码全丢**。修法：`child.stderr.destroy()` 立即释放管道句柄 + 等 `'close'` 而非 `'exit'` + 入口改用 `process.exitCode` 而非 `process.exit()`（强制退出会打断 libuv 清理） |
| **相对路径按引擎目录解析** | `tui/src/engine.mjs` 子进程 cwd | 引擎 cwd 原为「二进制所在目录」（node_modules 里），用户敲 `sitelens audit ./src` 会找不到路径。改为 **`process.cwd()`**——数据路径已由 `-config` 指向用户区绝对路径，不依赖 cwd |

### 端到端验证（真实 npm 平台包布局）

模拟 `@fengqiao666/sitelens-win32-x64-engine` 平台包（平台包二进制 + `data/go/technologies.json`），用独立 HOME 模拟全新安装：

```
sitelens doctor
  → "已交付平台包内置指纹库到用户区"
  → 指纹库 就位 3321 KB
  → 用户区产出：~/.sitelens/.seed-manifest.json + ~/.sitelens/data/go/technologies.json
```

命令冒烟（退出码）：`--version` 0 · `--help` 0 · `doctor` 0 · `history` 0 · `verified` 0 · `update`（缺参）2 · `graph-read`（缺参）2 · `audit`（缺参）2。

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
