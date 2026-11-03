# SiteLens 桌面版（Wails 壳）

把 SiteLens 装进桌面端：安装器、独立窗口、托盘常驻、启动页。
**引擎零改动**——全部扫描能力仍在 Go 单二进制（`sitelens serve` +
go:embed 前端）里，本目录只是给它套原生窗口壳。

> **交付线说明（v5.1.0 起）**：桌面交付正式切到 Wails 壳（本目录）。
> 原 Electron 壳（`desktop/`）保留为历史形态，不再作为发版产物——
> 换壳的收益是分发体积（单文件壳 ~12MB vs Electron 安装包 ~100MB）
> 与同语言栈（Go 壳 + Go 引擎），代价见下「已知边界」。
> 换壳决策与实测数据见 `docs/开发文档-4.0.md` §26.25。

## 目录结构

```
desktop-wails/
├── main.go                  # 壳入口：引擎目录探测 / 端口决策 / 拉起引擎 /
│                            #   启动页编排 / 主窗 / 托盘 / 退出回收
├── quick.go                 # FE-08：托盘快速扫描（剪贴板 URL → /api/scan quick
│                            #   → 轮询 → 通知）/ 全局快捷键 / 对比窗口 / 窗口材质
├── notify.go                # FE-08：壳内轻量通知窗（右下角、Acrylic、6s 自动关闭）
├── version.go               # 壳版本号单一来源（发版脚本读这里）
├── port.go                  # 端口 IO：读偏好、读用户配置、回写协商结果
├── internal/portpolicy/     # 端口决策纯函数（壳偏好 > 配置原文 > 默认 5087）
├── assets/
│   ├── splash.html          # 启动页（与 desktop/splash.js 同源双宿主）
│   ├── index.html           # 兜底页（引擎未连接时显示）
│   ├── icon.ico / icon.png  # 品牌图标（与 desktop/build/icon.ico 同源）
│   └── rsrc_windows_amd64.syso  # exe 内嵌资源（go-winres 生成）
├── splash_test.go
├── quick_test.go            # FE-08 壳侧纯逻辑单测（URL 提取/API/通知/材质/定位）
└── go.mod / go.sum          # 独立模块（不随主模块 go test）
```

## 职责（对齐 Electron 壳的产品行为）

| 行为 | 实现 |
|---|---|
| 引擎目录探测 | 打包态 `<exe同级>/engine/`；开发态 `../build/engine`；`SITLENS_ENGINE_DIR` 覆盖 |
| 端口决策 | 壳偏好（`desktop-prefs.json`）> 配置原文 `web.listen` > 默认 **5087**，被占用才随机；协商结果回写 |
| 配置落点 | `%APPDATA%\SiteLens-Wails\config.yml`（**不写安装目录**，EPERM 教训）；merge 语义只更新受管键（`web.listen` + 可写路径 `store.data_dir` / `intel.overrides_path` / `checks.nuclei_dir` / `checks.plugin_dir`，见 `internal/usercfg`） |
| 种子交付 | 启动调引擎 `update-seed`，随包种子按**包版本**覆盖用户区（`internal/seedrefresh` 定边界） |
| 自动更新 | 启动静默 + 托盘手动；读 `latest.yml` → 版本比对 → 下载 + sha512 校验 → `/S` 静默就地覆盖安装 → 自动重开（`internal/updater` 定判定） |
| 启动页 | 透明无底板挂件「对焦」动画；最低展示 1.9s；主窗创建即隐藏、与启动页退场同时现身 |
| 托盘 | 品牌图标 + 快速扫描剪贴板 URL / 打开工作台 / 打开对比窗口 / 检查更新 / 退出；左键单击图标 = 唤起工作台 |
| 全局快捷键（FE-08） | `Ctrl+Shift+S` 唤起工作台并聚焦 URL 输入框；`Ctrl+Shift+Q` 快速扫描剪贴板 URL（Wails `GlobalShortcut`，无需新依赖） |
| 快速扫描（FE-08） | 剪贴板 → 提取 http(s) URL → `POST /api/scan {"level":"quick"}` → 轮询 `/api/job/{id}` → 完成通知（结果由引擎自动入历史）；同一时刻只跑一个 |
| 多窗口对比（FE-08） | 托盘「打开对比窗口」开第二个窗口加载 `/history?diff=1`，壳侧把 diff 区滚入视野（每次新开，可并排多份） |
| 窗口材质（FE-08） | Windows 11 22H2+ 用 Mica（`Windows.BackdropType`）+ 深色标题栏跟随系统主题；更老系统由 Wails 降级为 blur-behind；`SITLENS_WIN_MATERIAL=off` 回退纯色 |
| 结果通知（FE-08） | 壳内轻量通知窗：右下角、无边框置顶、不占任务栏、Acrylic、6s 自动关闭；不引入系统 Toast 依赖 |
| 退出回收 | `taskkill /T /F` 树杀引擎（含 chromedp 拉起的 Chrome 孙进程） |
| 生命周期留痕 | `%APPDATA%\SiteLens-Wails\shell.log`（GUI 子系统无控制台，退出原因必须留痕） |
| API Token 注入（A-01/D-02） | 启动读/生成 `web.api_token`（64-hex，0600，**日志绝不打印 token**）→ 主窗 URL `#token=` fragment → 前端 bootstrap 存 localStorage 并抹掉 fragment → 此后所有请求带 `X-Token` |
| 端口 nonce（D-07） | 32B hex → 引擎 `SITLENS_SHELL_NONCE` → `/api/version` 回显 → `waitReady` 逐字节比对，缺失/不等立即树杀引擎并报错（防端口 TOCTOU 抢占） |
| 数据目录（C-17） | 引擎 `SITLENS_DATA_DIR=%APPDATA%\SiteLens-Wails\state`（与 yaml `store.data_dir` 同源）；安装目录只读、不再写 `data/` |
| 桌面壳桥（D-06） | `window.sitelens`：`GetInfo/GetAutoStart/SetAutoStart/GetCloseAction/SetCloseAction/CheckUpdate/InstallUpdate/OpenDataDir`（`chrome.webview.postMessage` + `RawMessageHandler` + `ExecJS` 回包；浏览器形态 `available=false` 全降级） |

### 安全接线要点（改壳前必读）

> ⚠ **`waitReady` 必须带 `X-Token`**：引擎的令牌守卫覆盖**所有** `/api/*`（含
> `/api/version`，见 `internal/server/authz_guard_test.go`）。配置了 `web.api_token`
> 后，健康检查若不带 token 会一直 401 → 壳误判「引擎未就绪」→ 树杀 + 退出。
> 对应回归：`hardening_test.go` 的 `TestWaitReadySendsAPIToken`。
>
> ⚠ **nonce 不匹配不要重试**：真引擎不会在稍后变出正确 nonce；继续轮询只会把
> 「端口被其它进程抢占」拖成 30s 超时，掩盖真实原因。

### 数据布局

| 位置 | 内容 | 生命周期 |
|---|---|---|
| 安装目录（`$PROGRAMFILES64\SiteLens`） | 壳 `sitelens.exe` + `engine/`（引擎 exe + 只读资产） | 随 app 更新整体替换 |
| `%APPDATA%\SiteLens-Wails\config.yml` | 引擎配置（壳写入的受管键 + 用户键，含壳注入的 `web.api_token`） | 永久 |
| `%APPDATA%\SiteLens-Wails\state` | 引擎状态目录 = `store.data_dir` = `SITLENS_DATA_DIR`（扫描历史/图谱 `history.json`） | 永久 |
| `%APPDATA%\SiteLens-Wails\desktop-prefs.json` | 壳偏好（协商端口） | 永久 |
| `%APPDATA%\SiteLens-Wails\shell-prefs.json` | 壳偏好（关闭行为 `exit`\|`tray`，0600） | 永久 |
| `%APPDATA%\SiteLens-Wails\data` | 随包种子（按版本交付：NVD/情报/指纹）+ 可变情报 `intel_overrides.json` | 随版本覆盖 |
| `%APPDATA%\SiteLens-Wails\updates` | 自动更新下载的安装包 | 可清理 |

> 注意：Wails 线的用户数据区是 `%APPDATA%\SiteLens-Wails`，
> 与 Electron 壳的 `%APPDATA%\SiteLens` **不同**——两条壳并存时不互相污染，
> 但也意味着换壳后历史/配置需要手工迁移（见「已知边界」）。

## 构建与发版

前置：Go 1.26+、makensis（Linux 上打 NSIS 还需 wine + xvfb-run）。

> ⚠ **首次构建需联网（模块无 vendor）**：`desktop-wails` 是**独立 Go module 且未 vendor**
> （主模块的 `vendor/` 对它无效），首次构建必须能访问 Go module proxy 解析
> `github.com/wailsapp/wails/v3 v3.0.0-beta.22` 及其传递依赖；之后命中本机 module cache 才能离线。
> 离线/内网构建机请先在有网环境执行一次 `(cd desktop-wails && go mod download)`，
> 再把 `GOMODCACHE`（`go env GOMODCACHE`）一并带到构建机；或自行 `go mod vendor` 后加 `-mod=vendor`。
> 另注意：主模块的 `go build ./...` **不会**构建本壳——壳必须在 `desktop-wails/` 内单独构建。

```bash
# 只构建壳 + 引擎载荷（产物落 dist/wails/SiteLens/）
bash tools/wails_build.sh

# 完整发版：构建 → 校验 PE → 打包 NSIS →（可选）上传 CNB
bash tools/release_local.sh              # 只构建打包
bash tools/release_local.sh --publish    # 再上传 CNB Release（需 CNB_TOKEN）
```

产物：`dist/release/SiteLens-Setup-<版本>.exe`。

### Linux / macOS 构建（5.2.x 起）

壳的 Windows 专属能力（CREATE_NO_WINDOW、taskkill、user32 MessageBoxW、Mica）
已拆到 `platform_windows.go`，POSIX 平台走 `platform_unix.go` 的降级实现
（无控制台窗口概念 → no-op；进程回收 → Kill；自动更新 → 显式拒绝，
只支持 Windows NSIS 安装器）。窗口材质在非 Windows 平台降级为不透明纯色窗。

```bash
# Linux：需 gcc / pkg-config / libgtk-3-dev / libwebkit2gtk-4.1-dev / libx11-dev
# macOS：需 Xcode Command Line Tools
bash tools/wails_build_unix.sh              # 构建 + 打包
bash tools/wails_build_unix.sh --no-package # 只构建
```

产物：

| 平台 | 产物 | 状态 |
|---|---|---|
| Linux amd64/arm64 | `dist/wails/SiteLens_<ver>_<arch>.deb`、`dist/wails/linux-<arch>/SiteLens/` | ✅ CI 原生构建 + deb 打包已验证（CI 门禁） |
| macOS arm64/x64 | `dist/wails/SiteLens_<ver>_<arch>.dmg`、`SiteLens.app` | 🚧 代码已移植，待 macOS 机器/CI 实机构建验证 |

`tools/wails_build_unix.sh` 同样内置硬闸：平台魔数校验（Linux ELF / macOS
Mach-O）、壳/引擎版本一致性；引擎文件名按平台取后缀（`sitelens-engine[.exe]`）。
macOS 的 `.app` 用 `Info.plist`（bundle id `top.feng-qiao.sitelens`）包壳与
`engine/`，未签名/未公证（需要 Apple Developer ID 后再补）。

`tools/wails_build.sh` 内置两道硬闸，打包前拦下：

1. **PE 魔数校验**（壳 + 引擎）——错平台二进制进包是 v3.0.0 真实事故的根因；
2. **壳/引擎版本一致性**——`version.go` 必须等于 `internal/server.Version`，
   这是「README 下载入口停在旧版本」那类漂移的结构性防线。

## 桌面深化（FE-08）

### 快捷键与托盘

| 入口 | 行为 | 冲突/降级 |
|---|---|---|
| `Ctrl+Shift+S` / 托盘「打开工作台」/ 左键单击托盘图标 | 还原并前置主窗，注入脚本聚焦 URL 输入框（`#url` → 常见属性 → 任意可见输入框三级降级） | 快捷键被占用：`Register` 返回错误 → 只记 `shell.log`，托盘入口照常可用 |
| `Ctrl+Shift+Q` / 托盘「快速扫描剪贴板 URL」 | 剪贴板取第一个 http(s) URL → 快速档扫描 → 结果入历史 → 通知 | 无剪贴板/剪贴板无 URL：静默降级（留痕 + 一条轻提示），不影响其它入口；同一时刻只跑一个扫描 |
| 托盘「打开对比窗口」 | 新开窗口加载 `/history?diff=1`（可并排多份） | 引擎未就绪时窗口显示错误页，不崩溃 |

快速扫描的引擎交互（**引擎零改动**，全部走既有 API）：

```
剪贴板 → extractURL → POST /api/scan {"url": "...", "level": "quick"}
       → 轮询 GET /api/job/{id}（800ms 间隔，最长 11 分钟）
       → status=done：引擎已把结果存历史（返回 scan_id）→ 通知「已存历史 #id」
       → status=error/cancelled：通知原因
```

鉴权与引擎 guard 同优先级：`SLENS_API_TOKEN` 环境变量 > 配置文件 `web.api_token`；
两者都没有（默认）时不需要 `X-Token`。

### 窗口材质与主题

- 主窗/对比窗默认 `Windows.BackdropType = Mica`（`BackgroundTypeTranslucent`），
  Windows 11 22H2+ 显示材质；更老系统由 Wails 自动降级为 blur-behind（不会崩、
  不会黑屏——`SupportsBackdropTypes()` 为假时走 `ACCENT_ENABLE_BLURBEHIND`）。
- `Windows.Theme = SystemDefault`：深色/浅色标题栏跟随系统主题，Wails 订阅
  `SystemThemeChanged` 自动切换，壳不需要自己监听。
- 逃生阀：`SITLENS_WIN_MATERIAL=off` 退回不透明纯色窗（观感异常时不用改代码回滚）。
- 通知窗用 Acrylic（同一机制、更轻），6s 自动关闭；通知不抢任务栏、置顶显示。

### 自测

```bash
cd desktop-wails
go build ./... && go vet ./... && go test ./...     # 纯逻辑单测，不启动 GUI
```

## 已知边界（如实说）

- **自动更新已接线（v5.2）**：启动静默检查 + 托盘「检查更新」；读更新源的
  `latest.yml`、比对版本、下载安装包并 sha512 校验，然后以 `/S` **静默就地覆盖
  安装**（无向导页，安装器按注册表 `InstallDir` 不挪窝），装完自动拉起新版。
  - **覆盖更新的另一环是「种子按版本交付」**：本壳启动时调引擎
    `update-seed`，把随包只读种子（NVD 快照/情报行/指纹规则）按**包版本**
    覆盖到用户数据区。旧 Electron 壳是「用户区不存在才拷」，包内快照永远
    进不来（升了版本情报还是旧的）；现在版本变化才覆盖、同版本 no-op，
    `state/`（历史）、`pools/nuclei/`（模板池）、`plugins/`、`data/wordlists/`
    永不覆盖。
  - **已知限制（如实）**：安装器是机器级（`RequestExecutionLevel admin`），
    非提权进程拉起的自动更新**会弹一次 UAC**——语义上是就地覆盖、无向导页，
    但不是零交互；要做到零 UAC 需改用户级安装，另行评估。
- **壳模块未 vendor，离线不能"首次"构建**：`desktop-wails/go.mod` 的依赖只在 module cache 里，
  无网机器首次构建会失败。详见「构建与发版」的 ⚠ 提示（预热 `go mod download` 或自行 vendor）。
- **崩溃自愈未接线**：Electron 壳有引擎崩溃自动重启（5 分钟窗口 ≤3 次
  指数退避）；Wails 壳当前引擎异常退出即随壳退出，未做重启。
- **单实例未接线**：Electron 壳用 `requestSingleInstanceLock` 保证单开；
  Wails 壳当前可多开（多个壳各拉一个引擎，端口靠偏好/随机区分）。
- **前端未见壳桥**：Electron 壳经 preload 暴露 `window.sitelens`，设置页
  「关于与更新」「桌面端」两页据此显示并直连更新器；Wails 壳未提供等价桥，
  这两个页签在壳内不出现（更新入口在托盘菜单）。
- **配置迁移**：两条壳的用户数据区不同（`SiteLens-Wails` vs `SiteLens`），
  从 Electron 壳升级过来的用户需要手工把配置/历史拷到新目录。
- **安装包未签名**：首次运行 SmartScreen 可能拦一下，选「更多信息 → 仍要运行」。
- 模板池 719MB 不随安装包，首次使用全量模板检测前跑一次 `update-nuclei`。
- **FE-08 对比窗口的 `?diff=1` 参数前端不消费**：`web/history.html` 只有「勾选两条
  记录 → 对比」的交互，没有 URL 参数入口（本轮范围不含 `web/`）。壳侧加载
  `/history?diff=1` 后注入脚本把 diff 区滚入视野并高亮「对比勾选的两条」按钮；
  真正的对比仍需用户勾选两条记录。要让参数直达对比，需要前端改造（另立任务）。
- **FE-08 通知是壳内通知窗，不是系统 Toast**：Wails 的 notifications 服务在
  Windows 侧会引入 `git.sr.ht/~jackmordaunt/go-toast` 依赖（本轮约束优先无新依赖，
  且构建机无网络），故用 Wails 多窗口实现右下角通知。
- **FE-08 全局快捷键的「占用」不可预知**：`Ctrl+Shift+S/Q` 若被其它程序抢占，
  只降级为托盘菜单并记 `shell.log`，不弹错误框；需要排查时看该日志。
- **FE-08 材质依赖系统能力**：Mica/Acrylic 在 Windows 11 22H2+ 才有；更老系统为
  blur-behind 观感（不崩溃）。引擎页面 body 自带不透明底色，材质主要作用于
  标题栏与页面空帧期。
- **Linux/macOS 桌面（5.2.x 起）**：壳已可原生构建（Linux 走 GTK3 + WebKitGTK 4.1，
  macOS 走 Cocoa/WebKit），但自动更新只支持 Windows NSIS 安装器（其他平台
  `downloadAndInstall` 显式拒绝）；Linux/macOS 包当前**未签名**（Linux 待 GPG，macOS 待
  Developer ID + 公证）。macOS 尚未在实机跑过完整扫描回归。
