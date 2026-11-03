# 发布物矩阵与校验规则（`scripts/release/`）

> 本文件是发版前「产物命名 / 版本一致性 / 签名占位」的**唯一校验口径**；配套脚本
> [`check.ps1`](check.ps1) 零依赖实现（仅 PowerShell，不需 Node/Go/签名工具）。
> 面向的完整交付矩阵见 [`../../docs/生态-插件市场-SLA-情报.md`](../../docs/生态-插件市场-SLA-情报.md) §4。

## 1. 权威来源

| 事项 | 唯一来源 |
|---|---|
| 桌面壳版本号 | `desktop-wails/version.go` 的 `const Version`（发版脚本从这里读取） |
| 引擎版本号 | `internal/server/server.go` 的 `const Version`（必须与壳版本一致） |
| 安装包命名 | `SiteLens-Setup-<ver>.exe`（`tools/release_local.sh` 产出到 `dist/release/`） |
| 更新清单 | `latest.yml`（electron-builder 兼容子集：`version/path/sha512/releaseDate`；Wails 壳直接读） |
| update 源 | GitHub `desktop-stable`（三件套：exe + `.blockmap` + `latest.yml`）；CNB Release 只放安装包与发行说明 |
| CLI/TUI 版本 | `tui/package.json`（独立版本线；引擎平台包版本随 npm 包） |
| 引擎平台产物 | `SiteLens_<token>_engine_<ver>[.exe]`，`token ∈ win64/linux64/linux-arm64/mac64/mac-arm64` |

## 2. 产物矩阵（当前）

| 产物 | 位置/命名 | 平台 | 状态 | 签名 | 校验点 |
|---|---|---|---|---|---|
| 桌面安装包 | `dist/release/SiteLens-Setup-<ver>.exe` | Windows x64 | ✅ 正式 | ✅ 自签名（内部验收；CN=SiteLens Internal Self-Signed） | 命名含版本、PE 头 `MZ`、版本=壳版本、体积>1MB |
| 安装 workspace | `dist/wails/SiteLens/sitelens.exe` + `engine/sitelens-engine.exe` + `engine/data/` | Windows x64 | ✅ 正式 | ✅ 自签名（同上） | 两个 exe 均为 PE；版本串一致；`engine/data` 存在 |
| 更新清单 | `latest.yml` | Windows x64 | ✅（GitHub feed） | — | `version`=壳版本；`path`=`SiteLens-Setup-<ver>.exe`；`sha512` 非占位 |
| 差分包 | `SiteLens-Setup-<ver>.exe.blockmap` | Windows x64 | ✅（GitHub feed，可选） | — | 与 exe 同名同版本 |
| 发行说明 | `docs/release-<ver>/release-body-<ver>.md` | — | ✅ | — | 存在；发布前 `【待发布】` 占位必须全部回填 |
| CNB 版本页 | 安装包 + 发行说明 | Windows x64 | ✅ | — | **不上传 latest.yml/blockmap**（防双源漂移） |
| npm CLI/TUI | `@fengqiao666/sitelens-cli` | win/linux/mac，x64/arm64 | ✅ 正式 | npm 完整性 | `bin`/`files`/版本；引擎平台包名与产物命名 |
| Linux 桌面 | `dist/wails/SiteLens_<ver>_<arch>.deb`、`dist/wails/linux-<arch>/SiteLens/` | Linux x64/arm64 | 🚧 可构建（CI 已验证 amd64 构建+deb） | 未签名（GPG 待） | ELF 魔数、壳/引擎版本一致、engine/data 存在 |
| macOS 桌面 | `dist/wails/SiteLens_<ver>_<arch>.dmg`、`SiteLens.app` | macOS arm64/x64 | 🚧 代码已移植，待 macOS 实机验证 | 计划 Developer ID + 公证 | Mach-O 魔数、壳/引擎版本一致 |

## 3. 检查项（`check.ps1` 实现）

| 编号 | 检查 | 失败级别 | 说明 |
|---|---|---|---|
| R1 | 壳版本可解析 | FAIL | `desktop-wails/version.go` 匹配 `const Version = "x.y.z"` |
| R2 | 引擎版本可解析且等于壳版本 | FAIL | `internal/server/server.go` 的 `const Version` |
| R3 | `-ExpectedVersion` 一致（如传 `5.2.0`） | FAIL | 发版脚本可传入期望版本 |
| R4 | 安装包命名符合 `SiteLens-Setup-<ver>.exe` 且版本一致 | FAIL | 存在 `dist/release/` 时强校验 |
| R5 | 安装包/壳/引擎 PE 头为 `MZ` | FAIL | 复现 v3.0.0「Linux ELF 装进 Windows 包」事故防线 |
| R6 | 暂存目录结构完整（exe+engine exe+data） | WARN/FAIL | 未构建时 WARN；`-Strict` 时 FAIL |
| R7 | `latest.yml` 字段自洽（version/path/sha512） | WARN/FAIL | 存在才校验；`sha512` 为空或占位 → WARN |
| R8 | 签名状态（Authenticode） | WARN/FAIL | 非 Windows 或未接入时 WARN；`-RequireSigned` 时 FAIL；当前已自签名（内部验收） |
| R9 | 发行说明存在且无 `【待发布】` 占位 | WARN | 发版前必须回填；`-Strict` 时 FAIL |
| R10 | `CHANGELOG.md` 存在 `## v<ver>` 段 | WARN | 提示补更新日志 |
| R11 | npm CLI 包版本可解析、`bin` 指向存在 | WARN | 独立版本线；存在 `tui/package.json` 时校验 |
| R12 | 引擎平台包命名（`SiteLens_<token>_engine_<ver>`） | WARN | 存在 `tui/packages` 时按目录校 |

## 4. 用法

```powershell
# 只报告、不失败（CI/发版前置规划用）
pwsh scripts/release/check.ps1 -DryRun

# 发版前硬校验（缺产物/版本不一致/PE 头错 → 退出码 1）
pwsh scripts/release/check.ps1 -ExpectedVersion 5.2.0

# 要求产物已签名（企业发布）
pwsh scripts/release/check.ps1 -RequireSigned

# 严格模式：暂存目录不完整、发行说明占位未回填也视为失败
pwsh scripts/release/check.ps1 -Strict
```

退出码：`0` 通过（或 DryRun 完成）、`1` 存在 FAIL、`2` 用法/根目录错误。

## 5. 与发版流程的衔接

```
改版本号（desktop-wails/version.go）
  → tools/wails_build.sh            # 壳+引擎+载荷，内置 PE 校验
  → scripts/release/check.ps1 -Strict   # 产物命名/版本/PE/签名占位
  → tools/release_local.sh          # NSIS 出包 → dist/release/SiteLens-Setup-<ver>.exe
  → 发布前：check.ps1 -ExpectedVersion <ver>（硬校验）
  → CNB 版本页上传（exe + 发行说明；不回填 latest.yml）
  → GitHub desktop-stable 手工同步三件套（exe/blockmap/latest.yml）
```

> 签名接入后（⏳ Authenticode）：在 `tools/release_local.sh` 出包后对 exe 执行 `signtool sign`
> 并把 `check.ps1 -RequireSigned` 加入发版硬门禁；macOS/Linux 桌面交付时再扩展本节。

## 6. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-11-01 | v0.1 | 初稿：权威来源、产物矩阵、R1–R12 校验规则、usage 与发版衔接。 |
