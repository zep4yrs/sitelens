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
├── version.go               # 壳版本号单一来源（发版脚本读这里）
├── port.go                  # 端口 IO：读偏好、读用户配置、回写协商结果
├── internal/portpolicy/     # 端口决策纯函数（壳偏好 > 配置原文 > 默认 5087）
├── assets/
│   ├── splash.html          # 启动页（与 desktop/splash.js 同源双宿主）
│   ├── index.html           # 兜底页（引擎未连接时显示）
│   ├── icon.ico / icon.png  # 品牌图标（与 desktop/build/icon.ico 同源）
│   └── rsrc_windows_amd64.syso  # exe 内嵌资源（go-winres 生成）
├── splash_test.go
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
| 托盘 | 品牌图标 + 显示主界面 / 退出 |
| 退出回收 | `taskkill /T /F` 树杀引擎（含 chromedp 拉起的 Chrome 孙进程） |
| 生命周期留痕 | `%APPDATA%\SiteLens-Wails\shell.log`（GUI 子系统无控制台，退出原因必须留痕） |

### 数据布局

| 位置 | 内容 | 生命周期 |
|---|---|---|
| 安装目录（`$PROGRAMFILES64\SiteLens`） | 壳 `sitelens.exe` + `engine/`（引擎 exe + 只读资产） | 随 app 更新整体替换 |
| `%APPDATA%\SiteLens-Wails\config.yml` | 引擎配置（壳写入的受管键 + 用户键） | 永久 |
| `%APPDATA%\SiteLens-Wails\state` | 扫描历史（store.data_dir） | 永久 |
| `%APPDATA%\SiteLens-Wails\desktop-prefs.json` | 壳偏好（协商端口） | 永久 |
| `%APPDATA%\SiteLens-Wails\data` | 随包种子（按版本交付：NVD/情报/指纹） | 随版本覆盖 |
| `%APPDATA%\SiteLens-Wails\updates` | 自动更新下载的安装包 | 可清理 |

> 注意：Wails 线的用户数据区是 `%APPDATA%\SiteLens-Wails`，
> 与 Electron 壳的 `%APPDATA%\SiteLens` **不同**——两条壳并存时不互相污染，
> 但也意味着换壳后历史/配置需要手工迁移（见「已知边界」）。

## 构建与发版

前置：Go 1.26+、makensis（Linux 上打 NSIS 还需 wine + xvfb-run）。

```bash
# 只构建壳 + 引擎载荷（产物落 dist/wails/SiteLens/）
bash tools/wails_build.sh

# 完整发版：构建 → 校验 PE → 打包 NSIS →（可选）上传 CNB
bash tools/release_local.sh              # 只构建打包
bash tools/release_local.sh --publish    # 再上传 CNB Release（需 CNB_TOKEN）
```

产物：`dist/release/SiteLens-Setup-<版本>.exe`。

`tools/wails_build.sh` 内置两道硬闸，打包前拦下：

1. **PE 魔数校验**（壳 + 引擎）——错平台二进制进包是 v3.0.0 真实事故的根因；
2. **壳/引擎版本一致性**——`version.go` 必须等于 `internal/server.Version`，
   这是「README 下载入口停在旧版本」那类漂移的结构性防线。

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
