# SiteLens 桌面版（Electron 壳）

把 SiteLens 装进桌面端：安装器、独立窗口、托盘常驻、自动更新。
**引擎零改动**——全部扫描能力仍在 Go 单二进制（`sitelens serve` +
go:embed 前端）里，本目录只是给它套了一个原生窗口壳。

## 架构

```
┌─ SiteLens.exe（Electron 壳，本目录）────────────────┐
│  main.js   窗口 / 托盘 / 单实例 / 自动更新            │
│  engine.js 拉起引擎子进程、空闲端口、就绪探测、日志    │
└──────────────┬───────────────────────────────┘
               │ spawn（首参纯字面量，cwd=resources/engine）
┌──────────────▼───────────────────────────────┐
│  sitelens.exe serve（Go 引擎，仓库主体，零改动）│
│  · 端口来自 desktop-listen.yml（部分覆盖语义）  │
│  · data/ 载荷随引擎目录解析                    │
└───────────────────────────────────────────────┘
```

- 端口：壳选一个随机空闲端口写入 `desktop-listen.yml`，引擎配置是
  「默认值 + yml 部分覆盖」语义，因此 Go 侧不需要任何新参数。
- 安装：NSIS 单用户安装到 `%LOCALAPPDATA%\Programs\SiteLens`
  （用户可写，引擎的 `data/state` 直接可用）；oneClick 静默安装。
- 自动更新：electron-updater generic 源（`package.json` → 
  `build.publish.url`，当前指向 CNB release `desktop-stable` 标签）。
  启动静默检查，发现新版本后台下载（blockmap 差量），就绪后弹窗
  「立即重启 / 稍后」；引擎二进制随安装包整体升级。
- 关窗不退出：收进托盘继续跑扫描，退出走托盘右键菜单。
- 排障日志：`%APPDATA%\SiteLens\desktop.log`（壳）与
  `%APPDATA%\SiteLens\engine.log`（引擎输出，1MB 滚动）。

## 本地构建

前置：Go 1.26+、Node 20+、npm。国内网络走 `.npmrc` 里的 npmmirror。

```cmd
cd desktop
npm install                 :: 若 electron 二进制被 npm 脚本门禁拦下：
node scripts/fetch-electron.js
npm run engine              :: go build 引擎 + 暂存 lite 数据载荷
npm run dist                :: 出 release\SiteLens Setup <版本>.exe
```

产物三件套（发布自动更新必须全部上传）：

| 文件 | 用途 |
|---|---|
| `SiteLens Setup x.y.z.exe` | 安装包 |
| `SiteLens Setup x.y.z.exe.blockmap` | 差量更新 |
| `latest.yml` | 更新清单（含 sha512） |

## 发布一个新版本

1. 改 `package.json` 的 `version`（与引擎版本保持一致）
2. `npm run engine && npm run dist`
3. 把三件套上传到更新源目录（当前约定：CNB 仓库 release
   `desktop-stable` 的附件区，覆盖旧文件）

更新源可以是任何静态文件托管（generic 协议只要求
`<url>/latest.yml` 可直连下载）；换托管只需改 `build.publish.url`。

## 图标

`build/icon.ico / icon.png` 由 `build/make_icon.py` 从
`assets/logo.png`（品牌 logo）生成，勿直接手改；换 logo 后重跑：
`python build/make_icon.py`（需 Pillow）。
