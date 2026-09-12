# SiteLens 桌面版（Electron 壳）

把 SiteLens 装进桌面端：安装器、独立窗口、托盘常驻、自动更新、
崩溃自愈。**引擎零改动**——全部扫描能力仍在 Go 单二进制
（`sitelens serve` + go:embed 前端）里，本目录只是给它套原生窗口壳，
所有产品化行为靠引擎既有的配置面（「默认值 + yml 部分覆盖」）实现。

## 架构

```
┌─ SiteLens.exe（Electron 壳，本目录）──────────────────────┐
│  main.js   窗口 / 托盘 / 单实例 / 自动更新 / 崩溃自愈编排    │
│  engine.js 用户数据布局 / 端口策略 / 引擎子进程 / 就绪探测   │
└──────────────┬───────────────────────────────────┘
               │ spawn（首参纯字面量，cwd=引擎目录）
┌──────────────▼───────────────────────────────────┐
│  sitelens.exe serve -config .sitelens.yml          │
│  （Go 引擎，仓库主体，零改动）                       │
└───────────────────────────────────────────────────┘
```

### 数据布局（更新/卸载永不伤用户数据）

| 位置 | 内容 | 生命周期 |
|---|---|---|
| 安装目录 `%LOCALAPPDATA%\Programs\sitelens` | 引擎 exe + 只读资产（情报库种子/NVD/指纹规则/字典） | 随 app 更新整体替换 |
| `%APPDATA%\SiteLens\state` | 扫描历史（store.data_dir） | 永久 |
| `%APPDATA%\SiteLens\pools\nuclei` | 模板池（update-nuclei 在线拉取） | 永久 |
| `%APPDATA%\SiteLens\plugins` | 用户插件 | 永久 |
| `%APPDATA%\SiteLens\data` | 可变情报（update-nvd / update-fp / update-ehole 写入） | 永久 |

首启把安装包内置种子（NVD 37MB + 情报行 + 指纹规则）按缺失补拷到
用户数据区——首开即完整体验，后续 update-\* 成果不会被任何更新覆盖。
控制台地址固定 `http://127.0.0.1:5087`（被占用才换随机端口并持久化）。

### 排障

- `%APPDATA%\SiteLens\desktop.log`：壳的启动里程碑与更新事件
- `%APPDATA%\SiteLens\engine.log`：引擎输出（1MB 滚动）
- 引擎崩溃自动重启（5 分钟窗口最多 3 次，指数退避），托盘气泡提示；
  超限弹窗示警

## 自动更新

electron-updater generic 源（`package.json` → `build.publish.url`，
当前 = CNB release `desktop-stable` 标签的附件区）。启动静默检查 →
后台差量下载（blockmap）→ 弹窗「立即重启 / 稍后」→ 静默安装升级
（含引擎）。发布新版时 CI 自动把三件套覆盖到 desktop-stable。

## 本地构建

前置：Go 1.26+、Node 18+、npm。国内网络 `.npmrc` 已指向 npmmirror。

```cmd
cd desktop
npm install                       :: electron 二进制若被 npm 脚本门禁拦下：
node scripts/fetch-electron.js    ::   手动补拉
npm run engine                    :: go build 引擎 + 暂存数据载荷
npm run dist                      :: 出 release\SiteLens-Setup-<版本>.exe
```

产物三件套（发布自动更新必须全部上传）：

| 文件 | 用途 |
|---|---|
| `SiteLens-Setup-x.y.z.exe` | 安装包 |
| `SiteLens-Setup-x.y.z.exe.blockmap` | 差量更新 |
| `latest.yml` | 更新清单（含 sha512） |

## 发布一个新版本

常规路径：打 `v*` tag 推送，CI 自动构建并完成双发布（版本 release +
desktop-stable 更新源），无需手工步骤。

手工路径（CI 不可用时）：改 `package.json` 版本号 → `npm run engine &&
npm run dist` → 把三件套上传到更新源目录。更新源可以是任何静态托管
（generic 协议只要求 `<url>/latest.yml` 可直连），换托管只需改
`build.publish.url`。

## E2E 更新实测（发版前建议跑一遍）

```cmd
:: 1) 基线：当前版本出 win-unpacked，复制一份防覆盖
npx electron-builder --win dir && xcopy /E /I release\win-unpacked release\app300

:: 2) 更新包：package.json 版本号 +0.0.1 → npm run dist →
::    把 Setup exe / .blockmap / latest.yml 拷进 desktop\feed\
:: 3) 指基线到本地 feed（覆盖 resources\app-update.yml）：
::    provider: generic
::    url: http://127.0.0.1:8765/
:: 4) 起 feed 并带钩子启动基线：
python -m http.server 8765 -d feed
set SITLENS_E2E_UPDATE=1 && release\app300\SiteLens.exe
:: 5) 验收：%APPDATA%\SiteLens\desktop.log 应出现
::    update downloaded: v<新版本> → e2e: auto quitAndInstall → app v<新版本> ready
::    且 state/ 与 data/ 原位存活
```

## 图标

`build/icon.ico / icon.png` 由 `build/make_icon.py` 从
`assets/logo.png`（品牌 logo）生成，勿直接手改；换 logo 后重跑：
`python build/make_icon.py`（需 Pillow）。

## 已知边界

- 安装包未做代码签名（SmartScreen 会提示"更多信息→仍要运行"）；
  有签名证书后在 `build.win.certificateSubjectName` 配置即可
- 模板池 719MB 不随安装包，首次使用协议/全量模板检测前跑一次
  `update-nuclei`（控制台设置页或 CLI）
- 桌面版内置 NVD 全量字典，无 PG 依赖；`migrate-pg` 等服务器能力
  不在桌面版叙事内
