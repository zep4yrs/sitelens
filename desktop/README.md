# SiteLens 桌面版（Electron 壳）

把 SiteLens 装进桌面端：安装器、独立窗口、托盘常驻、自动更新、
崩溃自愈。**引擎零改动**——全部扫描能力仍在 Go 单二进制
（`sitelens serve` + go:embed 前端）里，本目录只是给它套原生窗口壳，
所有产品化行为靠引擎既有的配置面（「默认值 + yml 部分覆盖」）实现。

## 目录结构

```
desktop/
├── main.js                  # 壳主进程：窗口 / 托盘 / 单实例 / 崩溃自愈 / 更新事件分发
├── engine.js                # 引擎子进程管理：配置写入 / 端口协商 / 种子初始化 / 就绪探测
├── preload.js               # contextBridge 桥：设置页经 window.sitelens 调用更新器
├── package.json             # electron-builder 配置（NSIS / 更新源 / files 白名单）
├── package-lock.json
├── .npmrc                   # npmmirror 镜像（electron / builder binaries）
│
├── lib/                     # 纯函数库（可独立单测）
│   ├── yml-merge.js         #   .sitelens.yml 合并器：受管键原位更新，用户键/注释/未知键保留
│   ├── port-policy.js       #   端口决策：壳偏好 > 配置原文 > 默认 5087，来源标签可追踪
│   └── ...
│
├── test/                    # node --test 单测（CI regression 门禁必跑）
│   ├── yml-merge.test.js    #   配置合并回归：引号安全 / 用户键保留 / 受管键更新
│   └── port-policy.test.js  #   端口决策回归：偏好优先 / 非法值遮蔽 / 来源标签
│
├── build/                   # 打包资源（electron-builder 自动拾取）
│   ├── icon.ico             #   多尺寸图标 16→256（由 make_icon.py 从品牌 logo 生成）
│   ├── icon.png             #   512×512 PNG（托盘 / extraResources）
│   ├── license.rtf          #   NSIS 安装向导许可协议页（Unicode 转义，任何代码页不乱码）
│   ├── license.txt          #   许可协议纯文本源
│   └── make_icon.py         #   图标生成脚本（Pillow，从 assets/logo.png 裁剪+缩放）
│
├── scripts/
│   └── fetch-electron.js    # 手动补拉 Electron 二进制（npm allow-scripts 拦截时用）
│
├── build-engine.js          # 构建脚本：go build 引擎 + 暂存数据载荷到 engine/
├── engine/                  # 构建产物（gitignore）：sitelens.exe + data/ 载荷
│   ├── sitelens.exe
│   └── data/                #   NVD 种子 / 情报行 / 指纹规则 / 字典
│
├── release/                 # 构建产物（gitignore）：安装包 + win-unpacked
│   ├── SiteLens-Setup-x.y.z.exe
│   ├── SiteLens-Setup-x.y.z.exe.blockmap
│   ├── latest.yml
│   └── win-unpacked/        # 免安装目录版（E2E 更新测试用）
│
└── README.md                # 本文件
```

### 各文件职责

| 文件 | 职责 | 被谁调用 |
|---|---|---|
| `main.js` | 壳进程入口：创建窗口、托盘、注册 IPC、分发更新事件、崩溃自愈编排 | Electron 运行时 |
| `engine.js` | 引擎子进程全生命周期：配置写入、端口协商（壳偏好 > 配置 > 5087）、种子初始化、就绪轮询、优雅停止、崩溃回调 | main.js require |
| `preload.js` | contextBridge 最小暴露：设置页经 `window.sitelens` 调用更新器 / 桌面端偏好 | 设置页渲染进程 |
| `lib/yml-merge.js` | 纯函数：配置文本合并（受管键原位更新，用户键/注释/未知键保留）、listen 值解析 | engine.js |
| `lib/port-policy.js` | 纯函数：端口决策（壳偏好 > 配置原文 > 默认），来源标签追踪 | engine.js |
| `build-engine.js` | 构建脚本（node build-engine.js）：go build 引擎二进制 → 暂存 lite 数据载荷到 engine/ | 开发者手动运行 |
| `build/make_icon.py` | 从 assets/logo.png 裁剪生成 icon.ico / icon.png | 换 logo 后手动运行 |
| `scripts/fetch-electron.js` | npm allow-scripts 门禁拦截 electron postinstall 时手动补拉二进制 | 网络受限环境 |

### 数据布局（更新/卸载永不伤用户数据）

| 位置 | 内容 | 生命周期 |
|---|---|---|
| 安装目录 `%LOCALAPPDATA%\Programs\sitelens` | 引擎 exe + 只读资产（情报库种子/NVD/指纹规则/字典） | 随 app 更新整体替换 |
| `%APPDATA%\SiteLens\state` | 扫描历史（store.data_dir） | 永久 |
| `%APPDATA%\SiteLens\pools\nuclei` | 模板池（update-nuclei 在线拉取） | 永久 |
| `%APPDATA%\SiteLens\plugins` | 用户插件 | 永久 |
| `%APPDATA%\SiteLens\data` | 可变情报（update-nvd / update-fp / update-ehole 写入） | 永久 |

首启把安装包内置种子（NVD 37MB + 情报行 + 指纹规则，位于安装目录
`resources\engine\data`）按缺失补拷到用户数据区——首开即完整体验，
后续 update-\* 成果不会被任何更新覆盖。控制台地址默认
`http://127.0.0.1:5087`，端口优先级为：
**壳偏好（`desktop-prefs.json`）> 配置原文 `web.listen` > 5087**。
被占用才换随机空闲端口，协商结果回写 `desktop-prefs.json` 与
`.sitelens.yml`，下次启动优先认领；偏好缺失/回写失败时回退 5087，
降级路径记入 engine.log（不静默漂移）。

### 排障

- `%APPDATA%\SiteLens\desktop.log`：壳的启动里程碑与更新事件
- `%APPDATA%\SiteLens\engine.log`：引擎输出（1MB 滚动）
- 引擎崩溃自动重启（5 分钟窗口最多 3 次，指数退避），托盘气泡提示；
  超限弹窗示警

## 自动更新

electron-updater generic 多源轮询（客户端内置，顺序 = CNB 主源 →
Gitee → GitHub，均为 `…/releases/download/desktop-stable/` 的
desktop-stable 标签附件区）：启动静默检查 + 运行期每 6 小时复查，
失败的源自动切换下一个，成功的源粘住；后台差量下载（blockmap）→
弹窗「立即重启 / 稍后」→ 静默安装升级（含引擎）；同一版本不重复弹窗。
发布新版时 CI 自动把三件套覆盖到 desktop-stable（Gitee / GitHub 镜像
需各自 token，当前为手工同步）；设置页「检查更新」经 IPC 直连更新器，
真实检查并显示命中的源。

## 本地构建

前置：Go 1.26+、Node 18+、npm。国内网络 `.npmrc` 已指向 npmmirror。

Linux 上出 Windows NSIS 安装包需要 **Wine + Xvfb**（Debian/Ubuntu 下
`apt-get install wine wine64 xvfb xauth`）。两件事都不能少：

- `electron-builder` 会经 wine 调用 NSIS 的 `makensis.exe` 生成卸载器；
- wine 的图形驱动初始化失败时，**任何 32 位 PE 都会秒退**，日志是
  `err:winediag:nodrv_CreateWindow Application tried to create a window,
  but no driver could be loaded.`（随后 electron-builder 报
  `wine process failed 1`）。容器里没有 X server，必须起虚拟显示：
  所有 wine 调用都套 `xvfb-run -a`。

设 `USE_SYSTEM_WINE=true` 可让 electron-builder 直接用系统 wine，跳过它
自带的 wine 工具集下载（其 wine-4.0.1-mac 包在 Linux 上会 spawn 失败）。

> 32 位 wine（`dpkg --add-architecture i386 && apt-get install wine32:i386`）
> 只在**宿主机 wine < 9** 时才需要：老版本靠 32 位库、或靠实验性 wow64 加载
> `C:\windows\syswow64\ntdll.dll`（失败即 `c0000135`）。wine 10 起 wow64
> 已成熟，`WINEARCH=win64` 单装 `wine64` 即可。
>
> ⚠️ wine 的退出码不能当成败判据：32 位 NSIS 引导程序在 wine 下常驻不退
> （`--version` 会一直挂住），/S 静默安装才按 `SetErrorLevel` 返回。
> 验收请以**产物存在且非空**为准，别拿 wine 退出码判红绿。

CI（`.cnb.yml` 的 `v*` tag 流水线）已按此配置；lite / full 两个 job 里
`makensis` 的编译 + 加载校验统一收在 `tools/ci_nsis_exe.sh` 里。

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
`assets/logo.png`（品牌 logo）裁剪生成（去掉 67% 留白，内容撑满），
勿直接手改；换 logo 后重跑：`python build/make_icon.py`（需 Pillow）。

## 已知边界

- 安装包未做代码签名（SmartScreen 会提示"更多信息→仍要运行"）；
  有签名证书后在 `build.win.certificateSubjectName` 配置即可
- 模板池 719MB 不随安装包，首次使用协议/全量模板检测前跑一次
  `update-nuclei`（控制台设置页或 CLI）
- 桌面版随包内置 NVD 全量字典快照（离线可用；上游更新由 update-nvd
  在线补齐），无 PG 依赖；`migrate-pg` 等服务器能力
  不在桌面版叙事内
