# 桌面版 DIY TODO — 启动页 + 安装器定制

> 状态更新于 2026-09-13。构建产物：`desktop/release/SiteLens-Setup-3.0.0.exe`；
> 验收方式：单测 12/12 → 静默装/卸全流程 → 启动冒烟（desktop.log 里程碑
> splash shown → engine ready(4s) → window shown + 引擎 HTTP 200）。
> 本机已装回正式版 `D:\Program Files\SiteLens`，桌面+开始菜单快捷方式就位。

## 一、透明启动页（无底板）

引擎就绪前，屏幕上只浮现 logo + 品牌描边动画，没有深色底板、没有窗口框——像桌面挂件。

### 设计

- BrowserWindow `transparent: true` + `frame: false` + `alwaysOnTop: true`
- HTML body `background: transparent`，只有 logo 图片和描边文字两个元素
- 引擎就绪后启动页淡出，主窗口淡入

### 动画时序

| 时间 | 元素 | 效果 |
|---|---|---|
| 0s | logo | 从 scale(0.6) + opacity(0) 弹性放大浮现 |
| 0.3s | "sitelens" 描边文字 | SVG stroke-dashoffset 逐笔画出轮廓 |
| 1.8s | 描边→填充 | 轮廓画完后文字从空心过渡到实色 |
| 2.4s | 状态文字 | "正在启动引擎…" 淡入 |

### 任务

- [x] 创建 `desktop/splash.js`：独立透明启动窗（logo base64 + SVG 描边动画 + 状态/错误接口）
- [x] 主窗口在引擎就绪前不创建（main.js whenReady：先出启动页 → engine.start → 就绪才建窗直接进工作台）
- [x] 启动页淡出 → 主窗口淡入的过渡（splash fadeOut + win.setOpacity 渐入）
- [x] 崩溃/超时时启动页显示错误信息后淡出（splash.splashFail：红字 3.5s → 淡出，主窗口错误页常驻接管）

---

## 二、安装器 DIY

### 已完成

- [x] 图标裁剪（去 67% 留白，内容撑满）——**原样保留原 logo 风格，不做改色/重绘**（2026-09-13 用户明确：改了风格挨批，已回滚）
- [x] 许可协议页 RTF（中文不乱码，`build/license.rtf`，gen_rtf.py 可复现）
- [x] `allowToChangeInstallationDirectory: true`（可选安装目录）
- [x] **默认装 D 盘**：`build/installer.nsh` customInit——无既往安装、未用 /D 指定、D: 为固定磁盘三者同时满足时默认 `D:\Program Files\SiteLens`（C 盘安装是大忌）。实测静默装落 D: ✓
  - **交互模式修正（2026-09-13 晚）**：模式选择页（仅为我/所有人）点下一步时 `setInstallModePerUser` 会重读注册表并重置 $INSTDIR（无既往安装回落 C 盘用户目录），直设的 D 盘被覆盖——「向导默认 C 盘」的根因。修法：交互模式下把 D 盘默认值预写 `InstallLocation`（静默装不写，$INSTDIR 直设即可），让模式页认领回来；安装完成时模板覆写为最终目录，中途取消由 `.onUserAbort` 清理（值=默认目录且该目录无真实安装的卸载器才删，无状态判断）。实测全新路径向导落 D 盘 ✓
- [x] **PATH 环境变量**：customInstall 把安装目录追加进 `HKCU\Environment`（幂等）+ WM_SETTINGCHANGE 广播；customUnInstall 卸载时按分号边界三态移除。实测：装后 PATH 出现条目、卸后零残留 ✓
  - 注：原设想「自定义安装展开后勾选」做不了——electron-builder 的 MUI2 向导链不允许注入 nsDialogs 自绘页，改为默认开启、卸载自动移除（无残留即无代价）
- [x] **安装/卸载品牌侧栏图**（164×314 24 位 BMP，gen_brand_bmps.py 生成）：logo 原样放浅色圆角底板 + mono 品牌名 + 绿点 + 站点透视 v3.0.0 + 「仅限授权测试目标」
- [x] **安装进度条品牌化**：customInstall 内 PBM_SETBARCOLOR 改品牌绿 #22c55e（编译进安装器；静默装不可视验，向导安装时生效）
- [x] **安装完成页运行 SiteLens**：NSIS `runAfterFinish` 默认勾选（electron-builder assisted 默认行为保留）
- [x] **快捷方式**：桌面 + 开始菜单（实测两处 .lnk 均生成，图标为裁剪后 logo）
- [x] **卸载询问保留扫描历史与偏好**：customUnInstall 弹 MB_YESNO（交互卸载时）；静默 /S 不弹窗默认保留（与 `deleteAppDataOnUninstall: false` 一致）
- [x] **卸载界面品牌化**：uninstallerSidebar 侧栏图

### 与原设想的偏差（做不了的注明原因）

- **QQ / 火绒 / WPS 式全窗口品牌背景 + 大按钮「立即安装」**：需要在 electron-builder 的 NSIS 模板外重写整个页面链（MUI2 不支持混插 nsDialogs 自绘页），等于 fork 模板自己维护 NSIS 工程，收益/维护比不划算。落地为「向导品牌化」折中：品牌侧栏图 + RTF 许可 + 品牌进度条 + 可选目录。若后续坚持整窗风格，再评估手写 NSIS 工程。
- **「添加到 PATH」勾选项**：同上（无法注入自定义页），默认开启 + 卸载移除替代。

### 不做

- 代码签名（无证书；SmartScreen 提示属预期行为，发布页已说明）

---

## 三、验收清单

- [x] 安装流程（静默装实测：D: 落盘 → 注册表卸载键 → PATH → 快捷方式 → 卸载全净）
- [x] 许可协议页 RTF 中文（上轮已验证渲染，本轮接线 `license: build/license.rtf`）
- [x] 安装目录可选（含 D: 盘；默认即 D:）
- [x] 桌面 + 开始菜单快捷方式图标为裁剪后 logo
- [x] 启动时透明启动页（logo + 描边动画）→ 淡入工作台（desktop.log 里程碑全序）
- [x] 关窗收托盘 / 托盘退出 / 开机自启均正常（上轮验证，本轮未改动该路径）
- [x] 自动更新多源轮询正常（上轮验证；本轮冒烟日志里 update 源不可达为网络环境所致，非致命）

## 维护提示（下次改桌面版必读）

- 改 `web/` 或 `desktop/` 任何文件 = `npm run engine`（go:embed）+ `npm run dist`；`build.files` 白名单漏模块 = ASAR 内 require 失败秒退（splash.js 已入清单）
- `installer.nsh` 的 StrFunc 声明必须按 pass 守卫：electron-builder 用 `/DBUILD_UNINSTALLER` 把同一脚本编两遍，安装侧函数在卸载器 pass 未引用 → warning 6010 = 编译失败
- customInit 跑在 initMultiUser 之后，`$INSTDIR` 已被填成 `%LOCALAPPDATA%\Programs\SiteLens`，判「空」永远不成立；默认目录改判注册表 InstallLocation + /D 参数
- NSIS 警告即错误（warning 6010 = error）：未引用的 StrFunc 声明会炸编译
