# SiteLens 产品页（亮色默认，暗色独立）

## 文件

- `index.html`：亮色版（默认），完整产品介绍页；CSS/JS/Three.js/anime.js/噪点全部内联，无外部请求。
- `dark.html`：暗色版，独立文件，不混排；与亮色版同结构、同内容。
- `web/welcome.html`：由引擎 `/welcome` 路由加载的版本，和 `site/index.html` 保持同步。
- `preview-desktop.png` / `preview-mobile.png`：静态首屏预览。

## 视觉层

- **Three.js r128（MIT，内联）**：WebGL 证据场——17k 点阵、镜头聚焦、环形 HUD、证据节点、扫描光晕；鼠标移动镜头，空闲时自动巡游。
- **anime.js 3.2.2（MIT，内联）**：首屏与滚动入场编排；**首屏关键文案不做 opacity 动画**，避免动画被节流时白屏。
- WebGL 不可用时显示 CSS 证据镜 fallback；移动端关闭 WebGL、使用同一套 CSS 镜面场，避免小屏卡顿。

## 真实工作台，不是手搓 demo

`#demo` 区不再使用前端伪造扫描台，而是直接加载 **SiteLens 实际工作台**：

- `/welcome`：引擎读取 `web/welcome.html`，把 `__SITELENS_TOKEN__` 注入 iframe 的 fragment；
- `/demo/app`：仅对同源 iframe 放行 `frame-ancestors 'self'` / `X-Frame-Options: SAMEORIGIN` 的 app.html 副本；
- 工作台里的输入、扫描、历史、证据都走真实 `/api/*`；静态直接双击 HTML 时 iframe 显示降级提示。

访问：启动 SiteLens 后打开 `http://127.0.0.1:<web.listen>/welcome`。根路径 `/` 与 `/app` 仍是原工作台，不受影响。

## 同步与部署

修改 `site/index.html` 后：

1. `cp site/index.html web/welcome.html`
2. 重新构建引擎（`go build -o dist/wails/SiteLens/engine/sitelens-engine.exe ./cmd/sitelens-engine`）
3. 重启 SiteLens；`/welcome` 即加载新页面。

安装包按 `SiteLens-Setup-5.2.3.exe` 命名放在 `index.html` 同目录；由引擎提供时，下载按钮需指向实际发布地址。

## 口径

- 产品介绍，不是版本更新公告；版本号只出现在界面示意、部署区和页脚。
- 边界保留：G09/G10 默认关、完整矩阵未跑、PG 真机未验、内部签名版本。
- 不套 Pyisland 的居中大 Logo + 浮动胶囊导航；页面结构是 SiteLens 自己的证据台/扫描场。
