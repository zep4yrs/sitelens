# SiteLens 产品官网（单文件）

- `index.html`：完整产品介绍页，CSS/JS/图标全部内联，无外部字体、图片或脚本依赖；
- `preview-desktop.png` / `preview-mobile.png`：1440 宽桌面首屏与 390 宽移动端首屏预览；
- 下载按钮指向同目录 `SiteLens-Setup-5.2.3.exe`，部署时把安装包放在旁边即可；
- 支持亮/暗主题切换，跟随系统偏好，手动选择写入 localStorage；
- 文案口径：产品介绍，不是版本更新公告；版本号只出现在界面示意与页脚；
- 边界口径保留：G09/G10 默认关、完整矩阵未跑、PG 真机未验、内部签名版本。

部署：把整个 `site/` 目录放到任意静态服务器；安装包按 `SiteLens-Setup-5.2.3.exe` 命名放在 `index.html` 同目录。
