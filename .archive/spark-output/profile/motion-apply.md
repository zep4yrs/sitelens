# React Bits — Project Profile
_Auto-maintained by motion-apply skill. Edit manually to override._

## Stack
- Variant: JS-CSS（原生 JS + Turbo Drive，无 React/TS/Tailwind）
- Animation engine: 无引擎——CSS transition/keyframes + 少量 JS（slPoll/MutationObserver）
- React version: 无（ReactBits 组件库不适用本项目）
- Framework: SiteLens 自研双壳（Electron 安装版 + Wails 实验壳），引擎 Go go:embed 前端

## Scene
- Detected: DASHBOARD（扫描器工作台：表格/表单/状态面板为主，全站单顶带+左列双区布局）
- Intensity ceiling: subtle/functional only
- Override: 用户可说"这个页面是 landing page"解锁高冲击动效

## Tonality (inferred)
- Style: Corporate 专业稳重（用户 AskUserQuestion 拍板，2026-09-17）
- Color: 近无彩色（#fafafa/#1a1a1a + 深灰主色），severity 语义色（红/黄/蓝）仅用于分级
- Font: LXGW WenKai + Noto Sans SC
- Radius: 控件 8px / 容器 10px / 胶囊 999px
- 动效 tokens: --t-fast 150ms / --t-med 250ms / --t-slow 400ms / --ease cubic-bezier(0.2,0,0,1)

## History
- 2026-09-17: 全站动效基准落地（tokens + 级联 + 下划线 + reduced-motion）——motion-plan.json 12 元素规格
- 2026-09-17: Monaco 就绪淡入 + 发现跳行闪烁渐隐（audit.js）
- 用户批准的循环例外：空态呼吸 2.6s / 状态点运行脉冲 1.2s / logo 呼吸点（3.0 既有）

## Preferences (derived)
- Lean: Corporate 克制、功能性、无 overshoot
- Avoid: 回弹、大位移（>8px）、循环装饰（除用户批准项）、glitch/neon

## 环境陷阱（本项目特有）
- 前端由 go:embed 打进引擎二进制：改 web/ 后必须 `go build` 重建引擎再验证
- embed 资源 Cache-Control: no-cache（防旧 common.js + 新页面白屏）
- Turbo 换 body 不换 window：全局函数残留（如 switchTab）需按路径+DOM 判定上下文
