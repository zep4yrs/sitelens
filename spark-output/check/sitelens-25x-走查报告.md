# 设计走查报告 — SiteLens 25A/25B 交付 + 全站动效

**走查目标**：25A 源码审计升级（Monaco+文件树+标注）+ 25B 七页体验升级 + Corporate 动效基准
**走查时间**：2026-09-17
**走查模式**：Mode C 定向验证（25A/25B 验收清单逐项核对）+ 10 类静态/动态抽查（CDP 实测 + 代码核查）

## 优先核对：上游验收承诺 → 落地核对

### 25A 验收清单（7 项）

| # | 验收项 | 判定 |
|---|---|---|
| 1 | zip 多文件 → 树层级 | ✅（CollectSources 相对路径 + buildTree；demo 实测树渲染） |
| 2 | 点文件 → 内容 + 语言高亮 | ✅（CDP：编辑器 489 字符、python 映射） |
| 3 | findings 标注 = 列表 | ✅（markers 7 = 发现 7） |
| 4 | 点发现 → 跳行居中 | ✅（lineNumber=2 精确命中） |
| 5 | 切走切回状态保留 | ✅（models 按 URI 常驻设计） |
| 6 | 演示样本入口不存在 | ✅（按钮 + runDemo 已删） |
| 7 | Turbo 全链路不回退 | ✅（VERIFY-PASS） |

### 25B 各页验收

| 页 | 交付 | 判定 |
|---|---|---|
| B1 批量 | 逐 URL rows（后端运行中即推）+ 队列表格 | ✅（真实跑通：queueVisible/1 行渲染） |
| B2 网络层 | 检测卡片网格 | ✅ |
| B3 历史 | 统计卡 + 时间筛选 chips | ✅ |
| B4 情报库 | 防抖即搜 + 严重度 chips | ✅ |
| B5 登录爆破 | 导出命中 CSV | 🟡 部分（实时尝试流延后：需后端事件流） |
| B6 攻击链 | 复制链路 JSON | 🟡 部分（画布重写 + 详情侧栏延后） |
| B7 设置 | 搜索框（实测"exploit"精准命中 1 分组）+ exploit 危险警示框 | ✅ |

## 10 类抽查 Findings

### 🟠 Major
1. **[反馈与交互]** 登录爆破进行时无「已尝试 N」实时计数（poll 仅整体 message；后端无逐次事件流）
   - 出现位置：工作台-登录爆破 / internal/server loginbrute job
   - 修复建议：复用 B1 模式——job.Result 加 attempts 计数，poll 时展示（后端小改 + 前端一行）

### 🟡 Minor
2. **[组件使用]** 圆角 7px 残留 2 处（左栏软芯片、模式行 tab），违反 8px 刻度
   - 出现位置：web/app.html 芯片规则、web/css/app.css 模式行
   - 修复建议：统一 8px —— **本次走查已当场修复**
3. **[反馈与交互]** 被动页顶带当前项高亮仅视觉，无 aria-current="page"
   - 出现位置：common.js topNavHTML
   - 修复建议：slUpdateNav 时同步 setAttribute("aria-current", "page")
4. **[组件使用]** tw-fold 折叠样式 9 行死代码残留（扫描配置折叠壳已拆除）
   - 出现位置：web/app.html style 块
   - 修复建议：下轮清理
5. **[响应式]** 窄窗（980px 下限）时左控制列 302px 固定，五模式行 11px 标签贴边拥挤
   - 出现位置：web/app.html .tw-modes
   - 修复建议：窄窗媒体查询下标签缩至 10.5px

## 通过项抽样（未列全）

- 空态三态（未选目标/无结果/无预览置灰）✓；批量 0 发现列 "—" ✓；危险项红色警示+文字+徽章三重 ✓；图标按钮均有 title ✓；对比度 muted-fg #64748b on #fafafa ≈ 4.7:1 ✓

## 修复优先级建议

- 建议修复：Major 1（爆破计数，复用 B1 模式后端小改）+ Minor 3（aria-current 一行）
- 可延后：Minor 2（已修）/ 4（死 CSS）/ 5（窄窗挤压）
