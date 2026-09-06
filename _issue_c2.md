两轮审查已逐条对照源码核实并全部处理，修复提交 624ad9d（已推送 main，49 项测试全绿）。感谢 CodeBuddy——重定向 SSRF、空库缺 cve_ms、verdict 字段名、死路由 500 四条是实打实的关键发现。

**已修复**
- 🔴 SSRF 重定向穿透：fetcher 禁用自动重定向，新增 _get_follow 逐跳 TargetValidator 校验（协议白名单 + DNS 解析 + 私网拒绝），post_form 跳转同处理
- 🔴 空库缺 cve_ms：ensure_schema 补建表；match_cve_ms 加兜底（空表静默跳过不阻塞扫描）
- 🔴 ensure_schema 中 jobs 的 ALTER 位于 CREATE 之前：已移正（修复全新部署首次启动即崩）
- 🟠 /api/stats 富集列（sources/cvss_score/cvss_sev/cvss_vector_txt）纳入 ensure_schema
- 🟠 三级判定字段：前端 v.level → v.verdict，确认/可能徽章恢复渲染（实扫 20 条情报全部携带 verdict）
- 🟠 /netsec /loginbrute /verified 死路由 → 302 重定向到工作台页签 / 历史页签
- 🟠 /api/audit：200MB 请求体上限 + 512MB 解压上限（防 zip 炸弹）
- 🟠 favicon 改 b64encode（encodebytes 换行导致大图标哈希与 fofa 不一致）
- 🟡 report_html 目录探测字段 url（原取不存在的 path 显示空白）；历史已验证表补命中证据列；删除记录 toast；情报外链仅 http/https 渲染；data/ 路径锚定仓库根（任意 CWD 启动可用）；netsec 支持非 443 端口；爆破 OCR 结果清洗；limit 非数字回退默认值

**核实后不修（误报 / 已有防护）**
- `sys_version` NameError 为误报：类属性赋值不需要 import sys，服务全程正常运行
- Cookie 明文：本就是 POST + 默认绑定 127.0.0.1，维持现状
- 批量取消时序：cancel 路由同时写入两个集合并标记 cancelling，worker 终态判定已覆盖，无实际窗口
- zip 路径穿越：is_relative_to 边界校验已有，本次叠加解压体积上限

实测：49 项单元测试全绿；text-well 实扫 13 项指纹、20 条情报全部携带 verdict。