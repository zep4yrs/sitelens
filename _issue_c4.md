@fengqiao(枫桥) 已逐条对照源码核实 624ad9d，确认修复到位 ✅（本地复跑 49 项测试全绿）。

**逐项核实结果**

🔴 关键项 4/4 落实：
- **SSRF 重定向穿透**：`fetcher.py` 新增 `_get_follow`，禁用 `allow_redirects` 后逐跳 `TargetValidator.validate(nxt, resolve=True)`，最多跟 6 跳；`fetch` / `fetch_bytes` / `get_text` 全部切换，`post_form` 的 POST 也改为不跟随 + 校验后 `_get_follow`。`urljoin` 处理相对 Location 也对。302→内网的绕过路径已封死。
- **空库缺 cve_ms**：`db.py` ensure_schema 补 `CREATE TABLE cve_ms`；`vuln.py` match_cve_ms 加 try/except 兜底，空表/缺表静默返回不阻塞扫描。顺带的 pg_trgm 降级包含匹配也是加分项。
- **ALTER 移到 CREATE 之后**：已确认 `db.py` 中 `ALTER TABLE jobs ADD COLUMN result` 现位于 `CREATE TABLE jobs` 之后，全新部署不再崩。
- **verdict 字段名**：`web/app.html` 与 `web/history.html` 均改为 `v.verdict` 三分支渲染，与 `vuln.py` 输出一致。

🟠🟡 其余项抽查均落实：
- `/api/stats` 富集列（sources/cvss_score/cvss_sev/cvss_vector_txt）已入 ensure_schema
- 死路由 `/netsec` `/loginbrute` `/verified` → 302 到 `/app#页签` 与 `/history#verified`
- zip 炸弹：`MAX_CONTENT_LENGTH` 200MB + 逐条累计 `file_size` 对比 512MB 上限，校验在 extractall 之前
- favicon `b64encode`（无换行）与 fofa 标准一致
- 情报外链 `safeLink` 协议白名单（`^https?://`），三个页面统一接入，还补了 `rel="noopener noreferrer"`
- `DATA_DIR` 锚定 `Path(__file__).parents[1]`，任意 CWD 启动可用；`_safe_limit` 回退默认值不再 500；OCR 清洗、目录探测 `url` 字段、netsec 非 443 端口均确认

**误报澄清**：`sys_version` 确实是我方误报——`app.py:698` 是类体属性赋值 `sys_version = ""`，不涉及 `sys` 模块引用，无需 import。批量取消与 Cookie 两项的「不修」理由也核实合理。

本次提交还顺带做了静态路由 realpath 防目录穿越加固，超出审查清单范围 👍。当前无未决阻塞项，本 Issue 审查闭环。