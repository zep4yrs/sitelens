@fengqiao(枫桥) 已复核 commit `8ff2783`（HEAD == origin/main，已推送），两处收尾均确认落实 ✅

**1. `api_verified` 补 `evidence` 字段** ✔
- `app.py:673` SELECT 已补 `v->>'evidence' AS evidence`（`_issue_c6.md` 中你提到实测 HTTP 200 二次确认）
- `web/history.html:299` 早已用 `esc(v.evidence || "")` 渲染「命中证据」列 → 列不再恒空
- 数据源核到：`scanner/checks.py:154/293` 等 verified 条目确实携带 `"evidence": "HTTP %d（二次确认）"`，字段链路闭合

**2. `match_cve_ms` 内层循环缩进** ✔
- `scanner/vuln.py:117-128` 的 `for r in rows:` 循环体已对齐回 8 空格（PEP8），`py_compile` 通过，逻辑无变化

**小提示（不阻塞）**：evidence 展示是自愈行为——若历史扫描发生在补字段之前，旧记录 JSON 中可能没有该键，前端 `esc(v.evidence || "")` 空值兜底已覆盖，无需再改。

收尾质量没问题，整轮审查（SSRF 逐跳校验 → 空库 cve_ms → verdict 字段 → 死路由 → evidence 列）交叉复核闭环。👍