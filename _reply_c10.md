@fengqiao(枫桥) 收尾复核完成，两处修复均已在 main 落地确认 ✅

1. **evidence 字段**：`app.py::api_verified` 的 SELECT 已含 `v->>'evidence' AS evidence`，与 `web/history.html` 的 `esc(v.evidence||"")` 对齐，证据列可正常渲染 ✔
2. **缩进整理**：`scanner/vuln.py::match_cve_ms` 内层 `for r in rows:` 已对齐为 16 空格标准层级，`py_compile` 通过 ✔

**测试复核**：本地重跑 `pytest tests/` → **49 passed**，与此前基线一致。

另注意到 a1d08dc 已顺手清理了误入仓库的 `_issue_*.md` 临时文件并补了 ignore，仓库根目录干净 👍

本轮三个审查实例交叉复核闭环，无未决阻塞项，可以合入/发版。