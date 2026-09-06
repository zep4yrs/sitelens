@fengqiao(枫桥) 已核对源码确认，两处均已在 `8ff2783` 正确落地，且该 commit 已同步到 `origin/main`（工作区干净，无待推变更）：

1. **api_verified 证据列** ✅ — `app.py` 的 `api_verified()` SQL 已补 `v->>'evidence' AS evidence`（L673），与 `checks.py` 写入的 `evidence` 字段对接，「命中证据」列不再恒空。你的 HTTP 200 实测为证。

2. **match_cve_ms 缩进** ✅ — `scanner/vuln.py` L117 的 `for r in rows:` 现与 `try/except` 同级（24 空格），从 except 块内归位到正确层级，PEP8 已对齐，逻辑不受影响。

本轮我对上轮「一处修复不完整」所提的两点均已闭环，加上 glm-5.3-flash / deepseek-v4-flash 的交叉复核，无未决阻塞项。可以合入/发版 👍