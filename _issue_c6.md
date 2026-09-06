@fengqiao(枫桥) 已对照源码逐条复核 commit `624ad9d`（HEAD=main），你的修复总体扎实、方向正确，我原报的高危项（重定向 SSRF、空库缺 cve_ms、verdict 字段、死路由）均已正确闭环。补充一处**修复不完整**与若干次要观察。

## ✅ 已核实修复到位

- **SSRF 逐跳校验**：`fetcher._get_follow` 禁用自动重定向、逐跳 `TargetValidator.validate(nxt, resolve=True)`（协议白名单+解析+私网拒绝），且全局再无残留 `allow_redirects=True` 的目标请求；`post_form` 对 3xx 亦先校验再 GET 跟随。原高危 #1 已封堵 ✔
- **空库 cve_ms**：`ensure_schema` 已补 `CREATE TABLE cve_ms`；`match_cve_ms` 外层 try 空表静默跳过 ✔
- **jobs ALTER 时序**：已移到 `CREATE TABLE jobs` 之后 ✔
- **/api/stats 富集列**：`vuln_kb` 的 `sources/cvss_score/cvss_sev/cvss_vector_txt` 均已 `ADD COLUMN IF NOT EXISTS`，空库 /api/stats 不再 500 ✔（`pg_trgm` 不可用也已降级包含匹配）
- **verdict 字段**：app.html/history.html 均改 `v.verdict`，`safeLink` 仅 http/https 渲染、esc 转义引号，注入面收敛 ✔
- **死路由 / report_html(url) / favicon(b64encode) / OCR 清洗 / data 绝对路径(任意 CWD) / netsec 非 443(tls_port) / limit 兜底 / 删除 toast** 均与源码一致 ✔
- **sys_version**：`SilentHandler.sys_version = ""` 仅是类属性赋字符串字面量，无需 `import sys`，确系误报，不修合理 ✔

## ⚠️ 一处修复不完整

**「历史已验证表补命中证据列」列空白。** `web/history.html` 的 `loadVerified()` 在 `/api/verified` 表格新增了 `<th>命中证据</th>` 与 `esc(v.evidence||"")` 单元格，但后端 `app.py` 的 `api_verified()` SQL **未 select `v->>'evidence'`**（只取了 `check/title/severity/url`）。故该列恒为空。

修复：在 `api_verified` 的 SELECT 补 `v->>'evidence' AS evidence` 即可（verified 项确实携带该字段，见 checks.py 的 `"evidence": ...`）。

## 🔸 次要观察（不影响功能）

1. `scanner/vuln.py` `match_cve_ms` 内层 `for r in rows:` 的循环体相对缩进多了 4 空格（函数体整体 24 空格），语法/逻辑正确但违反 PEP8，建议顺手对齐。
2. `_safe_limit` docstring 写「返回 400」，实际是回退默认值（不 500 的目的已达到），措辞可校正。
3. `_maybe_favicon` 调 `fetch_bytes` 不再吞全部异常——若扫描站点的 `/favicon.ico` 302 到内网，会抛 `TargetError` 中断整次扫描。鉴于该场景本身就是真 SSRF，抛错是安全取向，可接受；若想更稳健可在此处单独捕获 TargetError 降级跳过。

## 结论

除「已验证表证据列」需在后端 SQL 补一个字段外，其余修复与「核实后不修」判断均成立。补上后整轮闭环，可以直接合入。
