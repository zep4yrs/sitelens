@fengqiao(枫桥) 已完成对仓库全量代码的审查。以下是问题汇总，按严重程度排列。

---

## 🔴 高危 Bug

### 1. SSRF：重定向未校验，可穿透内网
**位置**: `scanner/fetcher.py` L62, L80, L95, L130
所有请求均使用 `allow_redirects=True`，但 `TargetValidator` 只校验了**初始目标 URL**。若扫描一个外部域名，该站点可通过 HTTP 302 重定向到 `http://169.254.169.254/`（云元数据）或 `http://127.0.0.1/` 等内网地址，Fetcher 会**无条件跟随重定向并发出请求**。这突破了"拒绝内网/环回地址"的 SSRF 防护设计。

**修复建议**: 在 `fetch()`/`fetch_bytes()`/`get_small()` 中手动处理重定向，每次跳转前校验目标是否满足 `TargetValidator` 规则。

### 2. `cve_ms` 表在空库时不存在，每次扫描直接报错
**位置**: `scanner/db.py` (ensure_schema) / `scanner/vuln.py` L106
`Database.ensure_schema()` 创建了 `categories`、`technologies`、`vuln_kb` 等表，但**没有创建 `cve_ms` 表**。该表只在 `tools/import_assets.py` 中有完整的建表逻辑（且仅在资产包存在时才执行）。README 声称"没有漏洞收集包也能跑"，但扫描时 `engine.scan()` 会调用 `match_cve_ms()` 查询不存在的 `cve_ms` 表，导致**所有扫描都报错失败**。

**修复建议**: 在 `ensure_schema()` 中补建 `cve_ms` 表（DDL 可从 `import_assets.py` 复制），并在 `match_cve_ms()` 外层加 `try-except` 兜底。

---

## 🟠 功能 Bug

### 3. 前端字段名不匹配：`v.level` vs 后端 `v.verdict`
**位置**: `scanner/vuln.py`（输出 `verdict`）/ `web/app.html` L484-486、`web/history.html` L216-217
后端 `VulnMatcher.match()` 返回的每条漏洞字典中，三级判定字段叫 **`verdict`**（值为 `"confirmed"/"possible"/"excluded"`），但前端检查的是 **`v.level`**。结果是"确认受影响 / 可能受影响"徽章**永远不会渲染**，用户看不到三级判定结论。

### 4. 不存在的页面路由直接 500
**位置**: `app.py` L131-141
`page_netsec()` → `netsec.html`、`page_loginbrute()` → `loginbrute.html`、`page_verified()` → `verified.html`，但这 3 个文件在 `web/` 目录**不存在**。直接访问 `/netsec`、`/loginbrute`、`/verified` 会抛 `FileNotFoundError`（未加异常处理）。

### 5. HTML 报告目录扫描渲染错误
**位置**: `scanner/report_html.py` L42
报告 HTML 对 `dir_scan` 的渲染取 `it.get("path")`，但 `scanner/modules.py` 中 `dir_scan()` 返回的条目字段为 **`url`**，不包含 `path`。导致 HTML 报告中目录探测行首字段为空白。

### 6. `/api/audit` 上传无文件大小限制（DoS）
**位置**: `app.py` L173-221
Flask 默认 `MAX_CONTENT_LENGTH = None`（无限）。用户可上传任意大的文件/zip 包。zip 解压也无大小上限（`run_audit` 虽有单文件 1MB 检查，但那是解压后审计阶段）。恶意用户可以一次上传 GB 级压缩包，耗尽磁盘和内存。

---

## 🟡 UX / 体验问题

### 7. `/api/netsec` 丢失端口参数
**位置**: `app.py` L570
用户输入 `example.com:8443` 时，`TargetValidator.validate(host)` 返回 `("https", "example.com", 8443)`，但代码只取 `[1]`（host），**端口被丢弃**。然后 `run_netsec()` 始终对 443 端口做 TLS 检测，即使用户想测 8443 也会被查 443。

### 8. 认证 Cookie 明文暴露在 URL/表单
**位置**: `web/app.html` L127、L339-340
Cookie 值会随 `/api/scan` POST 请求体明文传输。若 API 通过明文 HTTP 或代理暴露，会话凭据可能泄露。建议使用 POST 并依赖 HTTPS 传输。

### 9. `/api/job/<job_id>/cancel` 竞态
**位置**: `app.py` L318-329
批量扫描取消时，`_cancel_requested.add(job_id)` 和 `_batch_cancel.add(job_id)` 非原子操作，且各线程对全局 set 的读写无锁保护。高并发下可能出现漏取消或误取消。

### 10. `/api/stats` 中 `similarity()` 依赖 pg_trgm 扩展
**位置**: `scanner/db.py` L311-315
`search_vulns()` 直接使用 `similarity(product, %s)` 函数，虽在 `ensure_schema` 尝试创建 `pg_trgm` 扩展，但如果扩展不可用（权限不足），该函数会抛错。代码没有降级处理。

### 11. `favicon_hash` 使用 `base64.encodebytes()` 而非 `b64encode`
**位置**: `scanner/favicon.py` L47
`base64.encodebytes()` 每 76 字符插 `\n`。对 >57 字节的 favicon，生成的 hash 与标准 fofa 实现（使用 `base64.b64encode()`）**不一致**，可能导致部分指纹匹配失效。

---

## 🟢 代码质量建议

1. **全局可变状态无锁**（`_engines`, `_cancel_requested`, `_batch_cancel`）— 建议改用 `threading.Lock` 或改用消息队列。
2. **`Fetcher.__session` 跨目标共享 Cookie** — 单个 `Fetcher` 实例如果被复用（比如同一 engine 扫描多个 URL），不同站点的 Cookie 会互相串台。当前每次扫描新建 Fetcher 所以没问题，但**缺少文档说明和防误用保护**。
3. **`/api/loginbrute` 仅靠前端 JS 勾选"授权确认"** — 后端只检查 `bool(data.get("authorized"))`，任何人都可直接 POST `{"authorized": true}` 绕过。作为安全工具，建议至少加上 token 或 IP 限流。
4. **`run_audit` 中 `SKIP_DIRS` 含 `data` 但 web 模板目录未排除** — 不过 web 目录中无敏感内容，影响有限。
5. **`crawler.py` 未限制单页 `<a>` 提取数量为 40**，但每页 HTML 可能包含大量链接，且深爬只取前 40 个 URL — 可优化为按相关性排序后取前 N。

---

## 总结

整体代码结构清晰、设计合理（封装/继承/多态/组合的运用规范），SSRF 防护主路径做得不错，扫描结果持久化、异步任务调度、多模块解耦都值得肯定。但存在 **2 个高危 Bug**（重定向穿透 SSRF、空库扫描即崩）、**4 个功能 Bug**（字段不匹配、死路由、报告渲染错误、无文件大小限制）以及若干体验问题。建议优先修复第 1、2 项，这直接影响产品的核心安全承诺和可用性。