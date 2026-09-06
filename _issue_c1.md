@fengqiao(枫桥) 已完成全仓库代码审查（app.py、scanner/ 全部 29 个模块、web/ 前端、tools/）。整体架构清晰、SSRF 防护和 SQL 参数绑定意识很好，但发现 **1 个启动级 Bug、4 个高危问题**及若干体验问题，按严重度列出：

## 🔴 严重（会导致功能失效）

### 1. `app.py:666` — `sys_version` 未定义，启动即 NameError
`SilentHandler` 里写了 `sys_version = ""`，但 `app.py` **没有 `import sys`**。类体求值时直接 `NameError: name 'sys' is not defined`，`python main.py serve` 无法启动（`if __name__ == "__main__"` 分支必触发）。
```python
import sys  # 顶部补上即可
```

### 2. `app.py:173` — `ALTER TABLE jobs` 在建表语句之前执行
`ensure_schema()` 里 `ALTER TABLE jobs ADD COLUMN IF NOT EXISTS result JSONB` 写在 `CREATE TABLE IF NOT EXISTS jobs` **前面**。全新部署时 jobs 表还不存在，该语句报错 → 事务回滚 → **整个 schema 初始化失败**，首次启动直接崩。把 ALTER 移到 CREATE TABLE jobs 之后。

### 3. `web/app.html:484` 与 `web/history.html:216` — 判定字段名用错
后端 `scanner/vuln.py` 输出的字段是 `verdict`（"confirmed"/"possible"/"excluded"），前端判断的却是 `v.level` → **「确认受影响/可能受影响」徽章永远不显示**，版本区间判定这一核心功能在页面上失效。前端统一改成 `v.verdict`。

## 🟠 高危（安全 / 数据一致性）

### 4. `app.py:459-466` — `/api/stats` 依赖未建列的 `sources`、`cvss_score`
这两列只在 `tools/update_intel.py:ensure_ext_columns()` 里添加，`db.py:ensure_schema()` 不建。全新部署后未跑过 update_intel 时，打开首页统计接口就 500（`column "sources" does not exist`）。建议把这两列的 `ADD COLUMN IF NOT EXISTS` 挪进 `ensure_schema()`。

### 5. `scanner/fetcher.py` — 请求未禁用 TLS 校验？不，问题是「从未设置」相反面：`requests` 默认 verify=True 没问题，但整个 Session **没有设置 `verify` 与代理环境隔离**，更值得提的是：目标站重定向到**其它域**时仍会继续跟随（`allow_redirects=True` 无跨域限制）。SSRF 校验只在 `ScanTarget` 入口做了一次，**重定向后的每一跳不再校验**，目标 302 到 `http://127.0.0.1:8500` 类内网地址即可绕过防护（DNS Rebinding 同理）。建议在 Fetcher 层禁自动重定向、手动逐跳校验后再跟随。

### 6. `app.py` — 上传审计接口无大小/数量限制
`/api/audit` 对 `files` 无 `MAX_CONTENT_LENGTH` 限制，zip 炸弹可写满磁盘（临时目录在解压后仍可能放大 N 倍才被 rmtree）。建议配置 `app.config["MAX_CONTENT_LENGTH"]`，并对解压后总大小设上限。

### 7. `web/index.html` 等页面 — 用户可控数据注入 DOM 的 XSS 面
前端大量 `innerHTML` 拼接（这是本地工具风险可控），但 `web/history.html:117` 表格里 `s.host / s.title` 都已 `esc()` ✔；**真正漏网的是 `web/app.html:487` 的 `v.ref` 拼进 `<a href>`**：`esc()` 不转义单引号，且 `ref` 来自外部情报库（GHSA/NVD 同步数据），若情报源被污染可注入 `javascript:` 或突破属性。建议对 URL 做协议白名单（`https?://` 开头才渲染为链接）。

## 🟡 中危 / Bug

### 8. `app.py:641` 与 `web/batch.html` — 批量取消判定矛盾
`api_batch` 的 worker 用 `job_id in _cancel_requested` 判断「已取消」，但 `/api/job/<id>/cancel` 对批量任务是把 job_id 放进 `_batch_cancel`，`_cancel_requested` 只在有运行中 engine 时才有值。批量任务若已启动、未点取消前 engine 字典为空（各子扫描各自的 engine），**取消逻辑依赖两个集合的状态时序**，存在「点了取消但状态仍变 done」的窗口。

### 9. `scanner/loginbrute.py` — 全局可变状态 `_last_diag` 线程不安全
多任务并发爆破时互相覆盖诊断信息，报错提示可能张冠李戴。改为局部返回即可。

### 10. `scanner/modules.py:230` — `SHELL_LIST` 相对路径依赖 CWD
所有 wordlist 路径都是 `"data/wordlists/..."` 相对路径，从其它目录启动（`python /path/main.py serve`）时全部静默返回空列表（弱口令/WebShell/目录扫描悄悄失效，无任何报错）。建议用 `Path(__file__).parent` 拼**绝对路径**——`scanner/db.py` 已有 ROOT 常量可复用。

### 11. `scanner/captcha.py:52` — 验证码答案可能返回字符串数字
`ocr_image()` 返回 ddddocr 识别文本，`digits` 模式直接塞进表单不做清洗（空格/换行），命中率和稳定性打折；建议 `re.sub(r"D", "", text)` 后再提交。

## 🔵 体验问题

### 12. 历史列表按 `s.id DESC` 排序但删除后 id 不回收——没问题；真正的小问题：
- `/api/history` 的 `limit` 参数传非数字时 `int()` 抛 ValueError → **500 而非 400**（`app.py:400`、`app.py:637` 两处），应 try/except 后返回 400。
- `web/history.html` 详情里 `v.evidence`（命中证据）未展示，与工作台不一致。
- `delScan` 删除后无 toast 反馈，只有列表刷新，误删无确认二次防护（有 confirm ✔ 但成功后无提示）。
- `app.py:167` 7z 解包超时 120s 内用户无进度反馈，前端只有笼统「检测中」。
- CSS/JS 路由（`app.py:230-235`）`send_file` 直拼 filename 且 `<path:filename>` 允许 `/`，werkzeug 的 safe_join 已挡 `..`，但建议仍显式 `os.path.realpath` 校验在 WEB_DIR 内，防软链/编码绕过。

## 📊 总评
代码规范度高（类型封装、多态检测器、参数化 SQL、SSRF 白名单都有模有样），**当前主要风险集中在「初始化时序」和「字段名不一致」这类集成 Bug**——#1/#2/#3 会让首次部署和版本判定功能直接失效，建议优先修复。附修复优先级：#1 #2 #3 #4（半天内可全部完成）→ #5 #6 #7 → 其余。