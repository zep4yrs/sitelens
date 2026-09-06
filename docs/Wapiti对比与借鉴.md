# SiteLens × Wapiti 同栈对比分析（补充 Nuclei 对比）

> 口径：2026-09-05 基于 wapiti-scanner/wapiti 仓库**实际代码**核对（GitHub API 抓取仓库树 +
> mod_nikto / mod_wapp / mod_takeover / wappalyzer 源码片段），SiteLens 侧为本地库内实测。
> Wapiti：GPL-2.0 · Python（httpx/asyncio）· 1,860 stars · 最后推送 2026-08-19（持续维护，支持 Python 3.12–3.14）。
> 选它的原因：与 Nuclei（引擎）不同，Wapiti 是**真正的同形态对手**——同为 Python、爬取→检测→报告的整车。

## 一、能力面对比（按仓库代码枚举，非宣传口径）

### 1.1 模块广度 —— Wapiti 占优

实测模块清单（attack/ 目录 + attack/modules/passive/）：

| 类别 | Wapiti 模块 | SiteLens 对应 |
|---|---|---|
| 注入类 | sql / timesql / xss / permanentxss / exec / file / xxe / ldap / ssrf / crlf / redirect | dast.py 4 项（反射 XSS / 报错 SQLi / 重定向 / 目录遍历，只读探测） |
| 专项 CVE | log4shell / spring4shell | 情报关联覆盖（无专项请求） |
| 枚举类 | buster（目录）/ backup / htaccess / wp_enum / cms / network_device / printer | dir_scan / webshell_probe / 子域名 / FingerDir |
| 认证类 | brute_login_form | loginbrute（+验证码 OCR，双方都有爆破） |
| 被动检查 | cookie_flags / csp / http_headers / https_redirect / inconsistent_redirection / information_disclosure / stacktrace_disclosure / unsecure_password（9 个） | security.py 8 项安全头评分（口径不同：它逐项报，我们加权出 A+–F） |
| 指纹 | wapp（Wappalyzer fork） | 7 检测器 + 370 精编 + 2481 表达式 + Bundle |
| 其他 | nikto（Nikto 库全量）/ ssl / takeover / methods / csrf / htp | 2613 Nuclei 模板子集（部分能力重叠） |

**诚实口径：模块广度 Wapiti 明显占优（注入类深度 + csrf/xxe/takeover/专项 CVE 我们都没有）。**

### 1.2 执行模型 —— Wapiti 占优（但我们有意的）

- Wapiti 3.x 为 **httpx + asyncio 异步**并发（mod_nikto 等模块实测 import）；
- SiteLens 为 requests 同步 + 全局 0.4s 限速（≈2.5 req/s），是**合规红线（限速+UA 自报）的有意设计**，不是能力天花板。
- 与 Nuclei 对比文档同一结论：吞吐劣势是取舍，不是借口。

### 1.3 数据源对比（双方都是"运行时吃社区库"的架构）

| 数据 | Wapiti（实测来源） | SiteLens |
|---|---|---|
| 检测规则 | 内置 payload JSON；**Nikto db_tests CSV**（运行时拉 wapiti-scanner/nikto fork，本地缓存）；takeover_fingerprints.json | 35 自研 check + Nuclei 2,613 子集 + 插件热加载（data/plugins/*.json） |
| 指纹库 | Wappalyzer technologies JSON（自维护 fork wappalyzerfork） | 370 精编 + 2,481 Tscan 表达式 + FingerDir + service_fp 11,966 |
| 漏洞情报 | **无情报层**（finding 里用正则把 CVE/BID/OSVDB 编号转成参考链接） | 11,024 情报 + GHSA 2,918 + OSV 1,188 + KEV 1,695 + 微软公告 34,931；版本区间三级判定 |
| 结果资产 | 无状态（报告文件） | PostgreSQL：scans / scan_techs / jobs；历史 diff、按技术反查、四格式导出 |
| 专项字典 | 自带（buster/backup/wp_enum 字典） | SecLists 精选（目录/子域名/口令） |

**结论：Wapiti 的"数据源"是检测规则库；SiteLens 是检测规则库 + 情报层 + 资产层三层。情报层是代差。**

## 二、优缺点（双向诚实）

### Wapiti 优于我们的
1. 注入验证深度：真 payload fuzzing vs 只读探测（结构性差距，见 §四）；
2. 检测面广：csrf / xxe / takeover / log4shell / spring4shell / network_device 等专项我们没有；
3. 异步吞吐；
4. CMS 专项体系（cms + wp_enum）比我们的 CMS_TECH_CHECKS 更完整。

### 我们优于它的（均为代码核实）
1. **漏洞情报层**：三级判定（confirmed/possible/excluded）+ KEV 红标 + 多源富集（GHSA/OSV/NVD 通道）——Wapiti 只有编号转链接；
2. **结果资产沉淀**：PostgreSQL 全量存储、历史 diff、按技术反查、四格式导出——它是无状态一次性报告；
3. **源码审计**：taint.py AST 污点分析（它没有 SAST）；
4. **合规内建**：SSRF 三层防护 + 限速 + UA 自报 + 授权门禁（它无内建约束）；
5. **验证码 OCR 的登录爆破** + 中文 Web 工作台（它是 CLI，另有无 GUI 的付费云端）。

## 三、借鉴路线（按投入产出比）

1. **P0 · 二次确认已做**（2026-09-05 上线）：命中重放复核 + 回显路径剔除——Wapiti/Nuclei 都没有的防误报机制，反向输出；
2. **P1 · 被动检查补齐**：cookie flags（HttpOnly/SameSite）与表单 CSRF token 存在性检测是**纯只读**可做，成本低；
3. **P1 · 请求聚类**：同路径多模板合并请求（Nuclei 对比文档已列，此处同样适用）；
4. **P2 · 子域接管指纹表**：takeover_fingerprints.json 思路 = DNS CNAME + 特征页匹配，只读可做；
5. **不学**：payload 注入注入类（与无害红线冲突，除非未来加"显式授权的注入模式"）；GPL 代码零拷贝（只借鉴思路，避免协议传染）。

## 四、对外口径（对外材料/介绍页通用）

> 在同栈（Python）同形态的 Wapiti 面前，SiteLens 的取舍是：以主动注入换取合规底线（限速、
> UA 自报、只读探测、授权门禁），以换取其没有的三层能力——技术指纹识别（2,851 指纹）、
> 漏洞情报三级判定（GHSA/OSV 多源 + 版本区间 + KEV 红标）、可检索的结果资产沉淀（PostgreSQL）。
> 防误报的二次确认机制为双向独有。

若被追问"注入能力不如 Wapiti"：如实回答是红线取舍；带版本区间的情报判定、指纹识别与
结果资产管理不受此限制，且我们的 Nuclei 模板通道保留了扩容空间。
