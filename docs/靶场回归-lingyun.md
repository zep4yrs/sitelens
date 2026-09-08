# 靶场校准回归报告 — lingyun.feng-qiao.top

- 日期：2026-09-08
- 靶场：lingyun.feng-qiao.top（xxCMS 演示站，PHP 5.6.40 EOL，移动云 CDN 双 A 记录）
- 授权：用户自有资产
- 方法：7 种扫描模式全量跑一轮（quick/standard/stealth/assets/deep/full/apocalypse），
  命中逐条与真实响应交叉验证（curl 复测），误报定性后修复引擎并复测收敛

## 模式阶梯（能力面随模式递增，符合设计）

| 模式 | 耗时 | verified | 构成 |
|---|---|---|---|
| quick | 0.1s | 0 | 仅首页被动指纹，验证引擎不运行 |
| standard | 1.6s | 0 | 爬取为主，验证引擎不运行 |
| stealth | 1.7s | 13 | 被动检测（cookie-attrs 12 + csrf-form 1） |
| assets | 81.6s | 0 | 发现面（子域/接管/目录），不跑验证 |
| deep | 25.7s | 1 | core 子集（admin-path） |
| full | 179s | 15 | core+passive+nuclei（php-detect） |
| apocalypse | 876→958s | **25（收敛后）** | 全模块+全量模板 |

## 校准三轮收敛（apocalypse 模式）

| 轮次 | verified | 变化 |
|---|---|---|
| v1（修前） | 39 | 15 条 404 回显类假阳性 |
| v2（status 保留修复） | 28 | −11：exposure 模板不再凭 404 回显路径子串命中 |
| v3（证据自解释） | 28 | 每条命中可看到"命中了哪个标记"，误报可定谳 |
| v4（status-only 拒收 + 回显剔 query 变体） | **25** | −3：wp-json/server-status 类状态码命中清零 |

### 修复的引擎缺陷（均为回归实测揪出）

1. **AND-merge 丢弃 status（反向"宁少报"）**：`status 200 AND 词` 的模板被
   转成仅词条件，Apache 404 页回显请求路径，路径子串（如 `.bash_history`）
   即命中 → 修复后 status 以 StatusAny 与词条件合取保留
2. **纯状态码组转换**：只看状态码不看内容的 check 在 CDN/WAF 环境任意
   路径即中（wp-json 404 命中 CVE、server-status 403 命中）→ 漏斗拒收，
   代价仅 −5 条（5412→5407）
3. **stripEcho 漏剔去 query 路径**：Apache 404 回显不含 query，完整路径
   剔除后残留路径关键词（wprm_recipe）→ 补剔 u.Path 变体

### 交叉验证方法

可疑命中逐条 curl 复测（浏览器 UA）：/.bash_history /.lesshst /graphql
/.env /robots.txt /storage/oauth-private.key 等全部返回真实 404
（"The requested URL … was not found"），证明 v1 的 exposure 命中均为
回显子串误报；/robots.txt 真实存在（200，含 xxCMS 目录 Disallow）。

## 收敛后 25 条命中定性

- **真实/合理 21 条**：cookie-attrs ×12（会话 Cookie 缺安全属性，靶场真实缺陷）、
  csrf-form ×1（登录表单无 token，真实缺陷）、admin-path ×1、php-detect ×1
  （X-Powered-By 头）、tech-detect ×3（nginx/php 头特征）、robots-txt ×2、
  exposed-file-upload-form ×1（首页确有 POST 表单，模板将其定级为 exposure 偏严）
- **上游模板质量误报 4 条**（引擎已可自证，Evidence 直接给出命中内容）：
  nuclei-acme-xss（词命中 `/html`——出现在任何 HTML 页）、
  nuclei-zenscrape-api-key / zenserp-api-key（正则 `[0-9a-z-]{36}` 命中首页
  任意长串）、nuclei-archibus-webcentral-panel（词命中 `login`——首页有登录表单）
  ——属 Nuclei 社区模板词表/正则过泛，非本引擎缺陷，可按模板 ID 黑名单过滤

## 结论

- 7 模式阶梯行为符合设计；验证型扫描器的可信度链路（软 404 基线 →
  回显剔除 → status 合取 → 二次确认 → 证据自解释）每一环都在回归中得到
  实测
- 误报率收敛：apocalypse 模式 verified 从 39 → 25，剩余 4 条误报全部
  可归因到具体模板并自证
- 已知边界：CDN 双 A 记录内容不一致会导致间歇性结论（admin-path 类
  路径时有时无）；时间盲注不覆盖表单字段
