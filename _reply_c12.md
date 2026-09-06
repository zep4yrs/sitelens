@fengqiao(枫桥) 收到分工。以下是我作为**安全与一致性守门**本轮交付的三块：① 全仓库复审结论；② 「请求聚类+断点续扫」实现方案；③ OOB 自托管回连威胁建模（仅设计）。本轮不改代码、不开 PR，按约定把发现与方案回贴本 issue。

---

## 一、全仓库复审（延续重定向 SSRF / 初始化时序 / 字段一致性）

先确认基线：当前 `main` 全仓 40 个 .py 语法通过，`python3 -m unittest discover -s tests` 49 项全绿。上一轮修复（624ad9d）已实质收敛三个方向，本次复审多数遗留项归为「非阻断性、进后期单」，仅 1 项建议随 P0 焊接一起处理。

### A. 重定向 SSRF —— 已封严，遗留 2 条非阻断
- ✅ `_get_follow` 逐跳校验 + 6 跳上限已落地；`post_form`、robots、favicon、bundle/jsmap 全走 `_get_follow`，无直通 `allow_redirects=True` 的裸 GET。
- 🔸 **建议进后期单**：`fetcher.__to_evidence` 里 `resp.url.split("/")[2]` 取 host 属于「字符串猜测」而非 `urlparse`。当前被外层 `try/except` 兜住不致崩，但 ip 为空、IPv6 `[::1]:443` 会被错误拆解。**顺手改用 `urlparse(resp.url).hostname`**，属一行级加固。
- 🔸 **cookie 汇总范围**：`fetch()` 收集的是 `self.__session.cookies` 全量（会话会在多跳/多次抓取间累积）。因爬虫限 `same_site`、重定向仅放行公网 http/https，实际泄露面可控；但建议给 CookieDetector / 采集留「仅本 origin」白名单，进字段一致性治理。

### B. 初始化时序 —— 空库可用性已打通
- ✅ `ensure_schema` 的 `ALTER` 已移到 `CREATE` 之后；`cve_ms` 建表补齐；`match_cve_ms` 空表/无表静默跳过；`search_vulns` 无 pg_trgm 降级包含匹配——上一轮 2/4 号空库崩溃点确认闭环。
- 🔸 **一致性隐患（本轮唯一实质项，建议随 extractor 焊接一起收）**：`result.vulnerabilities` 由 `vuln.match()` 与 `vuln.match_cve_ms()` 两条路径合并，**两套 dict 字段集不同**：
  - `match()` 产出：`id/tech/version/src/name/product/cve/type/severity/severity_zh/ref/desc/verdict/affected/kev`
  - `match_cve_ms()` 产出：`tech/cve/title/component/severity/severity_zh/src/ref/type`
  - 前端与 report_html 渲染用 `name or title`、`type` 兜底，能兼容；但 `/api/history/detail`、导出 CSV、未来三级判定徽章都要对两套做分支。**建议在 VulnMatcher 加一个统一 `_normalize()` 出口**，把 `match_cve_ms` 结果映射成与 `match()` 同构的 key 集（补 `name=title`、`verdict=possible`、空 `version/affected`），这样 diff/导出/情报详情一处收敛。

### C. 字段一致性（verified / 模块命中 / extra）
- ✅ `/api/verified` 聚合查询的 `check/title/severity/url/evidence` 五键在 check、nuclei、jsmap、dast 各类命中里**均已携带**，上一轮缺 `evidence` 已补。
- 🔸 **遗留**：check 模块（run_checks）的命中**不带 `src` 键**，nuclei/js/dast 带。聚合页当前不渲染 src 所以不破，但结果 JSON 里 `src` 缺失会让「来源字段一致性」在导出/详情侧产生空洞。建议 run_checks 命中统一补 `"src": "checks"`（一行，随检测面补齐轮一并做）。
- 🔸 netsec / weak_audit / webshell / dir_scan 命中走 `extras`，schema 与 `verified` 异构（无 `check/url/evidence`），当前按各自面板渲染没问题，但**不建议把 extras 混入 verified**，保持现状即可，仅需在数据契约文档里写明分区。

### D. 其它顺带确认
- `/css /js` 静态路由 realpath 校验、`/api/audit` 200MB 上传 + 512MB 解压、zip 内路径 `is_relative_to` 防护均已就位。
- `TargetValidator` 的 `BLOCKED_HOSTS` 未含 `.onion/.i2p`，但 resolve 后走公网 IP 校验，Tails 类地址解析不上线即拒，实测无绕过路径；若要更严可在列表补 `.onion`（低优先级）。

**本轮结论：无 P0 级阻断项，可进入后期开发。** 1 项实质（B 的 vulnerabilities 字段收敛）+ 3 项顺手项（A、C）建议排进 glm-5.3-flash 的 P0 焊接或检测面补齐迭代。

---

## 二、请求聚类 + 断点续扫 实现方案（设计评审用）

> 目标：后期「请求提速」的红线内优化——不减少请求含义，只把同质请求合并去重、把可断点中断的扫描状态落盘，失败后从游标续扫。

### 1. 复用现有两张"身份"：`jobs` 表 + `.nuclei_cursor` 文件
现状里已有一处游标雏形：`data/.nuclei_cursor` 记录 Nuclei 模板轮转位。续扫不应另起炉灶，把「全扫描阶段进度」抽象成**统一游标**即可。

### 2. 阶段打点：把扫描切成可续扫的原子段
`ScannerEngine.scan` 现为一次性顺序流。建议加 `resume_from` 参数，将 scan 拆成**编号阶段**并落 `jobs.payload.cursor`：

| 阶段 | 内容 | 可续扫性 |
|---|---|---|
| P1 | 目标校验+首页采集+信号 | 天然幂等，从头即可 |
| P2 | 浅爬取各页 | **按 page_index 续**（页级断点） |
| P3 | 多态检测（多页×检测器） | 页×技术，页级断点即可（检测器纯内存） |
| P4 | checks 专项 | **按 CHECKS 下标续**（data/plugins 会改长度，用 check id 而非 index） |
| P5 | Nuclei 子集 | **直接复用 .nuclei_cursor 轮转位**（已是文件级游标） |
| P6 | 可选模块 | 模块内部自带进度，模块级断点即可 |

### 3. 去重粒度——两类聚类
- **URL 去重**（同参不同页）：同一 `(method, scheme://host+path, normalized_query)` 只发一次，爬到的子页与检测器/check 若要同一 URL 复用上次证据。落地：在 `Fetcher` 上加**进程内 LRU 响应缓存**（`{normalized_url: (expires, resp_dict)}`，TTL 建议 30s），单次扫描内命中即不再发请求——这是纯提速，不影响正确性。
- **请求聚类（工程线，仅设计）**：把「仅查静态/低价值目录」的 `dir_scan`/`webshell`/`active_fp` 请求按**同 path 前缀**聚成一批，用单连接 `keep-alive` + `HTTP/1.1` 串行发，减握手开销。此层需谨慎——**不能把不同目标/不同语义的请求合并成一次**（会破坏软404与二次确认的独立性）。建议**只对同 host、同目标下、判定只依赖 status/size/header 的探测类**做批量，XSS/SQLi 这类带 body 语义的保持逐发。

### 4. 断点续扫落盘与恢复契约
- **落盘点**：每完成一个原子段，`JobStore.update` 写 `jobs.payload = {"url", "options", "cursor": {"page": n, "checks": [已完成id], "nuclei_offset": x, "modules": [...]}}`，`status` 保持可识别态（如 `paused`）。
- **恢复**：`/api/scan` 接受 `resume_job=<id>`，读取 cursor 从 P2/P4 续跑；重跑 P1 校验目标 + 首次采集以保证 base 态新鲜，其余从 cursor 跳过已完成段。
- **约束（安全一致性）**：续扫重跑 P1 时**必须重新过 TargetValidator**（目标在断点期间可能被 DNS 重绑定为内网 IP），续扫不得绕过首段校验——这是续扫功能的 SSRF 底线，写进设计不变量。

### 5. 验收口径
- 提速：同配置全扫请求数期望下降 ≥25%（LRU 命中主导，供回归断言）。
- 续扫正确性：`中断→续扫` 的 `verified`/`technologies` 结果与一次性全扫**集合相等**（回归断言，可加 fixture）。
- 安全：续扫首段强制重新校验目标；跨进程不共享内存游标，全部以 jobs.payload 为准。

此方案评审通过后交 glm-5.3-flash 落地。

---

## 三、OOB 自托管回连 威胁建模（仅设计，不实现）

> 远期「盲 SSRF / 盲 SQLi」的 OOB 验证前提。红线先决：**不引入任何对外可滥用回连通道**。

### 1. 威胁面与前提自洽
OOB 的本质是：让目标应用在**我方可控端点**产生可观察的 DNS/HTTP 回连，从而证明盲注/盲 SSRF 成立。若回连端点公开且无鉴权，等于给攻击者免费提供了**开箱即用的 SSRF/反射放大器**——这与本项目「无害只读、授权测试」的红线冲突。故 OOB 通道**必须私有、短时、单向、鉴权**。

### 2. 回连端点形态（三种，能力递增）
| 能力 | 端点 | 需满足 |
|---|---|---|
| 最低 | 仅记录「到达即命中」 | HTTP 回调 `/oob/<nonce>` 只记 `(source_ip, query, ts)` |
| 标准 | 能区分哪条注入触发 | 请求体带 `nonce` 且 target 侧注入的 payload 内嵌同一 `nonce` |
| 最高 | DNS 级（盲 SSRF 常需 DNS 先于 HTTP） | 托管权威区 `oob.<私域>`，见第 4 节自洽论证 |

### 3. 滥用防护矩阵（对照 SSRF 校验自洽）
| 风险 | 缓解 | 与现有 TargetValidator 的关系 |
|---|---|---|
| 回连端点被外部扫描/爆破 | nonce 为高熵随机（≥128bit）、单次有效、TTL 5min | 非 URL 校验问题，属端内授权 |
| 攻击者把目标引去**别人**的回连端点 | 不跟随不可信 Host（payload 只填我方已知端点） | 与逐跳 SSRF 校验正交：校验是对「我方代发的请求」生效，OOB 是「目标主动外连」，我方不放行目标外连任意地址 |
| 目标本身被用于反射（回连目标 → 第三方） | 回连端只监听、不回拨；仅记录 | 自洽点：我方**从不**代目标发起指向回连端的请求，OOB 不扩展现有 SSRF 面 |
| nonce 复用/碰撞 | UUIDv4 + 会话绑定 | — |
| 日志含用户/口令回显 | 只记 IP + 时间 + nonce，**不回显 body** | — |

### 4. SSRF 校验自洽性论证（核心）
- 现引擎的 SSRF 防护管辖的是 **「扫描器 → 目标及其重定向」** 这段我方主动代发的链路，约束为公网、仅 http/https、逐跳校验。
- OOB 回连是 **「目标 → 我方监听端点」** 的反向链路。两者是**不同方向、不同责任主体**，不构成冲突：OOB 端点由我方独占持有与鉴权，`TargetValidator` 无需（也不该）对反向回连放行任意公网——因为触发 OOB 的是目标进程，而非扫描器代发。
- 风险并非 SSRF 校验被绕过，而是**新引入了一个面向外网的接收面**。故 OOB 端必须：私有网卡/防火墙白名单 → 不监听 0.0.0.0 → 高熵 nonce 单次有效 → 无回拨 → 日志最小化。合规上属「主动模块」，遵循「主动模块默认关」红线，需显式授权 + UI 勾选。

### 5. 交付边界
仅此设计；实现依赖 glm-5.3-flash 的能力评估，且**与现有的盲注入检测（报错型 SQLi/反射 XSS）共用授权确认流**，不新增默认攻击面。

---

## 给本轮的勾选与移交
- [x] 全仓库复审（无 P0，B 项字段收敛建议随 P0 焊接处理）
- [x] 请求聚类+断点续扫 实现方案（交 glm-5.3-flash 评审后落地）
- [x] OOB 威胁建模（设计交付）
- [ ] 请求聚类+续扫 由 glm-5.3-flash 实现
- [ ] 两个只读模块 / extractor 焊接 / match_cve_ms 风格收敛 由 glm-5.3-flash 实现
- [ ] 回归扩容 由 deepseek-v4-flash 承接

另建议把 B-C 的四项顺手加固单开 issue 分派，避免混入单次 PR 增加评审噪音。