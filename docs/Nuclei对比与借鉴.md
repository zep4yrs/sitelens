# SiteLens × Nuclei 对比分析与借鉴路线

> 注：本文成文于 Python 实现阶段，其中的实现细节描述对应 python 分支；
> 当前主干为 Go 版，功能现状以 docs/Go迁移对照表.md 为准。

> 结论基于 2026-09-05 对双方**实际代码**的核对（本项目 scanner/ 全部模块 + Nuclei 官方仓库），
> 数据量为当日库内实测值，非文档转抄。后续迭代以本文为口径依据。

## 一、定位关系：不是竞品，是上下游

- **Nuclei**（projectdiscovery/nuclei，MIT，Go）：漏洞检测**引擎**。YAML DSL 定义检测场景，
  社区模板库持续增长（官方宣传 7,000+；本项目 `data/nuclei` 快照仅 http 目录即 **11,306** 个 yaml），
  覆盖 HTTP/DNS/TCP/SSL/WHOIS/WebSocket/无头浏览器等协议。
- **SiteLens**：验证型 Web 漏洞扫描器**工作台**。串起「指纹识别 → 情报关联 → 模板验证 → 报告交付」，
  验证环节运行着 Nuclei 社区模板的适配子集（当前 2,613 条）。

一句话：**Nuclei 是引擎，我们是用引擎搭出来的整车；而且我们直接借了它的零件（模板）。**

## 二、代码级对比（以实现为准，不以宣传为准）

### 2.1 模板运行能力 —— Nuclei 压倒性

| | SiteLens | Nuclei |
|---|---|---|
| 可运行模板 | 2,613 条（`data/nuclei_checks.json`） | 模板库持续增长（官方宣传 7,000+，本地快照 http 目录 11,306） |
| 支持的模板类型 | **单 GET** + path 仅 `{{BaseURL}}` 后缀 + status/word matchers（`tools/import_nuclei.py:20` 明确跳过 DSL/payload/二进制/interactsh） | 全 DSL：多请求链、payload fuzz、extractor、OOB、headless、JS/Code |
| 执行模型 | 逐模板串行 GET（`scanner/checks.py:243 run_nuclei`），组间 OR / 组内 AND 子串匹配，软 404 基线 + 二次重放确认 | Go 高并发，默认 150 req/s，请求聚类 |
| 实际吞吐 | 全局限速 0.4s（≈2.5 req/s）+ 3 扫描信号量 | 默认 150 req/s |

**诚实口径：我们约 2.5 req/s vs 它默认 150 req/s，吞吐差约 60 倍；可运行的模板类型是它库里最简单的一类。**

#### 模板漏斗：11,306 → 2,613（为什么只有这些能跑）

对本地快照 `data/nuclei/http`（11,306 个 yaml）按特性统计（有重叠）：

| 被跳过的原因 | 涉及模板数 | 对应我们运行器缺的能力 |
|---|---|---|
| `dsl:` 表达式匹配器 | 3,543 | 表达式求值引擎 |
| `flow:` 多请求编排 | 1,101 | 多步骤请求状态机 |
| `payloads:` 模糊测试 | 689 | 注入/迭代引擎 |
| `interactsh` OOB 回连 | 543 | 外部回调服务器 |
| POST 等非 GET 方法 | 181 | 单 GET 之外的请求方法 |
| **实际转换入库** | **2,613** | 单 GET + 字面路径 + status/word 匹配 |

扩大模板覆盖率的路径 = 给 `run_nuclei` 逐个补上述能力，每补一项即可解锁对应类别，
其中「POST 支持」和「简单 DSL（比较运算符）」成本最低，OOB 成本最高（见 §三 P2）。

### 2.2 我们有、它没有的（代码核实）

| 能力 | 实现位置 | 说明 |
|---|---|---|
| 技术指纹识别 | `scanner/detectors/`（7 检测器多态）+ 370 自建 + 2,481 Tscan 表达式指纹 + BundleDetector | 一等公民能力；Nuclei 仅 `-as` 借 Wappalyzer 做技术检测 |
| 漏洞情报三级判定 | `scanner/vuln.py:36 match()`：confirmed / possible / excluded；KEV 集合常驻；微软公告组件别名 | Nuclei 无情报层 |
| 情报数据资产 | 库内实测：11,024 漏洞情报 / **1,323 条带 OSV 版本区间** / 1,695 KEV / 34,931 微软公告行 | 24h 守护线程自动更新已验证在跑 |
| 结果资产沉淀 | `scanner/db.py`（468 行）：scans / scan_techs / jobs；历史 diff、按技术检索、四格式导出 | Nuclei 无状态文件输出 |
| 源码审计 | `scanner/audit.py`（16 规则）+ `scanner/taint.py`（AST 同函数污点追踪） | Nuclei 无（教学级深度，见 §2.4） |
| 合规硬约束 | `scanner/target.py` SSRF 逐 IP 校验 + `scanner/fetcher.py` 全局限速/UA 自报 + 主动模块默认关 | Nuclei 无此类内建约束 |
| 界面 | Web 工作台 + 中文 + 批量/导出/情报库检索 | 纯 CLI（云端仪表盘另属商业产品） |

### 2.3 模板调度差异（我们的真差异点）

Nuclei 对目标无差别跑模板（用户手动 `-tags` 过滤）；SiteLens 先指纹识别再路由专项模板：
`scanner/checks.py:188 select_nuclei` 三路调度——① 指纹 tag 硬匹配置顶；② 其余按 256 维哈希
TF-IDF 余弦相似度排序（目标 title+指纹名 vs 模板 name+tags）；③ 无信号时文件游标轮转兜底。
同库不同命：**识别出 WordPress 才跑 WP 专项，不做无意义空跑。**

### 2.4 自知之明（被追问时的如实回答）

- `run_nuclei` 是 Nuclei 模板的**简易子集解释器**，不是引擎移植。payload 类、多请求链、
  需要 OOB 回连的模板跑不了——requests 栈的结构性边界。
- `dast.py`（109 行）：每参数 4 种无害探测，上限 15 参数；`taint.py`（100 行）：同函数
  赋值链追踪，不跨函数、不识别 sanitizer。**赢 Nuclei 是因为它没有，不是因为我们做得深。**
- MoE 路由是轻量实现（约 40 行），工程成立、有单测，勿按机器学习 MoE 的复杂度宣传。

## 三、借鉴路线（按投入产出比排序）

### P0 · extractor 机制 —— 打通「验证 → 情报」

Nuclei 模板的 extractors 可从响应**抽取内容**参与判定。我们 check 只有命中/不命中两个结果。
学法：check 支持 extractor（正则抽取版本号等），抽取值直接喂 `version_cmp.version_in()`
做区间判定。现在三级判定的版本号只来自指纹阶段（响应头/generator/脚本文件名），
check 侧抽取（如 phpinfo 页抽 PHP 版本、readme 抽 CMS 版本）会给「确认受影响」多一个来源。
**这是验证线和情报线的焊接点，投入产出比最高。**

### P1 · 四个直接可抄的工程件

1. **请求聚类**：`run_nuclei` 按 path 去重合并（大量模板探测同批路径），请求数显著下降——
   在不违反限速红线的前提下提速。
2. **断点续扫**：已有 `.nuclei_cursor` 游标与 jobs 表，补「中断 → 记录已完成 check → 续扫跳过」。
3. **SARIF 导出**：`exporters.py` 加一个 serializer，扫描结果可进 GitHub Security 面板，CI 故事讲圆。
4. **CLI 退出码约定**：`main.py` 命中即非零退出，方便流水线卡关。

### P2 · OOB 回连检测 —— 唯一真正的能力空白

盲 SSRF / 盲 SQLi 纯被动 GET 永远检不出。学 Interactsh 思路做最小自托管：
Flask 加 `/cb/<token>` 回连端点 + check 语法支持 `oob: true`。约束：回连地址须是目标可达的
公网域名（与 SSRF 校验拒内网自洽）。适合作为下一个大版本方向，不宜现做。

### P3 · 模板元数据治理

Nuclei 每条模板带 author/severity/reference/tags/description + 社区验证机制。
我们 42 条自研 check 仅有 id/severity/title/advice。补齐元数据（来源、日期、参考、验证状态），
报告更可信，也是未来扩大模板导入的前置条件。

### 不学清单

Go 重写（差异化不在性能）、盲目追 7,000+ 全量模板（子集已是运营项，随取随用）、
headless 浏览器（重、慢、与限速合规定位相悖）。性能做到「够用」（聚类 + 可配置速率）即停。

## 四、对外口径（对外材料/介绍页通用）

> SiteLens 兼容 Nuclei 社区模板子集（2,613 条，单请求验证类），通过指纹驱动的 MoE 式调度
> 提高命中路径效率；在此基础上补齐了 Nuclei 没有的三块：技术指纹识别（2,850+ 指纹）、
> 漏洞情报三级判定（OSV 版本区间 + KEV 在野利用红标）、本地可检索的结果资产
> （PostgreSQL 全量存储，支持历史 diff 与按技术检索）。

若被追问「payload 类模板能跑吗」：如实回答不能，requests 栈结构性边界，
带版本区间的情报判定与指纹识别不受此限制。
