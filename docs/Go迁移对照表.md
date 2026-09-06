# Go 迁移功能对照表（2026-09-07 夜间迁移完成时点）

> 目标：Go 主干全面替代 Python 版（python 分支）。本表逐项对照迁移状态，
> 「未迁移」项不隐瞒、不粉饰，均给出现状说明与建议去向。

## 迁移完成（Go 版可用）

| 功能 | Python 位置 | Go 位置 | 备注 |
| --- | --- | --- | --- |
| SSRF 安全校验 | scanner/target.py | internal/target | 比原版更严：显式非 http(s) 协议直接拒绝 |
| 限速 HTTP 客户端 | scanner/fetcher.py | internal/httpx | Set-Cookie 逐条保真，优于原版合并头启发式切分 |
| HTML 解析 | BeautifulSoup | internal/htmlx | 轻量索引扫描，够用且快；表单/密码框/id/placeholder 全捕获 |
| 指纹引擎（6 通道） | scanner/detectors/ | internal/sitelens | 修复导出形状 bug 后 370 条规则全量生效 |
| 漏洞情报三级判定 | scanner/vuln.py | internal/intel | confirmed/possible/excluded + KEV + CVSS |
| 微软公告关联 | scanner/vuln.py | internal/intel | MatchCVEMs |
| 验证型 check 41 条 | scanner/checks.py | internal/checks | 软404 基线/回显剔除/二次确认全保留 |
| check 用户插件 | — | internal/checks | data/plugins/*.json 热加载（规则用户化） |
| 参数级 DAST | scanner/dast.py | internal/dast | 新增基线剔除 + 盲注双确认 + 阈值全配置化 |
| 被动检测 | scanner/passive.py | internal/passive | 复杂的合并头切分被 Set-Cookie 保真天然替代 |
| 安全响应头评分 | scanner/security.py | internal/security | 8 头加权，分值/等级对齐 |
| 同域浅爬取 | scanner/crawler.py | internal/crawler | 新增 robots.txt Disallow 解析与阶段超时 |
| 版本比较 | scanner/version_cmp.py | internal/versioncmp | Parse/Cmp/VersionIn/ExtractVersion |
| TLS/DNS 网络层 | scanner/netsec.py | internal/netsec | CheckTLS/CheckDNSMail/OrgDomain |
| 登录爆破 | scanner/loginbrute.py | internal/loginbrute | 宽容表单解析 + 基线判定 + 授权闸 |
| 目录探测（含 403 绕过） | scanner/modules.py | internal/modules | 软404 基线剔除 + 伪造来源头绕过一次 |
| 子域名枚举 | scanner/modules.py | internal/modules | DNS 并发解析、解析器可注入便于离线测试 |
| WebShell 探测 | scanner/modules.py | internal/modules | 200 且非空正文判定 |
| FingerDir 主动指纹 | scanner/modules.py | internal/modules | 38 条精编 spec 全条件判定（请求上限可配） |
| 端口服务识别 | scanner/modules.py | internal/modules | 11966 条 banner 指纹；TLS 证书自实现校验（不跳过校验） |
| Nuclei 模板子集 | tools/import_nuclei.py + scanner/checks.py | internal/nuclei | YAML 直接装载（漏斗对齐原版，抽样通过率约 10% vs 原版 23%，头匹配/dsl 未迁移）；两路调度，语义向量路由以轮转游标近似 |
| 情报检索（trgm） | scanner/db.py | internal/intel.Search | product/name/CVE 相关度排序近似 |
| JS 攻击面（jsmap） | scanner/jsmap.py | internal/jsmap | SourceMap 泄露 + API 端点枚举 |
| 基础认证弱口令 | scanner/modules.py | internal/loginbrute | 401 路径 Basic 字典尝试 |
| 情报自动更新（KEV） | scanner/intel_update.py | internal/intel + server 守护 | CISA 公开源，缓存 data/state/kev_extra.json，间隔可配 |
| 源码审计 16 规则 | scanner/audit.py | internal/audit | 正则改写为 RE2 兼容（去 lookahead） |
| 阈值配置体系 | — | internal/config | 全项目超时/并发/上限统一 .sitelens.yml 注册表（Python 版无此集中度） |
| Web 服务 20 端点 | app.py (Flask) | internal/server | 契约逐键对齐，前端零改动；嵌入 web/ 单二进制 |
| 历史存储 | scanner/db.py (PG) | internal/store | 改文件式 JSON：单二进制零依赖；字段契约对齐 |
| 作业管理 | scanner/db.py (PG) | internal/store | 内存态（作业不跨重启，Python 版跨重启但无实际消费方） |
| 批量扫描 | app.py | internal/server | worker 并发可配、逐行日志、取消跳过 |
| CSV 导出 | scanner/exporters.py | internal/server | 明细/宽表 + BOM，中文表头 |
| CLI | main.py | cmd/sitelens | scan 全流水线 JSON 输出 + serve |
| 历史差异对比 | app.py /api/diff | internal/server | added/removed/version_changed |

## 未迁移（Python 分支独有，诚实差距清单）

| 功能 | 现状 | 建议去向 |
| --- | --- | --- |
| ddddocr 验证码识别（digits/calc/click） | 未迁移：要求验证码的表单明确报错拒绝，不静默瞎打 | Go 侧接 onnxruntime 或保留 Python 分支专责此项 |
| 源码审计污点分析（TAINT 数据流） | 未迁移：16 条规则静态匹配已可用 | Go 实现轻量 AST 污点（py 文本级先行） |
| PostgreSQL 知识库/检索（trgm） | 设计性替代：Go 用内存索引 + 文件存储 | 不回迁；trgm 检索以相关度排序近似 |
| 敏感信息审计（weak_audit 表单部分） | 部分迁移：Basic 认证已入引擎；表单弱口令由独立登录爆破端点承载（宽容解析优于原版常见字段枚举） | 保持现状 |
## 迁移中发现并修复的原版问题

1. **指纹库形状 bug**：370 条精编指纹中 194 条 html 通道被导出成 `{dom,html}`
   对象，Python 版靠 BeautifulSoup 通道掩盖了该问题；Go 加载器最初整体丢弃
   这些规则（识别率骤降），已通过兼容双形状加载修复并顺带恢复嵌套 dom 数据。
2. **协议校验绕过**：`ftp://x` 类目标被盲补 `https://` 前缀后解析为
   `https://ftp`（主机名 ftp）放行；Go 版改为显式协议白名单拒绝。
3. **internal/sitelens 包曾整体未入库**：.gitignore 裸写的 `sitelens` 二进制
   规则误伤了同名 Go 包目录，已改根锚定 `/sitelens` 并补录。

## 安全扫描（Mimosa normal，2026-09-07）

- findings: 0；依赖离线告警：0 匹配（唯一依赖 gopkg.in/yaml.v3 v3.0.1 无已知漏洞，已是最新版）
- 封印：sha256:8455ffba67b9b786380073a96e579340f41bb12cf7d1594fa6f262510d2e4881
- go vet 全绿；12 个包测试全绿

## 性能快照（i7-14650HX，go test -bench 实测，见 internal/engine/bench_test.go）

- 单页指纹匹配（370 规则全量）：5.3ms/页（字面量门控优化前 13.6ms，2.6x）
- 全流水线单站扫描（校验→采集→爬取→指纹→评分→被动→情报）：5.9ms（本机 httptest）
- 8 路并发全流水线：14.3ms/轮，堆常驻 ~2.4MB
- 情报关联（三级判定）：12.8µs/次
- 知识库加载：11024 条情报 + 34931 CVE + 1695 KEV 冷启动 < 1s（gzip JSON）
- 真实自扫描冒烟（HTTP 全链路含限速关闭）：0.44s/站
