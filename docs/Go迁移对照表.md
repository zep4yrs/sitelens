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
| 源码审计 16 规则 | scanner/audit.py | internal/audit | 正则改写为 RE2 兼容（去 lookahead） |
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
| 目录探测（dir_scan + 403 绕过） | 未迁移 | 移植 fingerdir 38 条 + 软404 基线（check 包已有同款机制可复用） |
| 子域名枚举（subdomain） | 未迁移 | Go 端 net.LookupHost + data/wordlists/subs_default.txt，工作量小 |
| 端口服务识别（service_probe） | 未迁移：依赖 PG 中 11966 条 service_fp 指纹 | 导出 service_fp 至 JSON 后移植 |
| WebShell 探测（webshell） | 未迁移：字典已在 data/wordlists/shell_default.txt | 移植为 checks 插件或独立模块，工作量小 |
| JS 攻击面（jsmap：SourceMap 泄露/bundle 端点） | 未迁移 | 正则级实现可行，Go 侧优先级中 |
| FingerDir 主动路径指纹（active_fp） | 未迁移：依赖 PG fingerdir 表 | 同 dir_scan 一并处理 |
| Nuclei 模板子集（2613 条 MoE 路由） | 未迁移：dump 中 nuclei JSON 未接入 Go check 引擎 | 复用 checks 插件 JSON 通道直接装载 |
| 情报自动更新守护（OSV/KEV 每 24h） | 未迁移：知识库当前为静态 dump | Go 定时任务 + tools/update_intel.py 产物重导出 |
| PostgreSQL 知识库/检索（trgm） | 设计性替代：Go 用内存索引 + 文件存储 | 不回迁；trgm 检索以相关度排序近似 |
| 敏感信息审计（weak_audit） | 部分迁移：登录爆破可用，页面敏感内容审计未迁移 | 并入 check 规则族 |

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
