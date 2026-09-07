# SiteLens 站点透视 — 网站技术指纹识别与漏洞关联系统（Go 版）

> 输入网址，看穿技术栈：**370 条精编指纹 / 72 个类别 / 11024 条漏洞情报 / 34931 个微软公告 CVE / 1695 条 KEV 在野利用**，
> 外加参数级 DAST 主动探测、安全响应头评分、源码审计、登录爆破、批量扫描与 Wappalyzer 风格宽表导出。
> **单二进制交付，零外部依赖（不再需要 PostgreSQL）。**

![stack](https://img.shields.io/badge/Go-1.26-blue)
![stack](https://img.shields.io/badge/frontend-零构建-lightgrey)

## 快速开始

```bash
# 构建（或直接使用仓库内 sitelens.exe）
go build -o sitelens.exe ./cmd/sitelens

# 启动 Web 服务（默认 127.0.0.1:5000；旧 Python 服务若占用端口请在配置中换端口）
./sitelens.exe serve

# 命令行全流水线扫描（JSON 输出到 stdout，摘要到 stderr）
./sitelens.exe scan https://example.com

# 使用自定义配置（全部阈值可选，见「配置」节）
./sitelens.exe -config .sitelens.yml serve

# Docker（多阶段构建，distroless 静态镜像；扫描目标勿写 localhost）
docker build -t sitelens .
docker run --rm -p 5000:5000 -v sitelens-state:/app/data/state sitelens

# 测试（全部离线可跑）
go test ./...
```

数据文件（自动降级：缺失时对应能力关闭，服务照常启动）：
- `data/go/technologies.json` 精编指纹规则
- `data/intel_dump.json.gz` 漏洞情报知识库
- `data/affected_ranges.json` 精选版本区间
- `data/wordlists/` 弱口令字典（登录爆破用，仅限授权目标）

## 功能总览

| 模块 | 说明 |
| --- | --- |
| 技术指纹 | 证据通道：响应头 / Cookie / meta / HTML 正则 / 脚本 src / 内联 JS；跨页合并去重，独立命中置信 +5 |
| 漏洞情报 | 三级判定：confirmed（版本落在区间）/ possible（同名无版本）/ excluded（区间外不输出）；KEV 红标；微软公告 CVE 关联 |
| 主动 DAST | 反射 XSS / 报错 SQLi（基线剔除误报）/ 时间盲注（双确认）/ 开放重定向 / 目录遍历；请求总量硬上限 |
| 安全评分 | 8 项安全响应头加权评分，A+–F 等级 + 中文修复建议 |
| 被动检测 | Cookie 安全属性缺失 + 登录表单 CSRF token 缺失（零额外请求） |
| 验证型 check | 41 条内置规则 + 用户插件（data/plugins/*.json 热加载）；CMS 指纹联动调度 |
| Nuclei 子集 | 社区模板按已识别技术 tag 挑选（上限可配，默认 300）+ 轮转游标长期全覆盖；YAML 直接装载（word/status/regex/dsl 安全子集，可运行模板 5412/11306） |
| 深度爬取 | 同域 BFS（robots.txt 遵循、页数/链接数/时长三重上限） |
| 登录爆破 | 宽容表单解析（id/placeholder 推断）+ 失败基线判定 + 命中即停；**必须勾选授权确认** |
| 源码审计 | 上传 zip/单文件，16 规则静态审计（zip-slip 防护、大小上限），内置演示样本 |
| 网络层检测 | TLS 证书过期/自签名/旧协议 + SPF/DMARC/MX 邮件安全 |
| 批量/导出 | 批量 ≤50 站点（worker 并发可配）；导出 JSON / 明细 CSV / 宽表 CSV（BOM，Excel 直开） |
| 认证扫描 | Cookie 会话注入（auth_cookie），覆盖登录后攻击面 |
| SSRF 防护 | 协议白名单 + 保留主机黑名单 + DNS 解析逐 IP 私网校验 + 重定向逐跳复检 |
| 检索 | 「哪些站用了某技术」历史检索；漏洞情报模糊检索（product/name/CVE 相关度排序） |

## 配置（.sitelens.yml，未设置的项回退默认值）

```yaml
scan:
  rate_interval_ms: 400      # 请求最小间隔（限速）
  timeout_sec: 15            # 单请求超时
  max_hops: 6                # 重定向跳数上限
  max_body_mb: 3             # 正文留存上限
  deep: true                 # 默认同域浅爬取
  resolve: true              # SSRF DNS 校验强度
  max_concurrent: 3          # 并发扫描任务数
checks:
  level: all                 # none | core | all
  plugin_dir: data/plugins   # 用户自定义 check 目录
  nuclei_cap: 300            # Nuclei 子集数量上限
  nuclei_dir: data/nuclei    # 模板库目录（目录不存在则自动跳过）
crawler:
  max_pages: 4
  respect_robots: true
  max_links_per_page: 80
  timeout_sec: 60
  headless: false             # 无头渲染（SPA 支持；需本机 Chrome/Chromium，缺失自动降级）
  headless_all_pages: false   # 渲染扩展到全部已爬页（默认仅首页）
  headless_timeout_sec: 20    # 单页渲染超时
dast:
  max_params: 24             # 参数探测上限
  time_blind: true           # 时间盲注（双确认）
  blind_threshold_ms: 3500
  sleep_seconds: 4
intel:
  dump_path: data/intel_dump.json.gz
  technologies_path: data/go/technologies.json
  search_limit: 40
netsec: { tls_timeout_sec: 8, mail_check: true }
loginbrute: { max_tries: 400, max_users: 8, max_passwords: 50, interval_ms: 150, max_concurrent: 2 }
audit: { max_archive_mb: 20, max_files: 800, max_file_kb: 512, max_findings_per_rule: 50 }
batch: { max_urls: 50, workers: 3 }
web:
  listen: 127.0.0.1:5000
  api_token: ""              # 非空则 /api/* 需 X-Token 头（也可用环境变量 SLENS_API_TOKEN）
  history_limit: 50
  history_cap: 200
store: { data_dir: data/state, max_records: 500 }
```

## API

全部端点见页面「API 文档」（/api-docs），与 Python 版契约一致：
`/api/version /api/stats /api/categories /api/scan /api/job/{id}[/cancel|/results]
/api/batch /api/history[/{id}] /api/export/{id}?fmt=json|csv|wide /api/diff
/api/vuln-search /api/verified /api/netsec /api/loginbrute /api/audit[/demo]
/api/captcha/capability`

## 架构

```
cmd/sitelens          CLI（scan / serve）
internal/server       内置 Web 服务：嵌入前端 + REST API + 作业调度
internal/engine       扫描编排：校验→采集→爬取→指纹→评分→check→被动→DAST→情报
internal/target       SSRF 安全校验（协议/保留主机/私网 IP/重定向逐跳）
internal/httpx        限速客户端：手动重定向 + Cookie 注入 + Set-Cookie 保真
internal/crawler      同域 BFS 爬取（robots.txt）
internal/htmlx        轻量 HTML 解析（title/链接/表单/meta/script）
internal/sitelens     指纹匹配引擎（预编译规则、多通道 AND/ANY 语义）
internal/checks       验证型 check（软404 基线/回显剔除/二次确认）+ 插件
internal/dast         参数级无害注入探测
internal/passive      被动安全检测
internal/security     安全响应头评分
internal/intel        漏洞情报知识库（三级判定 + KEV + 检索 + 统计）
internal/versioncmp   版本解析/比较/区间判定
internal/netsec       TLS/DNS 邮件安全
internal/loginbrute   登录爆破（授权闸 + 基线判定）
internal/audit        源码静态审计（16 规则）
internal/store        文件式历史存储 + 内存作业管理
internal/config       .sitelens.yml 全量阈值注册表
web/                  手写前端（零构建，go:embed 嵌入）
```

## 与 Python 版的关系

Python 全量实现保留在 `python` 分支（Flask + PostgreSQL + ddddocr 验证码 + 污点分析 +
目录探测/子域名/端口服务识别等主动模块）。Go 版为主干持续迭代，功能对照见
`docs/Go迁移对照表.md`。
