# SiteLens 站点透视 — 网站技术指纹识别系统

> 输入网址，看穿技术栈：**2850+ 产品指纹 / 78 个类别 / 11024 条漏洞情报 / 22133 个 CVE 索引**，
> 外加安全响应头评分、批量扫描与 Wappalyzer 风格宽表导出。

![stack](https://img.shields.io/badge/Python-3.10+-blue)
![stack](https://img.shields.io/badge/Flask-3.x-green)
![stack](https://img.shields.io/badge/PostgreSQL-18-blue)

## 快速开始

```bash
# 1) 依赖（Python 3.10+，本地需有 PostgreSQL 12+）
pip install -r requirements.txt

# 2) 配置数据库连接（项目根 .env，SLENS_DB_* 键；也可用环境变量）
#    SLENS_DB_HOST / SLENS_DB_PORT / SLENS_DB_USER / SLENS_DB_PASSWORD / SLENS_DB_NAME=sitelens

# 3) 初始化知识库（首次运行自动建表并播种 78 类 + 369 条精编指纹）
python tools/import_assets.py     # 可选：额外导入漏洞收集包资产（见下）

# 4) 启动
python app.py                     # http://127.0.0.1:5000
python main.py scan https://example.com        # 命令行扫描
python main.py scan <url> --full               # 含全部主动模块（仅限授权目标）
python -m unittest discover -s tests -v        # 测试（18 项，离线可跑）
```

## 功能总览

| 模块 | 说明 |
| --- | --- |
| 技术指纹 | 6 个检测器多态运行：响应头 / Cookie / meta / DOM 选择器 / 脚本 / TscanPlus 表达式 |
| 版本识别 | 响应头、generator、脚本文件名中的版本号正则捕获（如 nginx/1.24.0） |
| 漏洞情报 | 识别结果关联 11024 条漏洞情报（afrog/xray/TscanPlus POC 元数据）+ 22133 个微软公告 CVE |
| 安全评分 | 8 项安全响应头加权评分，A+–F 等级 + 中文修复建议 |
| 深度爬取 | 同域浅爬（BFS ≤4 页）合并证据提高检出率 |
| 批量/导出 | 批量 ≤50 站点；导出 JSON / 明细 CSV / 宽表 CSV（每类别一列，` ; ` 分隔） |
| 主动模块 | 目录探测（软404 基线 + 403 绕过可选）、子域名枚举、端口服务识别、主动路径指纹、登录爆破、WebShell 探测 —— **默认关闭，仅限授权目标** |
| JS 攻击面 | SourceMap 泄露检测 + bundle 内 API 端点枚举 |
| 认证扫描 | Cookie 会话注入，覆盖登录后攻击面 |
| 网络层检测 | TLS 证书过期/自签名/旧协议 + SPF/DMARC/MX 邮件安全 |
| 源码审计 | 上传源码/zip，16 规则静态审计 + Python 污点数据流分析（TAINT） |
| 情报自动更新 | 启动守护线程每 24h 拉 OSV 区间与 CISA KEV 在野利用清单（SLENS_AUTO_UPDATE=0 关闭） |
| MoE 式模板路由 | tag 联动置顶 → 语义向量排序 → 轮转游标，2613 模板长期全覆盖 |
| 检索 | 「哪些站用了某技术」历史检索；漏洞情报 trgm 模糊检索 |

## 架构

```
web/                    手写前端（零构建）：展示页/工作台/批量/历史/API 文档
app.py                  Flask：页面路由 + REST API + 异步扫描任务(线程池信号量)
main.py                 CLI 入口
scanner/
  target.py             ScanTarget + TargetValidator（SSRF 防护：协议白名单/
                        内网·环回·保留地址拒绝 + DNS 解析校验）
  fetcher.py            requests 封装：全局限速、超时重试、轻量 GET、二进制抓取
  evidence.py           BeautifulSoup 证据解析（meta/脚本/DOM 选择器命中）
  crawler.py            同域浅爬取
  detectors/            继承体系：BaseDetector → Header/Cookie/Meta/Html/Script
                        + TscanDetector（表达式指纹引擎，短词边界保护）
  engine.py             编排：校验→采集→解析→爬取→检测→安全评分→漏洞关联→模块
  vuln.py               漏洞情报匹配（短语级产品匹配防泛词误报 + 微软公告别名表）
  security.py           安全响应头评分
  modules.py            可选主动模块（默认关闭）
  embedding.py          字符 3-gram 哈希 TF-IDF 向量（离线语义检索辅助）
  registry.py           指纹注册表（校验 + 内置库播种）
  db.py                 PostgreSQL：知识库/历史(scan_techs 明细表)/任务 三类存储
  exporters.py          JSON / 明细 CSV / 宽表 CSV / 漏洞 CSV
tools/import_assets.py  资产导入管线（见 docs/开发文档.md 的溯源表）
tools/jwt_check.py 占位  离线 JWT 字典校验思路见文档
tests/                  18 项单元测试（mock 网络，离线可跑）
```

## 面向对象设计落点

| 考核点 | 实现 |
| --- | --- |
| 封装 | 全部实体（`Technology/ScanTarget/PageEvidence/ScanResult/SecurityReport`）私有属性 + property；`add_evidence` 内控置信度成长 |
| 继承 | `BaseDetector(ABC)` → 5 个证据源子类；`_Tx` 复用 |
| 多态 | 引擎对检测器列表统一 `detect(evidence, signals)` 调用，新增检测器零改动 |
| 组合 | `ScannerEngine` 组合 Fetcher/Crawler/检测器组/Registry/VulnMatcher；`Fetcher` 组合 `RateLimiter` |
| 扩展性 | 指纹是数据不是代码（PG 表），加指纹不改引擎；自定义指纹即插入 `technologies` 表 |

## 合规边界（重要）

- 仅 http/https 目标；解析到环回/私有/保留地址直接拒绝（SSRF 防护）；
- 请求全局限速 + UA 自报家门（`SiteLens/1.0`）；
- 漏洞情报只做**名称/版本关联提示**，POC 攻击载荷不落盘、不执行；
- 主动模块默认关闭；弱口令/WebShell 字典仅存档于 `data/asset-extras/`，**未接入任何功能**；
- 请仅扫描自有或已授权的目标，遵守对方 robots 与服务条款。

详细设计、数据库 schema、资产溯源表与 pgvector 迁移 SQL 见 `docs/开发文档.md`。

> API 鉴权：设置环境变量 `SLENS_API_TOKEN` 后，所有 /api/* 请求需携带 `X-Token` 头。
