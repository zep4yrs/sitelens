# CP-04 基准评测体系（benchmark/）

> 对应《竞品对标与追赶方案》**G01（基准评测体系缺失）**与 **G02（覆盖率口径不清）**，5.2.x 路线图条目 **CP-04**。
> 指标定义、季度复评流程、与 G01/G02 的对应关系见 **[docs/基准评测-5.2.md](../docs/基准评测-5.2.md)**；本文件是执行手册。

先有数字再谈对标：本目录把「冻结版本 + 固定靶场 + 人工标注 + 可重复判分」固化成脚本，任何对外引用的召回/误报数字都必须能由这里的产物复现。

## 1. 目录结构

| 路径 | 作用 |
|---|---|
| `README.md` | 本执行手册 |
| `run.ps1` | Windows 批量执行器（PowerShell 5.1+/7，零第三方依赖） |
| `run.sh` | Linux/macOS/Git Bash 批量执行器（JSON 清单需要 node） |
| `score.mjs` | 评分器（Node ≥18，零第三方依赖）；`--selftest` 为内置自检 |
| `coverage-catalog.json` | 覆盖率口径目录：漏洞类型 → OWASP Top10 / CNVD 映射 + 文本归差别名 |
| `profiles/{fast,standard,deep}.yml` | 三档冻结配置（限速档位固定 polite，保证可复现） |
| `targets/*.sample.json` | 目标清单样例（OWASP Benchmark / 教学靶场矩阵 / 真实站点盲测模板） |
| `ground-truth/TEMPLATE.ground-truth.json` | 标注模板 |
| `fixtures/` | 评分器自检夹具（**固定数据，勿改**；改则同步改 `score.mjs` 断言） |
| `out/` | 评测产物（已在 `.gitignore` 忽略，可随时重建） |

## 2. 前置条件

1. **被测程序**：构建或取得 `sitelens` 可执行文件（仓库根 `sitelens.exe` / `bin/` / `dist/` / PATH 均可自动发现）：
   ```bash
   go build -o sitelens.exe ./cmd/sitelens   # Windows
   go build -o sitelens ./cmd/sitelens       # Linux/macOS
   ./sitelens.exe -version                   # 版本会写进 run-meta.json
   ```
2. **Node ≥18**：仅 `score.mjs` 与 JSON 目标清单解析需要；`run.ps1` 本身不需要 node。
3. **靶场**：见 §8；本机/内网靶场已在 profile 中设置 `target.allow_private: true`。
4. **授权**：只评测已获得书面授权的目标（真实站点盲测见 §9）。`gov.cn` 不参评。

先验证评分器本身可用（CI 可加为门禁，本仓库不改 `.cnb.yml`）：

```bash
node benchmark/score.mjs --selftest
# [selftest] ... P=0.8000 R=0.6667 F1=0.7273
# SELFTEST PASS（36 条断言）
```

## 3. 快速开始（3 步）

```powershell
# 1) 准备目标清单（复制样例，按本地靶场端口/路径修改）
Copy-Item benchmark/targets/lab-matrix.sample.json benchmark/targets/lab-matrix.json

# 2) 批量扫描（产物：benchmark/out/<suite>-<mode>-<时间戳>/）
powershell -ExecutionPolicy Bypass -File benchmark/run.ps1 `
    -Targets benchmark/targets/lab-matrix.json `
    -Mode standard
# 可选 -Truth <ground-truth.json>：跑完自动调用 score.mjs 评分（写入 <out>/score/）

# 3) 标注完成后评分（也可由上一步 -Truth 自动执行）
node benchmark/score.mjs `
    --raw benchmark/out/lab-matrix-standard-20261101-120000/raw `
    --truth benchmark/ground-truth/lab-matrix.ground-truth.json `
    --out benchmark/out/lab-matrix-standard-20261101-120000/score
```

Linux/macOS 用 `bash benchmark/run.sh --targets ... --mode standard`（参数同 §5.2）。

## 4. 目标清单

### 4.1 JSON（推荐）

```json
{
  "suite": "lab-matrix",
  "version": "2026Q4",
  "targets": [
    { "id": "dvwa-sqli-low", "url": "http://127.0.0.1:8081/vulnerabilities/sqli/?id=1", "tags": ["dvwa", "sqli"] },
    { "id": "dvwa-csrf",     "url": "http://127.0.0.1:8081/vulnerabilities/csrf/",       "tags": ["dvwa", "csrf"] }
  ]
}
```

规则：
- `id` 唯一，且是 raw 结果文件名（`raw/<id>.json`）——ground-truth 必须用同一个 id 对齐；
- `url` 原样作为 `sitelens scan <url>` 的参数（一个 URL = 一次扫描 = 一个用例）；
- `suite` 用于产物目录命名与报告标题；`version` 记录靶场/样本集版本（**必须冻结**）。

### 4.2 纯文本

```
# 注释行
http://127.0.0.1:8081/vulnerabilities/sqli/?id=1
dvwa-csrf http://127.0.0.1:8081/vulnerabilities/csrf/
```

每行 `url` 或 `id url`；无 id 时自动生成 `t0001...`；URL 不能含空格。

### 4.3 OWASP Benchmark 完整清单

OWASP Benchmark 官方发布包含 `expectedresults-*.csv`（列：`test name, category, real vulnerability, CWE, ...`）。按 CWE 映射到本仓库目录生成 `targets` 与初始 ground-truth（**生成后必须人工抽检 ≥20%**）：

```powershell
# 思路示意（按实际 CSV 列名调整；CWE→目录 type 列表见 §7 或 catalog）
$cwe2type = @{
  '89' = 'sql_injection'; '79' = 'xss'; '22' = 'path_traversal'; '78' = 'command_injection';
  '90' = 'ldap_injection'; '643' = 'xpath_injection'; '327' = 'weak_crypto';
  '328' = 'weak_hash'; '330' = 'weak_random'; '501' = 'trust_boundary'; '614' = 'cookie_flags'
}
$rows = Import-Csv .\expectedresults-1.2.csv
$targets = @(); $truth = @()
$i = 0
foreach ($r in $rows) {
  $i++
  $id = 'benchmark-{0:d5}' -f $i
  $targets += [ordered]@{ id = $id; url = "http://127.0.0.1:8080/benchmark/$($r.'test name')"; tags = @($r.category) }
  $expected = @()
  if ($r.'real vulnerability' -eq 'true' -and $cwe2type[$r.CWE]) {
    $expected += [ordered]@{ type = $cwe2type[$r.CWE]; note = "CWE-$($r.CWE) $($r.category)" }
  }
  $truth += [ordered]@{ id = $id; url = "http://127.0.0.1:8080/benchmark/$($r.'test name')"; expected = $expected }
}
@{ suite = 'owasp-benchmark'; version = 'v1.2'; targets = $targets } | ConvertTo-Json -Depth 5 | Set-Content targets\owasp-benchmark.json
@{ suite = 'owasp-benchmark'; version = 'v1.2'; frozen = @{}; targets = $truth }     | ConvertTo-Json -Depth 5 | Set-Content ground-truth\owasp-benchmark.ground-truth.json
```

URL 路径取决于本地部署（Tomcat 上下文、端口）；部署方式见 §8。WAVSEP 同理，按其 `testcases` 清单建 target、按用例类型建 expected。

## 5. 批量扫描

### 5.1 `run.ps1`（Windows 主力）

| 参数 | 说明 |
|---|---|
| `-Targets <file>` | **必填**：目标清单（§4.1/4.2） |
| `-Out <dir>` | 输出目录（默认 `benchmark/out/<suite>-<mode>-<时间戳>`） |
| `-Mode fast\|standard\|deep` | 扫描档位，对应 `profiles/<mode>.yml`（默认 standard） |
| `-Sitelens <path>` | 可执行文件（默认自动发现） |
| `-Config <file>` | 自定义配置，覆盖 `-Mode` profile（冻结口径请固定并记录哈希） |
| `-Truth <file>` | 给出则跑完自动调用 `score.mjs` 评分 |
| `-TimeoutSec <n>` | 单目标硬超时秒数（超时杀进程并记 `exit=124`） |
| `-Limit <n>` | 只跑前 n 个（冒烟） |
| `-Resume` | 跳过已有 `raw/<id>.json`（中断续跑） |
| `-DryRun` | 只打印将执行的命令，便于核对 |

执行时先用 `"$sitelens" -config <profile> scan <url>` 逐条运行，stdout→`raw/<id>.json`、stderr→`raw/<id>.log`；同时写 `run-meta.json`（见 §10）与 `summary.csv`（执行台账）。

### 5.2 `run.sh`（Linux/macOS/Git Bash）

参数与 `run.ps1` 一一对应：`--targets/--out/--mode/--sitelens/--config/--truth/--timeout/--limit/--resume/--dry-run`。
`--timeout` 依赖 coreutils `timeout`（macOS 可用 `brew install coreutils` 的 `gtimeout` 或省略该参数）。

### 5.3 运行档位（profiles）

| 档位 | 爬取 | checks | 探测预算 | 用途 |
|---|---|---|---|---|
| `fast` | deep=false，20 页 | core | DAST 每类 ≤3 | 冒烟/回归，**不可**作为对外口径 |
| `standard` | deep=true，40 页 | core | 默认 | 对外基线/季度复评 |
| `deep` | deep=true，80 页 | all | 默认 | 盲测/争议用例复现（耗时显著更高） |

三档都固定 `rate_mode: polite`（固定请求间隔），否则自适应限速会让同一用例两次运行流量不同、结果不可复现。需要自定义配置时用 `-Config`，其 SHA256 会写进 `run-meta.json`。

### 5.4 产物结构

```
out/<suite>-<mode>-<时间戳>/
├── run-meta.json          # 冻结元数据：版本/配置哈希/目标清单哈希/时间/主机
├── summary.csv            # 执行台账：target_id,url,exit_code,duration_ms,verified,vulnerabilities,error
├── raw/
│   ├── <id>.json          # sitelens scan 原始 JSON（评分器唯一输入）
│   └── <id>.log           # stderr（WAF/错误原因）
└── score/                 # 评分产物（-Truth 自动评分或手动 score.mjs 时生成）
    ├── summary.md         # 指标 + 类型/用例明细 + FN/FP 清单
    └── summary.csv        # 逐用例计分 + TOTAL 行
```

`summary.csv`（执行台账）与 `score/summary.csv`（计分结果）是两个不同口径的文件，不要混用；`run.ps1 -Truth` / `run.sh --truth` 自动评分固定写入 `<out>/score/`。

`exit_code=124` 表示超时被杀；其它非 0 见对应 `.log`。有失败目标时执行器退出码为 1——**归档前处理**（重跑该目标或在对应用例上显式标注 `missing`），不要手改 raw。

## 6. 标注（ground truth）

模型：每个 target 一个 `expected[]` 期望漏洞类型集合；**空数组 = 安全用例**（出现任何目录内类型检出即记误报用例）。

```json
{
  "id": "dvwa-sqli-low",
  "url": "http://127.0.0.1:8081/vulnerabilities/sqli/?id=1",
  "expected": [{ "type": "sql_injection", "note": "参数 id；报错/时间差分均可接受" }]
}
```

规则：
1. `type` 必须存在于 `coverage-catalog.json`（否则评分器直接报错，防止口径漂移）；
2. 同一 target 同一 `type` 只标注一次；多实例请拆成多个 target id；
3. 判定依据必须可复现：请求 + 响应片段/截图/证据位置，写进 `note` 或独立标注表；
4. 可选 `match[]` 给该用例追加匹配别名（目录别名覆盖不到的写法用），例如 `{"type":"path_traversal","match":["fi 参数","include.php"]}`；匹配前同样做小写去符号归一；
5. **双人独立标注**，分歧由第三人/评审会仲裁；标注人先标注、后看扫描结果（或双盲），禁止照抄 raw；
6. 模板见 [`ground-truth/TEMPLATE.ground-truth.json`](ground-truth/TEMPLATE.ground-truth.json)。

## 7. 评分（score.mjs）

```bash
node benchmark/score.mjs --raw <out>/raw --truth <ground-truth.json> --out <out> [--catalog <file>] [--suite <name>]
node benchmark/score.mjs --selftest
```

| 参数 | 说明 |
|---|---|
| `--raw <dir>` | 必填：`raw/` 目录 |
| `--truth <file>` | 必填：ground truth |
| `--out <dir>` | 输出目录（默认 `<raw>/../out`） |
| `--catalog <file>` | 覆盖目录（默认 `coverage-catalog.json`；ground-truth 也可用 `"catalog"` 字段指定） |
| `--suite <name>` | 覆盖报告 suite 名 |
| `--quiet` | 只输出结果路径 |
| `--selftest` | 内置夹具自检（CI 门禁；通过 exit 0） |

口径速查（完整定义见 [docs/基准评测-5.2.md](../docs/基准评测-5.2.md)）：

| 指标 | 定义 |
|---|---|
| TP / FP / FN | 命中的期望条目 / 不在期望集合的检出类型 / 未命中的期望条目 |
| Precision / Recall / F1 | `TP/(TP+FP)`、`TP/(TP+FN)`、`2TP/(2TP+FP+FN)`（分母为 0 记 0） |
| 期望类型覆盖率 | TP 覆盖的类型数 / 期望类型总数（套件内口径） |
| 目录类型覆盖率（G02） | TP 覆盖的类型数 / 目录类型总数（**G02 的 ≥80% 口径**） |
| 安全用例误报率 | 有检出的安全用例数 / 安全用例总数 |
| `missing_raw` / `invalid_raw` | 没有 raw / raw 解析失败（对应期望条目记 FN） |
| `out_of_catalog` | 映射不到目录类型的 finding（只报告，**不计 FP**） |

输出：
- `summary.md`：汇总指标、类型明细、逐用例明细、FN/FP 明细、口径说明；
- `summary.csv`：逐用例 `target_id,url,expected_count,detected_count,tp,fp,fn,status,duration_s` + TOTAL 行。

`--out` 默认 `<raw>/../out`；为避免覆盖执行台账（`run.ps1|run.sh` 产出的 `summary.csv`），手动评分时请写到 `<out>/score`（或 runner 自动写入 `<out>/score/`）。

**CI 接入（建议）**：评分器自检是纯离线、零依赖、秒级的门禁，可加进 CI（本任务不改 `.cnb.yml`，由 CI 维护者审批后追加）：

```yaml
# .cnb.yml（示例，未在此仓库启用）
- name: benchmark scorer selftest
  script: node benchmark/score.mjs --selftest
```

退出码：0 成功（含 selftest 通过）；1 参数/输入/计分失败。

解读建议：小样本（<100 用例）时 P/R 的置信区间很宽，对外引用需附用例数与置信说明；`out_of_catalog` 多说明目录/归一需维护，不等于"没检出"；安全用例太少会让误报率失真。

## 8. 靶场矩阵

| 靶场 | 用途 | 典型部署（本机，示例端口） | 备注 |
|---|---|---|---|
| OWASP Benchmark | 召回/误报基准（约 2,740 用例） | `docker run -p 8080:8080 owasp/benchmark` | 每个 testcase 一个 URL；按 `expectedresults-*.csv` 建清单（§4.3） |
| WAVSEP | Web 扫描器评测 | Tomcat 部署官方 war，`http://127.0.0.1:8089/wavsep/` | 按其清单逐用例建 target |
| DVWA | 认证态 SQLi/XSS/上传/LFI/CSRF | `docker run -p 8081:80 vulnerables/web-dvwa` | 先初始化数据库并登录；认证态扫描需 `auth`/`login` 配置（不在本目录范围内） |
| pikachu | 中文综合靶场 | 本地 PHP/Apache 或社区镜像 `-p 8082:80` | 中文场景的标题/告警归一验证 |
| sqli-labs | SQL 注入深度 | `-p 8083:80` 社区镜像 | Less-1…Less-65 逐关建 target |
| upload-labs | 文件上传绕过 | `-p 8084:80` 社区镜像 | Pass-01…Pass-21 |
| xsslabs | XSS 场景 | `-p 8085:80` 社区镜像 | level1…levelN |
| bWAPP | 综合漏洞类型 | `-p 8086:80` 社区镜像 | 需初始化 DB |
| Juice Shop | SPA/API/业务逻辑 | `docker run -p 3000:3000 bkimminich/juice-shop` | 需 `crawler.headless: true` 才能测 SPA |
| WebGoat | 教学场景/认证 | `docker run -p 8087:8080 webgoat/webgoat` | 账号体系/认证矩阵 |

镜像 tag/digest 与靶场数据版本必须冻结（写进 `targets.version` 或报告附录），否则"同一靶场"跨季度不可比。仓库不内置镜像/靶场数据，避免把第三方内容打包进发行物。

## 9. 真实站点盲测（20–50 个授权样本）

1. **选样**：覆盖行业/技术栈/规模，登记 `authorization_ref`（书面授权/邮件/测试窗口）；`gov.cn` 不参评；
2. **盲测**：标注人不知道被测产品与竞品分别是谁（双盲），销售不参与计分；
3. **扫描**：统一 `-Mode standard` 与时间窗口，流量提前报备；每目标一次扫描；失败按 §5.4 处理；
4. **标注**：双人独立标注 + 分歧仲裁；20% 发现人工复核确认误报（FP 复核记录入报告）；
5. **计分**：`node benchmark/score.mjs`；
6. **发布**：结果对外需双方确认口径；样本与原始数据按合同脱敏归档。

对标 KPI（《竞品对标与追赶方案》§10）：盲测召回 6 个月内 ≥70%、12 个月 ≥80%；盲测误报 ≤15% / ≤10%。

## 10. 冻结、反作弊与归档

**冻结清单**（全部落入 `run-meta.json` 或报告附录）：
- 被测版本：`sitelens -version`、git commit、可执行文件 SHA256；
- 配置：profile 文件路径 + SHA256（自定义配置同理）；
- 模板库/情报库版本（nuclei 索引条目数、NVD/OSV 数据日期）；
- 目标清单 SHA256、靶场镜像 tag/digest；
- ground-truth 版本（`version` 字段）与标注人；
- 评分器版本（`summary.md` 头部）与覆盖率目录版本；
- 机器/网络环境、开始时间。

**反作弊**（《竞品对标与追赶方案》§9.4 同款）：
- 禁止针对靶场/域名硬编码或特判——发现即判负（代码评审 + 换靶场复测）；
- 每季度更换 ≥30% 靶场与样本；
- 竞品使用官方最新稳定版 + 默认推荐配置；评测人双盲；
- 标注先于扫描（或双盲），不得照抄扫描结果；
- 同一数字必须能由 `run-meta.json` + raw + ground-truth + score.mjs 复现，否则不对外。

**归档**：`out/<suite>-<mode>-<时间戳>/` 整体保留（raw/log/run-meta/summary）；报告引用该目录路径；历史对比只允许同 suite + 同 version + 同口径，跨口径数字不得并列。

## 11. 常见问题

| 现象 | 处理 |
|---|---|
| `exit=1` 且 raw.error 非空 | 看 `raw/<id>.log`（连接失败/WAF/配置），修好后重跑该目标或整体 `-Resume` |
| `exit=124` | 单目标超时；改用 `-Mode fast` 或调大 `-TimeoutSec`，并在报告中记超时 |
| 评分报 `expected 类型不在目录` | ground-truth 用了目录没有的类型：先补 `coverage-catalog.json`（记版本变更）再评分 |
| `out_of_catalog` 很多 | 目录别名需维护，或 finding 标题口径变化；不要当作"未检出" |
| `missing_raw`/`invalid_raw` | 对应目标没跑成功：重跑；确认不能跑时该用例记为 FN 并在报告注明 |
| 目标 `127.0.0.1` 被拒绝 | profile 已含 `target.allow_private: true`；自定义配置需自行加 |
| PowerShell 执行策略报错 | `powershell -ExecutionPolicy Bypass -File benchmark/run.ps1 ...` |
| 两次结果不一致 | 对照 `run-meta.json` 哈希/版本/模式；网络抖动先 `-Mode fast` 冒烟，别用不同档位对比 |

## 12. 相关文档

- [指标定义与季度复评流程](../docs/基准评测-5.2.md)
- [竞品对标与追赶方案（G01/G02、第 9 章评测执行手册）](../docs/竞品对标与追赶方案.md)
- [5.2 新功能路线图（CP-04）](../docs/新功能路线图-5.2.md)
- [覆盖率目录](coverage-catalog.json) / [标注模板](ground-truth/TEMPLATE.ground-truth.json) / [评分器](score.mjs)
