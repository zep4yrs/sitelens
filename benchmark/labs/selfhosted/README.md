# 自建合成靶场（验收专用，非标准矩阵）

> 用途：本机没有 Docker/PHP 时的 **benchmark 冒烟/验收**；端点实现真实的 SQLi/XSS/CSRF/
> 路径穿越行为 + 2 个安全用例。**它不是 DVWA/pikachu/sqli-labs 标准矩阵**，不得用于
> 对外宣称标准靶场召回；标准矩阵仍需在 Docker 环境补跑。

## 运行

```bash
python benchmark/labs/selfhosted/lab.py 8081
```

```powershell
# 另开终端：跑 10 个目标并评分
pwsh -File benchmark/run.ps1 `
  -Targets benchmark/labs/selfhosted/targets.json `
  -Mode standard `
  -Sitelens path/to/sitelens-5.2.3.exe `
  -Truth benchmark/labs/selfhosted/ground-truth.json `
  -TimeoutSec 180
```

## 端点

| 路径 | 行为 | 期望类型 |
|---|---|---|
| `/vulnerabilities/sqli/?id=1` 等 4 个 SQLi 路径 | `'` 触发 SQL 报错；`1'='1` / `1'='2` 返回不同内容 | sql_injection |
| `/vulnerabilities/xss_r/?name=test`、`/level1.php?name=test` | name 原样回显（未编码） | xss |
| `/vulnerabilities/fi/?page=include.php` | `page=../../etc/passwd` 返回 passwd 内容 | path_traversal |
| `/vulnerabilities/csrf/` | 状态变更表单，无 anti-CSRF token | csrf |
| `/login.php`、`/WebGoat/start.mvc` | 转义输出 + CSRF token + Cache-Control: no-store | 安全用例（期望 0 检出） |

## 限制

- 合成靶场，覆盖 4 个目录类型（4/30），不能代表真实应用复杂度；
- 标准 DVWA/pikachu 矩阵需要 Docker/PHP，尚未在本机跑；
- 2026-11-01 首轮结果：P=1.0000 R=1.0000 F1=1.0000（TP=8 FP=0 FN=0），见
  [`docs/release-5.2.3/benchmark-selfhosted-2026-11-01.md`](../../../docs/release-5.2.3/benchmark-selfhosted-2026-11-01.md)。
