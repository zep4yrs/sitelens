# 5.2.3 靶场验收（自建合成靶场，2026-11-01）

> **口径**：本机无 Docker/PHP，无法启动 DVWA/pikachu 标准矩阵；本次使用
> [`benchmark/labs/selfhosted`](../../benchmark/labs/selfhosted/) 自建合成靶场做首轮
> benchmark 验收。它**不是标准靶场矩阵**，结果只能作为“检测链路可用、无误报”的冒烟证据，
> 不能作为对外标准召回率。

## 环境

| 项 | 值 |
|---|---|
| 站点 | SiteLens 5.2.3 CLI（`go build -o .tmp/sitelens-5.2.3.exe ./cmd/sitelens`） |
| 扫描配置 | `benchmark/profiles/standard.yml`（deep、polite 150ms、core checks） |
| 靶场 | `benchmark/labs/selfhosted/lab.py` @ 127.0.0.1:8081 |
| 操作系统 | Windows 11 企业版 10.0.26300 |
| 时间 | 2026-11-01 16:10–16:14（Asia/Shanghai） |

## 套件

10 个目标：SQLi×4（sqli-error / sqli-labs / pikachu / bWAPP 路径）、XSS×2、路径穿越×1、
CSRF×1、安全用例×2（login / WebGoat）。端点实现真实漏洞行为（报错/布尔差分、原样回显、
passwd 内容返回、无 token 表单），安全用例带转义+CSRF token+`Cache-Control: no-store`。

## 结果

```
suite=selfhosted-lab targets=10 TP=8 FP=0 FN=0
Precision=1.0000 Recall=1.0000 F1=1.0000
预期类型覆盖率=100.0%（4/4）  目录类型覆盖率=13.3%（4/30）
安全用例误报=0/2   missing_raw=0 invalid_raw=0
```

| 类型 | 期望 | TP | FN | FP |
|---|---:|---:|---:|---:|
| SQL 注入 | 4 | 4 | 0 | 0 |
| 跨站脚本 | 2 | 2 | 0 | 0 |
| CSRF | 1 | 1 | 0 | 0 |
| 路径穿越/任意文件读取 | 1 | 1 | 0 | 0 |

单目标耗时 18–39s（standard 档，含限速与 4 个 SQLi 目标 35s 左右）。

## 口径修复（本轮发现）

SiteLens 的 `vulnerabilities[]` 会携带 CVE/模板情报（`verdict=possible`），
原 `score.mjs` 会把它们当作检出映射，产生大量 FP。已修：
`score.mjs` 对 `vulnerabilities[]` 中 `verdict=possible/potential/unverified` 的条目跳过；
`docs/基准评测-5.2.md` §3 同步；`--selftest` 36 断言通过。

## 复现

```powershell
python benchmark/labs/selfhosted/lab.py 8081
pwsh -File benchmark/run.ps1 -Targets benchmark/labs/selfhosted/targets.json `
  -Mode standard -Sitelens .tmp/sitelens-5.2.3.exe `
  -Truth benchmark/labs/selfhosted/ground-truth.json -TimeoutSec 180
```

原始输出：`benchmark/out/selfhosted-lab-standard-<ts>/`（`.gitignore` 忽略；本机为
`.tmp/lab/out`）。

## 待补

- 标准 DVWA/pikachu/sqli-labs/upload-labs/xsslabs/bWAPP/Juice Shop/WebGoat 矩阵（需 Docker/PHP）；
- 20 个授权样本 + 季度复评；
- 覆盖率从 4/30 提升（当前只验证 4 类）。
