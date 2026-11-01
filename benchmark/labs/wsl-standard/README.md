# WSL 标准靶场子集（DVWA low / xsslabs / upload-labs）

> 本机 WSL2 Ubuntu 24.04 部署的**标准开源靶场子集**，用于 5.2.3 验收。
> 与 `benchmark/labs/selfhosted`（合成靶场）不同：这些是真实开源靶场应用。
> 注意：只覆盖 DVWA/xsslabs/upload-labs；pikachu/sqli-labs/bWAPP/Juice Shop/WebGoat
> 未部署（sqli-labs 使用 PHP 5 `mysql_*`，Ubuntu 24.04 的 PHP 8.3 无法运行）。

## 部署（WSL2）

```bash
# 1) LAMP
apt-get update && apt-get install -y apache2 php php-mysql php-gd php-xml php-mbstring mariadb-server unzip
service mariadb start && service apache2 start

# 2) 靶场源码（GitHub codeload 经 Windows 下载后拷入 WSL；WSL 内 GitHub 被重置）
#    DVWA master / xss-labs master / upload-labs master → /var/www/html/{dvwa,xsslabs,upload-labs}

# 3) DVWA：config.inc.php 设置 default_security_level='low'、disable_authentication=true；
#    创建 dvwa 库/用户后访问 /dvwa/setup.php 点 Create/Reset Database。

# 4) 安全验证页：/var/www/html/safe/index.html（无链接/表单）
```

## 扫描

```powershell
pwsh -File benchmark/run.ps1 `
  -Targets benchmark/labs/wsl-standard/targets.json `
  -Config benchmark/labs/wsl-standard/profile.yml `
  -Sitelens .tmp/sitelens-5.2.3.exe `
  -Truth benchmark/labs/wsl-standard/ground-truth.json -TimeoutSec 180
```

`profile.yml` 是 **DAST-lite**（不深爬，只对入口页做主动检测）——DVWA 页面多，
`benchmark/profiles/standard.yml` 深爬单目标会跑 5–10 分钟（实测 2255+ 请求未结束）。

## 2026-11-01 结果（CSRF 修复后）

| 指标 | 值 |
|---|---|
| TP / FP / FN | 5 / 1 / 1 |
| Precision / Recall / F1 | 0.8333 / 0.8333 / 0.8333 |
| 类型覆盖 | 4/5（SQLi、XSS、CSRF、路径穿越） |
| 安全用例误报 | 0/1 |

- FP：upload-labs 上传表单无 CSRF token（`csrf-form`，POST 表单；是否算真漏洞可讨论）；
- FN：upload-labs 的 `file_upload` 未检出（上传利用默认 dry-run，需显式开启主动上传）；
- 本轮修复：`csrf-form` 曾把 DVWA 搜索表单（GET + `submit` 按钮/`name` 字段）误报为 CSRF，
  修复后 FP 3→1；回归测试 `internal/passive/passive_test.go:TestCSRFFormGetSearchNotFlagged`。
