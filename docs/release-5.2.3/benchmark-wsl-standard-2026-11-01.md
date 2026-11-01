# 5.2.3 标准靶场验收（WSL2 子集，2026-11-01）

> 口径：WSL2 Ubuntu 24.04 + PHP 8.3 + MariaDB 10.11 本地部署的**真实开源靶场子集**
> （DVWA low / xss-labs / upload-labs）；使用 DAST-lite profile（不深爬，只测入口页）。
> 不是完整 matrix：pikachu/sqli-labs/bWAPP/Juice Shop/WebGoat 未部署。

## 环境

| 项 | 值 |
|---|---|
| 靶场 | WSL2 Ubuntu 24.04；Apache 2.4.58 / PHP 8.3.6 / MariaDB 10.11 |
| 目标 | `http://127.0.0.1/dvwa/...`、`/xsslabs/level1.php`、`/upload-labs/Pass-01/`、`/safe/`（经 WSL2 localhost 转发） |
| SiteLens | 5.2.3 CLI（Windows 构建）+ `benchmark/labs/wsl-standard/profile.yml`（DAST-lite） |
| 时间 | 2026-11-01 17:10–17:20（Asia/Shanghai） |

## 结果（CSRF 修复后）

```
suite=wsl-standard-lab targets=7 TP=5 FP=1 FN=1
Precision=0.8333 Recall=0.8333 F1=0.8333
类型覆盖=80.0%（4/5）  安全用例误报=0/1
```

| 用例 | 期望 | 检出 | 结果 |
|---|---|---|---|
| dvwa-sqli | sql_injection | sql_injection | ✅ |
| dvwa-xss | xss | xss | ✅ |
| dvwa-lfi | path_traversal | path_traversal | ✅ |
| dvwa-csrf | csrf | csrf | ✅ |
| xsslabs-level1 | xss | xss | ✅ |
| upload-labs-pass01 | file_upload | csrf（FP） | ❌（file_upload FN；csrf-form 报在上传表单） |
| safe-page | — | — | ✅ 0 检出 |

单目标 1.8–30s（DAST-lite）。

## 本轮修复

`csrf-form` 原先把 DVWA SQLi/XSS 搜索表单（GET 表单 + `name`/`submit` 字段）误报为
CSRF，标准靶场首轮 FP=3/7。修复：
- GET 表单只用「强状态字段」判定（password_new/password_conf/password/update/save/delete/transfer/amount）；
- 排除 `submit/button/reset/image` 控件；
- 新增回归 `internal/passive/passive_test.go:TestCSRFFormGetSearchNotFlagged`。

修复后 csrf 类 FP 3→1（只剩 upload-labs 上传表单；POST 表单无 token，属可讨论的真问题）。

## 遗留

- `file_upload` 未检出：上传利用默认 dry-run，需显式开启主动上传后复测；
- 完整标准矩阵（pikachu / sqli-labs / bWAPP / Juice Shop / WebGoat）未部署；
  sqli-labs 使用 PHP 5 `mysql_*`，PHP 8.3 下需改造或换 PHP 5.6 容器；
- 本轮配置为 DAST-lite，不是对外 standard 深爬口径；完整口径仍需跑 `profiles/standard.yml`。
