# SiteLens 5.3.0 发行说明

> 5.2.3 之后的安全与验证能力升级。默认扫描行为与 5.2.3 一致，新能力全部 additive。

## 版本摘要

- **内置验证集 113 → 1,010 条**：手写核心 60 + 手写扩展 167 + 模板转译 783；
  扩展/转译集仅「完整/穷尽」档运行，标准档请求量不变；
- **ScopeGuard 双层**：`allow_hosts` 下沉到 HTTP 拨号层（重定向逐跳）、协议拨号/DNS
  查询、网络探测逐跳；越权目标零请求拒绝；
- **MCP 危险操作确认**：`scan` / `graphql_introspect` / `assets` 需 `confirm_action`
  一次性令牌（HMAC 绑定工具+参数、60s、单次有效）+ `allow_hosts` Pre-flight；
- **OPSEC 噪声档位**：`scan.opsec` = stealth / evasive / balanced / noisy；
- **目标导向证明链 + 攻击图路径**（只读）：证明链 API 与攻击图路径/瓶颈/证据缺口；
- **安全升级**：Go 1.26.11（修复 GO-2026-6859 net/http MaxBytesReader 竞态）；
  `target.allow_private` 原子化（消除 `-race` 数据竞争）。

## 安装包

| 文件 | 体积 | SHA256 |
|---|---|---|
| `SiteLens-Setup-5.3.0.exe` | `__SIZE__` 字节 | `__SHA256__` |
| `SiteLens_5.3.0_amd64.deb` | `__DEB_SIZE__` 字节 | `__DEB_SHA256__` |

桌面版更新源（`desktop-stable`）：`latest.yml` + 安装包，由 GitHub Actions 从 CNB
Release 同步（CNB 仍是构建/发布唯一真源）。

## 升级说明

- 从 5.2.3 直接覆盖安装即可，配置/历史/种子数据保持兼容；
- MCP 使用方注意：危险工具调用方式变为「先 `confirm_action` 再带 `confirm_token`」，
  且需配置 `--allow-hosts` / `SITELENS_MCP_ALLOW_HOSTS`；只读工具不变；
- 默认档位（标准）行为不变；需要新验证集请选「完整」或「穷尽」档。

## 质量

- `go test ./internal/... ./cmd/...`、`-race`、`govulncheck`、前端门禁全绿；
- 验证集实跑：通用站点/正常应用 0 误报，暴露靶场 30/30 命中
  （见仓库 `docs/5.3-验证集实跑报告.md`）；
- 逐条变更见 `CHANGELOG.md` v5.3.0 章节。
