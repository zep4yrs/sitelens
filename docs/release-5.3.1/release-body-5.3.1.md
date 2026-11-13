# SiteLens 5.3.1 发行说明

> 5.3.0 的元数据复核收尾版：内置验证集 ATT&CK / 噪声 / 安全等级补齐并接入产品。
> 扫描行为与 5.3.0 一致，新增能力全部 additive。

## 版本摘要

- **1,010 条内置验证全部带元数据**：safety 全 `read_only`；noise low 880 / medium 118 /
  high 12；ATT&CK 按证据类型映射到 15 个已核对技术；
- **ATT&CK 映射第二轮补齐**：默认桶 T1595 从 115 条收敛到 5 条（仅真正的主动探测），
  目录列举/管理面板/配置凭据/调试页/CVE 文件读取等按上游模板语义重新归类；
- **元数据接入产品**：
  - 引擎命中 `Hit` 带 `attack` / `noise` / `safety`；
  - SARIF 导出：规则 `tags` 写 ATT&CK 技术 ID，结果 `properties` 写 attack/noise/safety；
  - 新增只读 API `GET /api/checks`（全量 check + 元数据 + 说明）；
- **复核工具**：`tools/checkmeta` 导出全量 CSV + 分布摘要，便于审计抽样。

## 安装包

| 文件 | 体积 | SHA256 |
|---|---|---|
| `SiteLens-Setup-5.3.1.exe` | `__SIZE__` 字节 | `__SHA256__` |
| `SiteLens_5.3.1_amd64.deb` | `__DEB_SIZE__` 字节 | `__DEB_SHA256__` |

桌面版更新源（`desktop-stable`）：`latest.yml` + 安装包，由 GitHub Actions 从 CNB
Release 同步（CNB 仍是构建/发布唯一真源）。

## 升级说明

- 从 5.3.0 / 5.2.3 直接覆盖安装即可，配置/历史/种子数据兼容；
- 默认扫描行为不变；SARIF 新增 tags/properties 字段，旧消费者可忽略。

## 质量

- `go test ./internal/... ./cmd/...`、`-race`、`govulncheck`、前端门禁全绿；
- 元数据门禁：全量非空/合法/白名单、high 噪声占比 <10%、safety 全 read_only、
  SARIF/API 元数据回归；
- 逐条变更见 `CHANGELOG.md` v5.3.1 章节。
