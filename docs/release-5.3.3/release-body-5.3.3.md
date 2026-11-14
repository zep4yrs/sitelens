# SiteLens 5.3.3 发行说明

> 安装器升级目录修复版：修复 5.3.2 静默升级落到默认目录、形成双安装的问题。
> 自动更新逻辑（UAC 提权 / 默认自动安装）与 5.3.2 一致。

## 版本摘要

- **修复安装器升级目录**：NSIS 引导程序是 32 位，`.onInit` 读
  `HKLM\Software\SiteLens\InstallDir` 会被 WOW64 重定向到 `WOW6432Node`，
  导致读不到原安装目录 → 静默升级落到默认 `C:\Program Files`，与旧目录
  （如 `D:\Program Files\SiteLens`）形成双安装；
- `.onInit` 先 `SetRegView 64` 读安装目录/卸载表，读不到再回退 32 位视图；
  覆盖升级（含自动更新）就地更新原目录，不再产生第二份安装；
- 自动更新（5.3.2 引入）：启动 8s 后检查 + 每 6 小时复查，发现新版本自动
  下载 → sha512 校验 → 静默安装（一次 UAC）→ 重启；设置页可关闭。

> **5.3.2 双安装清理**：如果 5.3.2 把新版装到了 `C:\Program Files\SiteLens`，
> 先运行该目录下的 `uninstall.exe` 卸载多余副本，再安装 5.3.3；5.3.3 会按
> 注册表/卸载表回到原安装目录。

## 安装包

| 文件 | 体积 | SHA256 |
|---|---|---|
| `SiteLens-Setup-5.3.3.exe` | `__SIZE__` 字节 | `__SHA256__` |
| `SiteLens_5.3.3_amd64.deb` | `__DEB_SIZE__` 字节 | `__DEB_SHA256__` |

桌面版更新源（`desktop-stable`）：`latest.yml` + 安装包，由 GitHub Actions 从 CNB
Release 同步（CNB 仍是构建/发布唯一真源）。

## 质量

- `go test ./internal/... ./cmd/...`、`-race`、`govulncheck`、前端门禁全绿；
- 真机验证：5.3.2 → 5.3.3 静默覆盖安装落回原目录（注册表 64 位视图一致）；
- 逐条变更见 `CHANGELOG.md` v5.3.3 章节。
