# .archive/ —— 保留但不参与构建 / 测试 / 发版的退役产物

放这里的都是「产品不再调用、但需要留档」的东西。**点开头目录对工具链天然不可见**：

- Go：`go build ./...` / `go vet ./...` / `go test ./...` 不扫描点目录（`internal/` 等仍正常）；
- Node/npm：不会被自动发现（CI 里的 `node --test` 都显式列文件）；
- 发版/打包：`tools/build-engine.js` 与 `tools/wails_build.sh` 只认仓库根与 `build/`，不读这里。

## 内容

| 目录 | 是什么 | 为什么保留 |
|---|---|---|
| `desktop-electron/` | 退役的 Electron 桌面壳（v5.1.0 起交付线切 Wails） | 历史形态留档；**构建脚本 `build-engine.js` 已移出到 `tools/`**，壳内 `npm run engine` 不再可用 |
| `spark-output/` | 2026-09-17 设计走查的一次性产物 | 留档 |
| `assets/` | 零引用的旧 README 配图（`roadmap.png` / `banner.png` / `banner-3.0-exploit.png`） | 留档；当前 README 用的是 `assets/` 下另外几张 |
| `release-notes/` | 2.0.0–5.1.0 旧发行说明 | 发版脚本已不读（当前版本说明在 `docs/release-<ver>/`），历史留档 |

## 恢复

`git mv .archive/<x> <原路径>` 并回改引用即可。历史文档（CHANGELOG、docs/开发文档-4.0.md、
docs/bug清单-5.1.0.md 等）里出现的 `desktop/...` 旧路径，均指本目录下 `desktop-electron/` 的对应文件。
