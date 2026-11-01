# web/vendor —— 第三方前端资产升级指南

本目录记录 `web/` 下第三方前端资产（Monaco / Turbo / JSZip）的台账与升级流程。
**台账本体在 [`MANIFEST.md`](MANIFEST.md)**（版本 / 来源 / sha256 / 许可证）。

## 0. 一句话流程

```
确认目标版本 → 只替换资产文件（保持路径与文件名） → 重算 sha256 → 更新 MANIFEST → 跑门禁 + 手工冒烟 → 提交
```

**任何一步都不能省。** 只换文件不更新 MANIFEST 会让台账变成假账；只改 MANIFEST 不换文件更糟。

## 1. 通用规则

1. **保持路径与文件名不变**——`web/embed.go` 用 `//go:embed monaco` 与 `//go:embed *.html js/*.js css/*.css`
   内嵌，前端按固定 URL（`/monaco/vs/loader.js`、`/js/turbo.js`、`/js/jszip.min.js`）加载。
   改文件名 = 运行期 404 且编译期不报错（因为 embed 只认目录/通配符）。
2. **必须是离线可用形态**：禁止把页面里的引用改成 CDN 直链。本产品宣称"零运行时依赖"，
   外网不可达时 Monaco/Turbo/JSZip 仍要能工作（字体 CDN 是唯一已声明的例外，见根 `README.md`）。
3. **不要用 `?v=` 当版本号**：`web/js/audit.js:184` 的 `?v=<n>` 只是缓存击穿计数，
   真正的版本只认 `MANIFEST.md`。
4. **不要用 jsDelivr 的 "latest" 或动态 SRI**：turbo 文件头自己就写了
   `Do NOT use SRI with dynamically generated files!`。必须钉死版本号下载。
5. 许可证**以文件头实际声明为准**。上游是 MIT 不代表这个 vendored 文件里写了 MIT——
   Turbo 当前就是这种情况（台账标"待核实"）。升级时顺手核对上游 `LICENSE`，能填实就填实。

## 2. 逐项升级

### 2.1 Monaco Editor（`web/monaco/vs/`）

```bash
# 1) 取官方 min 发行版（示例版本号按需替换；来源 github.com/microsoft/vscode / monaco-editor）
#    解包后应得到 vs/ 目录：vs/loader.js、vs/editor/editor.main.{js,css}、
#    vs/base/worker/workerMain.js、vs/basic-languages/*、vs/language/{css,html,json,typescript}/*
# 2) 整目录替换（不要只替换 loader.js 或 editor.main.js，三者版本必须同源）
rm -rf web/monaco/vs && cp -r <解包目录>/vs web/monaco/vs
```

替换后必须确认：

- `web/monaco/vs/loader.js` 头部的 `Version:` 与 `Released under the MIT license` 仍在
  （版本号 + 许可证以该头部为准，抄进 MANIFEST）；
- 目录结构未变（`vs/loader.js`、`vs/editor/editor.main.js`、`vs/base/worker/workerMain.js` 均存在）——
  若上游改了 worker 路径或 loader API，需要同步改 `web/js/audit.js:289-290,303`；
- 文件数与总字节变化（MANIFEST 记录的是 94 文件 / 12,178,221 B，升级后应如实更新）。

### 2.2 Turbo（`web/js/turbo.js`）

```bash
# 钉版本下载 UMD 产物（不要 latest）
curl -fsSL https://cdn.jsdelivr.net/npm/@hotwired/turbo@<版本>/dist/turbo.es2017-umd.js \
  -o web/js/turbo.js
head -12 web/js/turbo.js   # 确认头部版本行 "Turbo <版本>" 与 Original file 行
```

注意：

- Turbo 被 **8 个页面**同步引入（`404/api-docs/app/chain/feedback/history/intel/settings.html` 第 7 行），
  跨大版本升级影响所有页面导航（Turbo Drive），必须逐页点一遍（前进/后退、表单提交、局部刷新）；
- 升级时核对上游 `LICENSE`，把 `MANIFEST.md §2.2` 的"待核实"改成实际许可证。

### 2.3 JSZip（`web/js/jszip.min.js`）

```bash
# 钉版本（dist 目录下的单文件发行版）
curl -fsSL https://cdn.jsdelivr.net/npm/jszip@<版本>/dist/jszip.min.js -o web/js/jszip.min.js
head -8 web/js/jszip.min.js   # 确认 "JSZip v<版本>" 与 dual license 行
```

注意：`web/js/audit.js:181-190` 在**首次导出打包**时才注入该脚本，属于低频路径——
升级后必须实际点一次"导出 zip"验证，否则坏掉也不会被日常使用发现。

## 3. 更新台账（必做）

1. 按 `MANIFEST.md §4.1` 重算**逐文件** sha256；
2. 按 `MANIFEST.md §4.2` 重算 Monaco **目录清单哈希**（文件数 / 总字节 / 清单 sha256 三项都要更新）；
3. 更新 `MANIFEST.md`：§1 总览表、§2 对应小节（版本 / 来源 URL / 体积 / sha256 / 许可证）、
   §5 变更记录追加一行（日期 + 换了什么 + 为什么）；
4. **跑门禁自检**（见 §4 第 0 步）：`node scripts/vendor-manifest-check.mjs` 必须 PASS 才算台账更新完成。

> 台账里的 sha256 是"当前仓库文件"的事实记录，**不是**上游发布值；只要文件是新的，就必须重算，
> 不能沿用旧值、也不能抄上游页面上写的校验和（压缩方式不同会不一致）。

> **格式契约**：`MANIFEST.md` 的逐文件完整性表固定三列 `路径 | 字节 | sha256`，
> 目录整体固定三行（文件数 / 总字节 / 目录清单哈希）——`scripts/vendor-manifest-check.mjs`
> 按这两个格式机械解析。别改格式（会被门禁判红），确需调整请同步改脚本。

## 4. 跑门禁（必做）

```bash
# 0) 台账完整性门禁（**必跑**，已接入 CI「前端转义回归」stage；exit 0 = 台账与文件一致）
node scripts/vendor-manifest-check.mjs

# 1) 语法（前端门禁的一部分；vendor 文件本身不参与，但要确认没连带改坏引用它的自有 js）
node --check web/js/common.js web/js/i18n.js

# 2) a11y / 标签 / 设计令牌门禁
node scripts/frontend-check.mjs

# 3) 前端单测（与 CI「前端转义回归」stage 同口径）
node --test web/js/esc.test.mjs web/js/scan-options.test.mjs web/js/tokens.test.mjs web/js/scan-live.test.mjs
node --test scripts/i18n.test.mjs scripts/frontend-check.test.mjs

# 4) 内嵌是否仍能编译（只改 web/ 下静态资产时也应跑一遍，确认 go:embed 未失配）
go build ./...

# 5) 基准自检（CI 同口径）
node benchmark/score.mjs --selftest
```

> 第 0 步是**强门禁**：只要 `MANIFEST.md` 与 `web/monaco/`、`web/js/turbo.js`、`web/js/jszip.min.js`
> 有任何不一致（换文件没更新台账、或改了台账数字），它会打印「期望 / 实际 / 路径」并非零退出。

手工冒烟（自动化门禁覆盖不到，**必须人工做**）：

| 项 | 怎么验 | 预期 |
|---|---|---|
| Monaco 懒加载 | 打开工作台 → 进入源码审计页 | 先骨架后编辑器；DevTools Network 出现 `/monaco/vs/loader.js`、`editor.main.js` |
| Monaco 降级 | 断网/改坏 `/monaco/vs` 路径 | 降级为只读纯文本，不白屏 |
| JSZip 导出 | 审计页点"导出 zip" | 正常下载 zip，可解压 |
| Turbo 导航 | 8 个页面间来回跳转、前进/后退 | 无整页闪烁异常、无 404 |

## 5. 反向检查（提交前自查）

```bash
git status --porcelain web/            # 只应看到预期的资产文件 + MANIFEST.md
git diff --stat web/                   # 确认没有误改 audit.js / app.html 等自有代码
```

以及：**台账 sha256 与文件必须一一对上**——`node scripts/vendor-manifest-check.mjs` 必须 PASS。
这条已接入 CI「前端转义回归」stage（`.cnb.yml`），所以本地没跑就提交会在 CI 红；台账与本目录
不再有"文档漂移"的缺口。
