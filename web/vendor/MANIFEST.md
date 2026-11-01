# 第三方前端组件台账（web/vendor）

> **目的**：记录 `web/` 下**非本仓库原创**的前端资产的版本、来源、完整性（sha256）与许可证，
> 让"这份 monaco / turbo / jszip 到底是什么版本、许可能不能用、升级要动哪里"可被外部复核。
>
> **适用范围**：`web/monaco/`、`web/js/turbo.js`、`web/js/jszip.min.js`。
> 仓库内其它 `web/js/*.js`（`app.js`/`audit.js`/`common.js`/`i18n.js`/`tokens.js` 等）是本仓库原创代码，
> 不在此台账内，也不随第三方升级变动。
>
> **sha256 口径**：下列哈希全部由**当前仓库文件实算**得到（`Get-FileHash -Algorithm SHA256` /
> `sha256sum`），未引用上游发布值。台账基线时间：2026-11-01。复核命令见 §4。

## 1. 总览

| 名称 | 版本 | 引入方式 | 许可证 | 体积 | 明细 |
|---|---|---|---|---|---|
| Monaco Editor | **0.52.2**（commit `404545b`） | 整目录入库 + `go:embed`，运行期懒加载 | **MIT**（文件头声明） | 94 文件 / 12,178,221 B | §2.1 |
| Turbo（@hotwired/turbo） | **8.0.13** | 单文件，`<script>` 同步引入 | **待核实**（文件头未声明，见 §2.2） | 94,052 B | §2.2 |
| JSZip | **3.10.1** | 单文件，运行期动态注入 | **MIT 或 GPLv3**（双许可，文件头声明） | 97,642 B | §2.3 |

## 2. 逐项明细

### 2.1 Monaco Editor

- **名称 / 版本**：Monaco Editor（VS Code 编辑器内核，官方 min 发行版）**0.52.2**，
  commit `404545bded1df6ffa41ea0af4e8ddb219018c6c1`。
  版本与许可证来自文件头自述（`web/monaco/vs/loader.js:1-6`、`web/monaco/vs/editor/editor.main.js:1-6`）：

  ```
  /*!-----------------------------------------------------------
   * Copyright (c) Microsoft Corporation. All rights reserved.
   * Version: 0.52.2(404545bded1df6ffa41ea0af4e8ddb219018c6c1)
   * Released under the MIT license
   * https://github.com/microsoft/vscode/blob/main/LICENSE.txt
   *-----------------------------------------------------------*/
  ```

- **来源 URL**：<https://github.com/microsoft/vscode>（许可正文 <https://github.com/microsoft/vscode/blob/main/LICENSE.txt>）。
  目录形态对应 `monaco-editor` 官方 min 发行的 `min/vs/` 树。
- **引入方式**：
  1. 目录整体入库：`web/monaco/vs/`；
  2. 编译期内嵌：`web/embed.go:12-13` `//go:embed monaco` → `MonacoFS`，由引擎以 `/monaco/` 前缀静态服务；
  3. 运行期懒加载（FE-09）：`web/js/audit.js:303` 动态插入 `/monaco/vs/loader.js`
     → `:289` `require.config({ paths: { vs: "/monaco/vs" } })`
     → `:290` `require(["vs/editor/editor.main"], …)`。
     不进审计页不下载（约 12MB）。
- **许可证**：**MIT**（依据：`loader.js` / `editor.main.js` 头部 `Released under the MIT license`）。
- **完整性（关键入口文件）**：

  | 文件（相对仓库根） | 字节 | sha256 |
  |---|---|---|
  | `web/monaco/vs/loader.js` | 30,061 | `e54ed34df62046aee410b0b60aebe6d3290c1c87f734d42f51063e1ead5ee87e` |
  | `web/monaco/vs/editor/editor.main.js` | 3,767,451 | `a0e91ed7d71e45c4ab051facd6ba446ab0cf8645515c01802b1208bb7f52ea58` |
  | `web/monaco/vs/editor/editor.main.css` | 131,865 | `2c5943595b7e59441ef81038433bd915aef1c52864b833b74549ddd8d319a9c9` |
  | `web/monaco/vs/base/worker/workerMain.js` | 376,545 | `eef69b3c3d3d3583273ccfd0f07c905a6b428797b3e369149371450538d5624e` |
  | `web/monaco/vs/language/typescript/tsWorker.js` | 5,800,846 | `06db6aa5c2a5ae905ec17e1b922d9f046328afc68a81cdab33d95e531e56a622` |
  | `web/monaco/vs/language/html/htmlWorker.js` | 449,524 | `bd019605d5d32198dcd27e03df67a7fe5d0900c808ac4c6d2cffe8dc45e4131a` |
  | `web/monaco/vs/language/css/cssWorker.js` | 778,112 | `e4d197569d1037951518be46618f2bab4a090aa374118ab0e17b9b6469fd75b7` |
  | `web/monaco/vs/language/json/jsonWorker.js` | 131,219 | `b000a1e55d33d3c1c0683913da1b18e0c9552d903693fd0bc78ba4b6ebc2f1a6` |

- **完整性（目录整体）**：
  - 文件数 **94**，总字节 **12,178,221**；
  - 目录清单哈希 **`de34ab58556cfa17ba3d82d1940b5e8e9cace13a8495bb33b8ea5624bb40bb8e`**
    （算法 = 对"按路径排序的 `<sha256> + 两个空格 + 路径` 清单"取 sha256，复现命令见 §4.2；
    这个指纹只用于**变更检测**，不是上游发布值）；
  - 组成：81 个 `vs/basic-languages/<lang>/<lang>.js` 语言包 + `vs/loader.js` +
    `vs/editor/editor.main.{js,css}` + `vs/base/worker/workerMain.js` +
    4 组语言 worker（`css` / `html` / `json` / `typescript`，每组 2 文件：`xWorker.js` + `x.js`）+
    `vs/base/browser/ui/codicons/codicon/codicon.ttf`。
- **升级方式**：见 `web/vendor/README.md` §2.1（替换整个 `vs/` 目录 → 重算 §4 → 更新本表 →
  跑 `node --check` / 前端门禁 / 手工开一次源码审计页确认懒加载与降级正常）。

### 2.2 Turbo（@hotwired/turbo）

- **名称 / 版本**：Turbo **8.0.13**。来源与版本来自文件头自述（`web/js/turbo.js:1-10`）：

  ```
  /**
   * Minified by jsDelivr using Terser v5.39.0.
   * Original file: /npm/@hotwired/turbo@8.0.13/dist/turbo.es2017-umd.js
   * ...
   */
  /*!
  Turbo 8.0.13
  Copyright © 2025 37signals LLC
   */
  ```

- **来源 URL**：`https://cdn.jsdelivr.net/npm/@hotwired/turbo@8.0.13/dist/turbo.es2017-umd.js`
  （文件头写的是 jsDelivr 的 min 产物、Terser v5.39.0 压缩；上游仓库 <https://github.com/hotwired/turbo>）。
- **引入方式**：`<script src="/js/turbo.js"></script>`，**8 个页面**同步引入（均在第 7 行）：
  `web/404.html`、`web/api-docs.html`、`web/app.html`、`web/chain.html`、`web/feedback.html`、
  `web/history.html`、`web/intel.html`、`web/settings.html`。
- **许可证**：**待核实**。该 min 文件头只有版本与版权行，**未声明许可证**；
  全文检索无 `MIT` / `license` 字样，也**未随仓库附带 LICENSE 文件**。
  上游 `@hotwired/turbo` 属 37signals 开源项目（社区普遍记为 MIT），但按"以文件头实际声明为准"
  的口径，此处标注**待核实**：升级或对外分发前必须核对上游 `LICENSE` 后回填本节。
- **完整性**：

  | 文件（相对仓库根） | 字节 | sha256 |
  |---|---|---|
  | `web/js/turbo.js` | 94,052 | `624c4c0097f504d24dbe8343769e385605b62cff40229f2904bf9c0f4214c8de` |

- **升级方式**：见 `web/vendor/README.md` §2.2。

### 2.3 JSZip

- **名称 / 版本**：JSZip **3.10.1**。来自文件头自述（`web/js/jszip.min.js:1-14`）：

  ```
  /*!
  JSZip v3.10.1 - A JavaScript class for generating and reading zip files
  <http://stuartk.com/jszip>
  (c) 2009-2016 Stuart Knightley <stuart [at] stuartk.com>
  Dual licenced under the MIT license or GPLv3. See https://raw.github.com/Stuk/jszip/main/LICENSE.markdown.
  JSZip uses the library pako released under the MIT license :
  https://github.com/nodeca/pako/blob/main/LICENSE
  */
  ```

- **来源 URL**：<https://github.com/Stuk/jszip>（同上文件头 URL）。
- **引入方式**：**运行期动态注入**，非 HTML 静态引用——
  `web/js/audit.js:181-190` 在首次需要打包导出时创建 `<script src="/js/jszip.min.js?v=<n>">`
  （`?v=` 只是缓存击穿计数，**不是内容版本**；真实版本以本台账为准）。
- **许可证**：**MIT 或 GPLv3（双许可，由使用者二选一）**，依据文件头 `Dual licenced under the MIT license or GPLv3`。
  ⚠ 本项目整体为 **GPL-3.0**（见仓库根 `LICENSE`），两种许可下均可分发；如需收紧到单一许可，
  选 GPLv3 分支与项目协议一致。
  该单文件内**内联了 pako**（文件头注明 pako 为 MIT），故不需单独台账。
- **完整性**：

  | 文件（相对仓库根） | 字节 | sha256 |
  |---|---|---|
  | `web/js/jszip.min.js` | 97,642 | `f12f367798e35ee2d9993dba6167fc61ddb52fb89880f5a99fbb606335188410` |

- **升级方式**：见 `web/vendor/README.md` §2.3。

## 3. 与构建 / 门禁的关系

- 三项均为**前端静态资产**，不参与 Go 模块依赖：与 `go.mod` / `vendor/` / `go.sum` 无关。
  Monaco 走 `go:embed`（`web/embed.go`）进二进制；turbo/jszip 由 `//go:embed js/*.js` 一并内嵌。
- **完整性已纳入 CI 门禁**：`scripts/vendor-manifest-check.mjs` 解析本文件声明的
  逐文件 sha256 / 体积，并复算 Monaco 目录清单哈希，任一不一致即非零退出；
  该脚本已接进 `.cnb.yml` 的「前端转义回归」stage（每次 push/PR 都跑）。
  也就是说：**台账与本目录/文件不再可能静默漂移**。
- **表格式即契约**：本文件的"逐文件完整性表"（三列 `路径 | 字节 | sha256`）与
  §2.1 的"目录整体"三行（文件数 / 总字节 / 目录清单哈希）是脚本的解析输入。
  改格式会导致门禁判红（fail-closed），确需调整时同步改
  `scripts/vendor-manifest-check.mjs` 的 `ROW_RE` 与 `EXPECTED_FILE_ENTRIES`。
- `.dockerignore` 未排除 `web/`，本目录会进入 Docker 构建上下文（纯文本，体积可忽略）。

## 4. 校验命令

### 4.1 逐文件校验（预期值见 §2）

> 下面只是**人工抽检 4 个 Monaco 入口 + 2 个单文件 js** 的命令；
> 台账里实际声明了 **8 个** Monaco 条目（另含 4 组语言 worker），
> 全量核对请直接用 §4.3 的门禁脚本（它会遍历 §2 全部表格行）。

PowerShell（Windows）：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath web/monaco/vs/loader.js,
  web/monaco/vs/editor/editor.main.js, web/monaco/vs/editor/editor.main.css,
  web/monaco/vs/base/worker/workerMain.js,
  web/js/turbo.js, web/js/jszip.min.js | Format-Table Hash,Path -AutoSize
```

bash / sha256sum（Linux/macOS）：

```bash
sha256sum web/monaco/vs/loader.js \
          web/monaco/vs/editor/editor.main.js \
          web/monaco/vs/editor/editor.main.css \
          web/monaco/vs/base/worker/workerMain.js \
          web/js/turbo.js web/js/jszip.min.js
```

### 4.2 Monaco 目录清单哈希（变更检测）

清单格式：每个文件一行 `<sha256> + 两个空格 + 相对仓库根的 POSIX 路径`，**按路径排序**，LF 换行、带尾随换行；
对该清单文件取 sha256。

```bash
cd <仓库根>
find web/monaco -type f -print0 | xargs -0 sha256sum | sort -k2 > /tmp/monaco.list
wc -l /tmp/monaco.list            # 预期 94
sha256sum /tmp/monaco.list        # 预期 de34ab58556cfa17ba3d82d1940b5e8e9cace13a8495bb33b8ea5624bb40bb8e
```

PowerShell 等价实现：

```powershell
$root = (Get-Location).Path
$lines = Get-ChildItem web/monaco -Recurse -File | ForEach-Object {
  $rel = $_.FullName.Replace($root + '\','').Replace('\','/')
  "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower(), $rel
}
$sorted = $lines | Sort-Object { ($_ -split '  ',2)[1] }
$payload = ($sorted -join "`n") + "`n"
$tmp = Join-Path $env:TEMP 'monaco.list'
[System.IO.File]::WriteAllText($tmp, $payload, (New-Object System.Text.UTF8Encoding($false)))
Get-FileHash -Algorithm SHA256 -LiteralPath $tmp | Select-Object Hash
```

### 4.3 门禁脚本（CI 同口径，替换资产后**必跑**）

```bash
node scripts/vendor-manifest-check.mjs          # 0 = 一致；非 0 = 台账与文件漂移
```

它做的事：解析本文件的逐文件表 + §2.1 的目录整体三行 → 实算每个文件 sha256 / 体积，
并复算 Monaco 目录清单哈希 → 任一不一致打印「期望/实际/路径」并非零退出。
该脚本已接进 `.cnb.yml`「前端转义回归」stage，本地跑一遍即可预判 CI 结果。

## 5. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-11-01 | 首次建立台账（D-13）。Monaco 0.52.2 / Turbo 8.0.13 / JSZip 3.10.1 的版本、来源、sha256、许可证与引入方式；Turbo 许可证标"待核实"（文件头未声明）。 |
| 2026-11-01 | 台账纳入 CI 门禁：新增 `scripts/vendor-manifest-check.mjs` 并接入 `.cnb.yml`「前端转义回归」stage；Turbo/JSZip 的完整性记录统一成三列表格（机器可解析的唯一格式）。 |
