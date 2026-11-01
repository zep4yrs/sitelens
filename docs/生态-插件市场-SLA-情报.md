# SiteLens 生态、插件市场、SLA 与情报流程（设计稿）

> **状态**：设计稿 v0.1（2026-11-01）。本文定义**对外可承诺的生态/交付规则**，不代表当前已具备
> 对应运营能力；标注 ✅ 的是 5.2.x 已落地的机制，⏳ 的是规划项。
>
> **现状基线**：
> - 模板/指纹/情报以「离线资产包」分发：`packs/nuclei-templates.tar.gz`、`packs/afrog`、
>   `data/nvd_cves.json.gz`、`data/affected_ranges.json`、`data/intel_dump.json.gz`、
>   `data/intel_overrides.json`、`data/tpl_intel.json.gz`；桌面安装包内置只读副本，用户侧经
>   `update-nuclei` / `update-osv` / `update-tplintel` / `update-seed` 更新。
> - 资产更新只强制 HTTPS + 实测 SHA256 留痕 + 可选钉值（上游不提供官方签名，**不伪造校验**）；
>   模板来源有「通过率 0 即整源失效」的覆盖门禁（CP-10 已有来源维度统计 runs/pass/fail/hits）。
> - CLI/TUI 已按 5 平台交叉编译引擎包：`win32-x64 / linux-x64 / linux-arm64 / darwin-x64 /
>   darwin-arm64`，产物名 `SiteLens_<token>_engine_<ver>[.exe]`，经 npm 分发。
> - 桌面正式交付仅 Windows x64（Wails + NSIS）；macOS/Linux 桌面壳**未交付**。

---

## 1. 插件市场规范（⏳ 规划，6.x/7.0）

### 1.1 包类型与边界

| 类型 | 内容 | 是否可执行代码 | 说明 |
|---|---|---|---|
| `template-pack` | nuclei/afrog 模板（YAML）、check 定义 | ❌（数据/表达式） | 复用现有模板引擎与语法校验；禁止任意 shell/JS |
| `fingerprint-pack` | 指纹规则、冷门指纹补充 | ❌ | 走现有匹配器；置信度由引擎校准（CP-11） |
| `intel-pack` | CVE/受影响区间/CVSS/KEV 标注增量 | ❌ | 与官方情报源合并规则见 §4 |
| `skill-pack` | 报告模板/合规映射表/词表 | ❌ | 纯数据 |
| `ui-theme` | 主题令牌（色/字体/尺寸） | ❌ | 只允许令牌覆盖，不允许注入 CSS/JS |
| `connector`（远期） | webhook/SIEM/工单集成 | ⚠️ 脚本沙箱外 | 6.x 前不做；若做必须独立进程 + 最小权限 |

**红线**：插件**不得携带可执行二进制或任意脚本**；模板表达式只允许白名单函数。任何需要
「执行代码」的扩展一律拒绝，避免把扫描器变成攻击载荷执行器。

### 1.2 manifest 字段（`sitelens-plugin.json`，UTF-8，必填加粗）

| 字段 | 类型 | 说明 |
|---|---|---|
| **id** | string | 反向域名式唯一 id（`com.example.pack`），发布后不可变 |
| **name** / **version** | string / semver | 展示名 / 语义化版本（不可重发同版本） |
| **kind** | enum | 上表六类之一 |
| **minEngineVersion** / maxEngineVersion | semver | 兼容区间；引擎加载时校验，不满足拒绝加载 |
| **publisher** | object | `{id, name, homepage, publicKey}`；发布者身份与公钥绑定 |
| **license** | string | SPDX（建议 GPL-3.0 兼容；商业包声明商业许可） |
| **digest** | object | `{sha256, files}`：包内全部文件的摘要清单（逐文件） |
| **permissions** | array | 见 §1.3；默认最小权限，空数组=仅纯数据 |
| **entrypoints** | object | 按 kind 声明入口：`templatesDir` / `rules` / `dataFiles` 等 |
| **compat** | object | `{platforms:[win64,linux64,...], engineTags:[]}`（如 onnx 标签） |
| **changelog** | string | 变更摘要（审核与用户可见） |
| **signature** | object | `{alg:"ed25519", keyId, sig}`（发布者对本 manifest 摘要的签名，见 §1.4） |

### 1.3 权限声明（用户可见、运行时强制）

| 权限 | 取值 | 默认 | 说明 |
|---|---|---|---|
| `network` | `none` / `registry-only` / `hosts:[…]` | `none` | 插件数据若需联网拉取，只允许声明白名单域名；引擎拒绝越界请求 |
| `filesystem` | `none` / `read:<subdir>` / `write:<subdir>` | `none` | 只允许插件目录内读写；禁止访问用户数据区任意路径 |
| `secrets` | `none` / `read:auth-headers` | `none` | 默认禁止读取认证头/凭据；需要时单独审核 |
| `exec` | 永远 `never` | — | 不提供执行权限 |
| `report` | `none` / `read:findings` | `none` | 报告类插件只读发现数据 |

安装时把权限清单展示给用户确认；运行期按清单强制（模板只读、网络白名单、路径沙箱）。

### 1.4 签名与完整性校验

```
发布者：manifest 规范化 JSON（键排序、去空白）→ SHA-256 → Ed25519 签名（私钥）→ 附 sig/keyId
引擎：  下载索引/包 → 逐文件 SHA-256 对比 digest → 校验证书链（内置根公钥 + keyId）
        → 验签失败/摘要不符/版本不可变冲突 → 拒绝安装并记录审计事件
```

- **信任根**：市场根公钥随引擎内置（离线可用）；发布者公钥需首次注册并经人工/组织审批；
  支持企业私有市场导入自有根公钥。
- **吊销/撤回**：签名清单带 `revokedAt`；引擎每日同步吊销列表（离线模式下次联网时生效），
  已装插件命中吊销则禁用并提示。
- **越权防护**：manifest 不可自证权限；任何权限提升=新版本+重新审核。
- **与现状衔接**：现有资产包是「上游无签名、只做 HTTPS+SHA256 留痕」；插件市场**要求发布者
  签名**，两者不混用；内置官方包继续走既有 SHA256 钉值机制。

### 1.5 审核流程

| 阶段 | 内容 | 门禁 |
|---|---|---|
| 提交 | 上传包 + manifest + 签名 + 变更说明 | 字段校验、semver、id 唯一、包大小上限 |
| 自动检查 | 结构/语法（模板可解析）、digest 一致、签名验签、权限最小化、危险模式扫描（命令注入/网络越界/路径穿越） | 任一失败拒绝 |
| 沙箱测试 | 在隔离靶场跑通模板（通过率门槛，复用 CP-04 基准与 CP-10 统计），确认无异常网络行为 | 通过率 0 或行为越界拒绝 |
| 人工评审 | 安全评审（数据外发、凭据读取、隐私）、生态政策 | 双人复核（高风险类） |
| 发布 | 签名索引、灰度（可配置百分比/白名单）、公告 | 灰度期可撤回 |
| 运营 | 举报/吊销/版本回滚、下载与安装审计 | 吊销 SLA 见 §3 |

- **版本不可变**：同版本重发一律拒绝；修正必须发新补丁版本并说明原因。
- **分发**：市场索引（`index.json`，签名的）→ 用户选择安装 → 引擎校验后落地到插件目录；
  内置官方 packs 仍随安装包离线可用；企业可配私有镜像/私有市场（同一协议）。
- **更新策略**：**默认不自动升级**；用户显式开启后只自动升同一主版本内的补丁/次版本；
  支持一键回滚到上一版本；离线环境用离线包导入（同样验签）。

---

## 2. SLA 分级

> 当前为单人维护项目，SLA 是**对外承诺目标**，需在商业合同/企业版落地前逐项确认可兑现性。
> 社区版不承诺时限，只承诺响应渠道。

| 等级 | 可用性目标（企业 API/服务） | P1 响应 | P2 响应 | P3 响应 | 修复时限（P1/P2） | 适用 |
|---|---|---|---|---|---|---|
| 社区版 | 不承诺 | 尽力（工作日 48h） | 尽力 | 尽力 | 不承诺 | 免费用户 |
| 标准版（企业） | 99.5%/月 | ≤4 工作小时 | ≤1 工作日 | ≤2 工作日 | P1 24h 内 hotfix/绕行；P2 下个补丁 | 中小团队 |
| 企业级 | 99.9%/月 | ≤1 小时（7×24） | ≤4 小时 | ≤1 工作日 | P1 8h 内 hotfix/绕行；P2 72h | 大客户/生产环境 |
| 情报 SLA（附录） | 见 §4.6 | — | — | — | 关键漏洞情报 ≤24h 入库目标 | 全部付费版 |

- **严重度定义**：P1=生产不可用/数据泄露/远程可利用；P2=主要功能不可用/有绕行；P3=一般缺陷；
  P4=咨询与建议。安全漏洞按 P1 处理并走私下披露渠道。
- **可用性口径**：以服务端 `/api/health`（或 `/api/version`）探测为准；排除计划维护窗口
  （提前 72h 通知，季度 ≤4h）、客户侧网络/环境、不可抗力、客户未按建议升级/配置导致。
- **补救**：连续两月未达可用性目标的企业客户，按合同约定服务抵用（credit）；不承诺现金赔付。
- **支持渠道**：企业工单 + 专属群；社区 Issue；安全漏洞走私下披露（§4.7）。

---

## 3. 情报 / 0day 流程

### 3.1 来源与采集

| 来源 | 用途 | 现状 |
|---|---|---|
| NVD（CVE/CVSS/CPE） | 基础漏洞库与评分 | ✅ `data/nvd_cves.json.gz`（快照）|
| OSV.dev | 受影响区间（版本级） | ✅ `update-osv` → `data/affected_ranges.json` |
| CISA KEV | 在野利用标注（提权） | ⏳ 规划（打分权重）|
| EPSS | 利用概率（排序/提权） | ⏳ 规划（可选接入） |
| 厂商公告 / 安全公告 | 补丁与受影响版本 | 人工复核补充 |
| 自有研究与外部报送 | 0day/未公开问题 | 走 §4.7 披露流程 |

采集约束：只抓公开来源，遵守 robots/许可；不抓取付费情报；上游无签名时只做 HTTPS+SHA256
留痕 + 可选钉值（沿用现有口径，不伪造校验）。

### 3.2 去重与合并

1. 主键：CVE ID（大小写规范化）；无 CVE 时用「厂商+产品+端点/版本」指纹。
2. 别名合并：CVE/CVE-别名/厂商公告号 → 同一漏洞实体；受影响区间取**并集**，评分取来源中
   最新/最高并记录来源与时间。
3. 冲突策略：NVD 与 OSV 区间冲突 → 标记 `conflict` 并保留双方，报告展示不确定；
   人工覆盖写入 `data/intel_overrides.json`（可审计、可回滚）。
4. 去重指标：重复率、冲突数、过期（撤回）数纳入情报质量报告。

### 3.3 评分与排序

- 基础分：CVSS（NVD 官方分数；5.2 起修准线性/查表口径，不自行造分）。
- 增强因子（可配置权重，默认保守）：KEV 在野利用 +、EPSS 高概率 +、可利用性（PoC/公开利用）+
  、资产相关性（指纹/版本命中）+、暴露面（公网/端口）。
- 定级：最终严重度仍以 CVSS 区间为准，增强只影响**排序与展示标签**（避免「自家分数」不可
  对拍）；所有增强项在报告中可解释。
- 质量门禁：每一批次跑基准用例（CP-04），评分器 `benchmark/score.mjs --selftest` 必须通过。

### 3.4 审核与发布

| 步骤 | 内容 |
|---|---|
| 生成 | 从来源生成候选快照（含来源、时间、签名前摘要） |
| 审核 | 抽样人工复核（高危/冲突/新增来源）；自动校验 schema 与区间合法性 |
| 签名 | 快照清单 SHA256 + Ed25519 签名（发布密钥与插件市场根分离） |
| 发布 | 通道：`stable`（默认）/`beta`（提前量）；版本号单调递增；元数据写 `intel_snapshots` |
| 灰度 | 先 beta 通道 7 天，观察误报/漏报与崩溃，再进 stable |
| 回滚 | 保留最近 N（默认 12）个快照；一键回滚 = 指回旧快照 + 重新签名；用户侧可钉 `data/` 快照 |

### 3.5 0day / 未公开漏洞处置

- **责任披露**：优先私下联系厂商/CNVD/CVE 编号机构；默认给 90 天修复窗口（可协商缩短/延长）。
- **产品边界**：只发布**检测/验证性模板**（确认存在、非破坏），**不内置利用代码/武器化 PoC**；
  不提供「一键 getshell」。
- **发布时机**：厂商修复或公开披露后进 stable；紧急在野利用可走 beta 提前量并显著标注。
- **法律与授权**：所有扫描需授权目标；0day 情报不向未授权用户开放；合规责任在使用者。

### 3.6 情报更新 SLA（付费版目标）

| 类型 | 目标 |
|---|---|
| 关键漏洞（CVSS ≥9 / 在野利用 / 高危供应链） | ≤24h 入库（含模板/区间），≤72h stable |
| 高危（7–8.9） | ≤72h 入库，≤7 天 stable |
| 中低危/批量同步 | 每周至少 1 次 |
| 撤回/修正 | 确认后 ≤24h 发布修正快照 |

---

## 4. 跨平台正式交付矩阵

> 「正式交付」= 有测试、有发布物命名规范、有升级路径；「规划」= 尚无产物。
> 发布物与检查规则见 [`../scripts/release/release-matrix.md`](../scripts/release/release-matrix.md)，
> 自动校验脚本 `scripts/release/check.ps1`。

| 平台/形态 | 状态 | 包格式 | 产物命名 | 签名 | 自动更新 | 兼容基线 |
|---|---|---|---|---|---|---|
| Windows 桌面（Wails） | ✅ 正式 | NSIS 安装包 `.exe` | `SiteLens-Setup-<ver>.exe`（`dist/release/`） | ⏳ 未签名（Authenticode 占位，见矩阵） | ✅ 自建壳读 `latest.yml`（GitHub `desktop-stable` 三件套：exe/blockmap/latest.yml），整包覆盖安装 | Windows 10 1903+/11 x64；需 WebView2 运行时；Go 1.26 构建 |
| Windows CLI/TUI（npm） | ✅ 正式 | npm 包 + 引擎平台包 | `@fengqiao666/sitelens-cli`；引擎 `SiteLens_win64_engine_<ver>.exe` | npm 源签名（发布流程）/引擎包无独立签名 | `npm update -g` | 同桌面；独立引擎版本随 npm 包 |
| macOS CLI/TUI（npm） | ✅ 正式 | npm 包 + 引擎平台包 | `SiteLens_mac64_engine_<ver>`、`SiteLens_mac-arm64_engine_<ver>` | 无独立签名（npm 完整性） | `npm update -g` | macOS 12+（x64/arm64） |
| Linux CLI/TUI（npm） | ✅ 正式 | npm 包 + 引擎平台包 | `SiteLens_linux64_engine_<ver>`、`SiteLens_linux-arm64_engine_<ver>` | 无独立签名（npm 完整性） | `npm update -g` | glibc 2.31+（Ubuntu 20.04+ 等）；x64/arm64 |
| macOS 桌面（Wails） | ⏳ 规划 | `.dmg`（可选 `.pkg`） | `SiteLens-<ver>-macOS-<arch>.dmg` | 计划 Developer ID + 公证（notarization） | 计划复用 `latest.yml` 同源协议 | macOS 12+ |
| Linux 桌面（Wails/Tauri 评估） | ⏳ 规划 | AppImage / `.deb`（可选 tar.gz） | `SiteLens-<ver>-linux-<arch>.AppImage` | 计划 GPG 签名 `*.asc` | 计划 AppImage 更新或复用 latest.yml | glibc 2.31+ |
| 企业服务端（6.x） | ⏳ 规划 | Docker 镜像 / 二进制 tar.gz | `sitelens-server-<ver>-linux-<arch>.tar.gz` / 镜像 tag | 镜像 digest + cosign（计划） | 手工滚动升级（不自动） | Linux x64/arm64 |

**兼容与升级约束**：

- 版本号单一来源 `desktop-wails/version.go`（与 `internal/server.Version` 必须一致，脚本硬校验）；
  npm 线独立版本（`tui/package.json`），引擎版本随平台包，二者不同步时以「引擎版本」为准并在
  `update-seed` 时收敛用户数据。
- Windows 自动更新只覆盖整包安装，不做增量；更新失败自动保留旧版可回退（安装器覆盖安装语义）。
- 跨平台 CLI 引擎必须由同一 commit 交叉编译（5 平台），发版时校验产物存在与版本串一致。
- 公开更新源唯一：GitHub `desktop-stable`；CNB Release 只发布安装包与发行说明（不上传
  latest.yml/blockmap，避免双源漂移）。
- 系统要求：Windows 需 WebView2（Win10 1903+ 可预装/引导安装）；macOS/Linux 桌面尚未交付，
  不对外承诺。

---

## 5. 风险与边界

| 风险 | 缓解 |
|---|---|
| 插件市场引入供应链攻击面 | 签名+权限最小化+无代码执行+审核沙箱+吊销机制；内置包与市场包分离信任域 |
| SLA 承诺与单人维护能力不匹配 | 合同前逐项评估；社区版不承诺；企业版设服务窗口与升级要求 |
| 情报来源依赖上游（NVD 停更/延迟、OSV 覆盖不全） | 多源合并 + 冲突标注 + 快照版本化 + 保留回滚；不伪造官方分数 |
| 0day 伦理/法律风险 | 责任披露、不武器化、授权目标、法务评审后再上线 |
| 跨平台桌面投入大 | 先以 CLI/TUI 覆盖 macOS/Linux（已有 5 平台引擎），桌面壳按需求排期 |
| 签名密钥管理 | 离线根/发布密钥分离、HSM/密钥库计划、吊销列表、轮换预案 |

---

## 6. 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-11-01 | v0.1 | 初稿：插件 manifest/权限/签名/审核/分发、SLA 分级、情报与 0day 流程、跨平台交付矩阵；标注现状（✅ 已落地机制 / ⏳ 规划）。 |
