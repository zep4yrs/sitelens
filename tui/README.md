# @fengqiao666/sitelens-cli

SiteLens 站点透视的终端扫描台：**唯一命令行入口**——交互式 TUI 与全部非交互命令都在这一个包里，引擎二进制随包自动分发（Windows / Linux / macOS，x64 与 arm64）。

```
npm install -g @fengqiao666/sitelens-cli
sitelens                      # 交互式 TUI（选功能）
sitelens scan https://example.com --level deep
```

## 能做什么

- 7 档语义化扫描：quick / standard / deep / full / assets（资产测绘）/ stealth（隐匿）/ apocalypse（毁天灭地，仅授权目标）
- 指纹识别、验证型 check（每条命中带可重放证据链）、DAST 参数级探测、目录/子域/WebShell/端口服务、TLS/DNS 安全检测
- 源码静态审计（污点分析 + 规则匹配）
- 本机诊断：资产就位矩阵 / 当前降级能力 / 最近失败记录
- 5.0 ML 深度融合（需引擎资产，见下）：cve-tech 产品先验实时改变 check 执行顺序与覆盖，结果里 `extras.ml_prior` 全程可解释
- 扫描历史落 `~/.sitelens/data/state`，跨次运行保留

## 命令一览

命令清单的**唯一事实源**是 [`src/commands.mjs`](src/commands.mjs)——`sitelens --help` 由它生成，不另写一份（两处维护必然漂移）。

### 常用

| 命令 | 用途 |
|------|------|
| `sitelens` | 交互式 TUI：选功能（扫描 / 源码审计 / 诊断 / 历史） |
| `sitelens scan <url>` | 非交互扫描：进度与事件走 stderr，`--json` 完整结果走 stdout，管道 / CI 友好 |
| `sitelens audit <目录>` | 源码静态审计（相对路径按当前工作目录解析） |
| `sitelens doctor` | 本机诊断：资产就位 / 降级能力 / 最近失败（`--json` 输出完整诊断包） |
| `sitelens history` | 扫描历史列表 |
| `sitelens verified` | 跨扫描的已验证发现汇总 |
| `sitelens serve` | 引擎 Web 控制台直通（参数原样传递） |

### 高级（运维 / 进阶）

| 命令 | 用途 |
|------|------|
| `sitelens update <目标>` | 更新数据资产：`nuclei` / `afrog` / `fp` / `ehole` / `nvd` / `osv` / `tplintel` |
| `sitelens correlate <black> <white>` | 黑白盒事实图关联（合并两张图并建证据链） |
| `sitelens graph-read <file>` | 读取结构化事实图（摘要 / `--self-test` 契约自检） |
| `sitelens regression <scan_id>` | 验证回归：重放历史扫描的已验证发现（退出码表达回归） |
| `sitelens migrate-pg` | 历史库一次性迁移（PG → 本地文件） |

## 用户区

npm 线没有安装目录可写，所有可再生数据与状态都落在 `~/.sitelens/`：

| 路径 | 内容 |
|---|---|
| `~/.sitelens/config.yml` | TUI 管理的配置（数据路径段） |
| `~/.sitelens/data/` | 数据资产（指纹库 / 情报 / 模板池 / 字典 / ML 模型） |
| `~/.sitelens/data/state/` | 扫描历史（`store.data_dir`） |
| `~/.sitelens/.seed-manifest.json` | 种子交付版本记录 |

首次运行（或引擎版本变化后）会自动把**平台包内置的指纹库**交付到用户区——复用引擎自带的 `update-seed`，按引擎版本收敛：版本变化才覆盖，同版本二次启动是 no-op。

> `config.yml` 由 TUI 管理（幂等重写）。需要长期自定义请改用环境变量或桌面版配置文件。

## 引擎二进制解析顺序

1. 环境变量 `SITELENS_ENGINE`
2. 随包平台包 `@fengqiao666/sitelens-<平台>-engine`（安装时按 os/cpu 自动选择，包内二进制命名 `SiteLens_<平台>_engine_<版本>`）
3. PATH 中的 `sitelens`

## 还不能做什么（如实）

- **漏洞情报关联默认不可用**：情报库属于内部资产，不随 npm 分发。自备数据（`intel_dump.json.gz` 等放置到 `~/.sitelens/data/`）或使用桌面安装器版可获得完整情报关联
- **ML 模型资产默认不随包**：包内引擎在检测到 `~/.sitelens/data/go/ml_assets`（cve-tech/cwe-type）时自动启用 ML 融合，否则静默跳过（主流程零影响）。资产可从 [ml-models-v1 Release](https://github.com/feng-qiao/sitelens/releases/tag/ml-models-v1) 获取后按引擎配置路径放置
- 利用级无害验证、登录爆破等主动能力默认关闭，须在引擎配置显式开启

## 授权与责任

扫描仅可用于你有授权的目标。本工具按 GPL-3.0 开源，使用者的合规责任自负；gov.cn 目标存在代码级硬保护，不可绕过。

项目主页：<https://cnb.cool/feng-qiao/sitelens> · Issue 直接提在仓库。
