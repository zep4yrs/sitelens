# @fengqiao666/sitelens-cli

SiteLens 站点透视的终端扫描台：交互式 TUI + 非交互 CLI，引擎二进制随包自动分发（Windows / Linux / macOS，x64 与 arm64）。

```
npm install -g @fengqiao666/sitelens-cli
sitelens                 # 交互式 TUI
sitelens scan https://example.com --level deep
```

## 能做什么

- 7 档语义化扫描：quick / standard / deep / full / assets（资产测绘）/ stealth（隐匿）/ apocalypse（毁天灭地，仅授权目标）
- 指纹识别、验证型 check（每条命中带可重放证据链）、DAST 参数级探测、目录/子域/WebShell/端口服务、TLS/DNS 安全检测
- 5.0 ML 深度融合（需引擎资产，见下）：cve-tech 产品先验实时改变 check 执行顺序与覆盖，结果里 `extras.ml_prior` 全程可解释
- 扫描历史落 `~/.sitelens/data`，跨次运行保留

## 三种入口

| 命令 | 用途 |
|------|------|
| `sitelens` | 交互式 TUI：目标输入 → 模式选择 → 实时进度与事件流 → 摘要 |
| `sitelens scan <url>` | 非交互：进度/事件走 stderr，`--json` 完整结果走 stdout，管道/CI 友好 |
| `sitelens serve` | 引擎 Web 服务直通（复用包内引擎，参数原样传递） |

## 引擎二进制解析顺序

1. 环境变量 `SITLENS_ENGINE`
2. 随包平台包 `@fengqiao666/sitelens-<平台>-engine`（安装时按 os/cpu 自动选择，包内二进制命名 `SiteLens_<平台>_engine_<版本>`）
3. PATH 中的 `sitelens`

## 还不能做什么（如实）

- **漏洞情报关联默认不可用**：情报库属于内部资产，不随 npm 分发。自备数据（`intel_dump.json.gz` 等放置到引擎数据目录）或使用桌面安装器版可获得完整情报关联
- **ML 模型资产默认不随包**：包内引擎在检测到 `data/go/ml_assets`（cve-tech/cwe-type）时自动启用 ML 融合，否则静默跳过（主流程零影响）。资产可从 [ml-models-v1 Release](https://github.com/feng-qiao/sitelens/releases/tag/ml-models-v1) 获取后按引擎配置路径放置
- 利用级无害验证、登录爆破等主动能力默认关闭，须在引擎配置显式开启

## 授权与责任

扫描仅可用于你有授权的目标。本工具按 GPL-3.0 开源，使用者的合规责任自负；gov.cn 目标存在代码级硬保护，不可绕过。

项目主页：<https://cnb.cool/feng-qiao/sitelens> · Issue 直接提在仓库。
