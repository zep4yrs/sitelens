<div align="center">

# 🔍 SiteLens 站点透视

**验证型 Web 站点安全评估平台 · 单二进制交付 · 零外部依赖**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Tests](https://img.shields.io/badge/%E6%B5%8B%E8%AF%95-passing-brightgreen)]()
[![Release](https://img.shields.io/badge/release-v1.0.0-0074D9)]()
[![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux-supported-blueviolet)]()

*输入网址 · 看穿技术栈 · 验证漏洞 · 输出证据*

372 条精编指纹 · 11024 条漏洞情报 · 5400+ 可运行模板 · 8 页本地控制台

</div>

---

## ✨ 核心能力

| 能力 | 说明 |
|---|---|
| 🔬 **验证优先** | 每条发现经**二次确认重放**，附**证据链**：重放请求、响应快照、通道命中信号、curl 一键复现 |
| 🧬 **指纹识别** | 372 条精编规则（响应头/Cookie/Meta/HTML/脚本/icon_hash favicon 哈希），主动路径指纹探测 |
| 💉 **DAST 主动探测** | 反射 XSS / 报错 SQLi / 开放重定向 / 路径穿越 / **时间型与布尔差分盲注**（双确认） |
| 🌐 **SSRF 出带确认** | 自托管回调 beacon（默认关），目标回连即出带确认，不依赖外部服务 |
| 🕵️ **403 绕过探测** | 路径变异 × 信任头 × 改写头 × HEAD/OPTIONS 变体表，命中即报"访问控制可被绕过" |
| 📡 **漏洞情报关联** | 11024 条情报 + CVSS v3.1 评分 + OSV 在线同步 + KEV 在野利用标记，三级判定（确认/可能/不受影响） |
| 🗂️ **目录 / 子域 / 接管** | 软 404 基线过滤 + 回显剔除；子域 DNS 枚举 + 接管指纹探测 |
| 🔐 **登录爆破审计** | 弱口令字典 + 验证码识别 sidecar 接口，**仅限授权目标**，前端需勾选授权确认 |
| 📊 **批量与历史** | 多目标批量扫描、历史记录、双扫描 diff、漏洞检索、Wappalyzer 风格宽表导出（JSON/CSV/HTML/MD） |
| 🧱 **白盒源码审计** | TAINT 污点分析引擎 + 规则库，命令行 `audit` 一键出报告 |

## 🚀 快速开始

### 图形化安装（推荐）

从 [Release](../../releases) 下载 `SiteLens-1.0.0-setup-full.exe`，双击按向导安装：
开始菜单 / 桌面快捷方式、完成即启动、自带完整卸载器。

### 便携包

下载 `SiteLens-1.0.0-full-win64.zip` 解压即用，双击 `sitelens.exe`。

### 源码构建

```bash
go build -o sitelens.exe ./cmd/sitelens
./sitelens.exe serve            # Web 控制台（默认 http://127.0.0.1:5000）
./sitelens.exe scan <url>       # 命令行全流水线扫描，JSON 输出
```

<details>
<summary><b>🧰 更多运行方式</b></summary>

```bash
# Docker（多阶段构建，distroless 静态镜像；扫描目标勿写 localhost）
docker build -t sitelens .
docker run --rm -p 5000:5000 -v sitelens-state:/app/data/state sitelens

# 模板 / 情报库更新
./sitelens.exe update-nuclei    # 镜像官方 Nuclei 模板库
./sitelens.exe update-afrog     # 镜像 afrog 社区 POC 库
./sitelens.exe update-osv       # 从 OSV.dev 同步影响区间与 CVSS
```

</details>

## 🎯 扫描模式

| 模式 | 定位 |
|---|---|
| `quick` | 快速面（核心验证集，分钟级） |
| `standard` | 标准面（爬虫 + 指纹 + 基础 DAST） |
| `deep` | 深度面（扩展验证集 + headless 渲染） |
| `full` | 全流水线（Nuclei 模板子集 + 全模块） |
| `assets` | 资产测绘（子域 / 端口 / 服务面） |
| `stealth` | 隐匿穿 WAF（限速 + 指纹伪装姿态） |
| `apocalypse` | 毁天灭地（全模块 + 大模板量，仅限授权目标） |

## 🧪 工程质量

- ✅ **23 个包单元测试** + `-race` 竞态门禁（CI 阻断级）
- ✅ **govulncheck 依赖漏洞扫描**门禁，当前零发现
- ✅ **靶场实弹校准**：DVWA / pikachu / sqli-labs / upload-labs / xsslabs 真实缺陷命中，干净站零误报 × 2
- ✅ **百万次级 fuzz** 的转换漏斗与 DSL 安全子集求值器
- ✅ **靶场回归门禁脚本**：`tools/regression_nightly.sh`（农场→矩阵→零误报断言）

## 🗺️ 路线图

```
1.0 发现器 ✅ ──▶ 1.5 验证强化 🚧 ──▶ 2.0 验证器 ──▶ 3.0 利用器 ──▶ 4.0 审计器
   指纹+情报+DAST    证据链/盲注/      证据链全覆盖      利用级无害证明    AST 数据流
   七种模式          出带确认/认证态    反序列化探测      影响面量化       CWE 全集
                                       回归 CI 化        利用链推导       黑白联动
```

## 📚 文档

| 文档 | 内容 |
|---|---|
| [产品说明](docs/产品说明.md) | 安装包版本区别、配置项、使用指引 |
| [开发文档](docs/开发文档.md) | 架构、包结构、二次开发说明 |

---

<div align="center">

**⚠️ 合规声明**

本工具仅限对**自有或已获书面授权**的目标使用，全程只读无害验证，主动能力默认关闭且有硬上限。<br>
对未授权目标使用属违法行为，后果由使用者自负。

**SiteLens** · fengqiao · 用 ❤ 与 Go 构建

</div>
