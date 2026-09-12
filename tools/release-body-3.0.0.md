# SiteLens v3.0.0 — 利用器（Exploit Validation）

![SiteLens 3.0.0 利用器](assets/release-3.0.0.png)

发布日期：2026-09-12 ｜ 上个版本：[v2.0.0](../../releases/tag/v2.0.0) ｜ GPL-3.0

3.0 做了两件大事：把检测覆盖面摊开——模板池从 5,400+ 涨到 117,889 条并且全量调度，不再抽样；把验证往前推了一步——新增利用级无害验证，对授权目标不只报告"可能有问题"，还能给出"能否实际利用"的证据。利用级能力默认关闭，仅对配置白名单内的目标生效。

## 升级前必读

- 全量模板模式下扫描时长明显增加，日常巡检请选「标准」强度
- 数据来源已全部更换为公开渠道（afrog / xray / nmap / 微软 / CISA / NVD），旧情报库可删，替换文件随安装包与本仓库分发
- 利用级验证需显式开启（见下方"启用方法"），未配置时行为与 2.0 完全一致

## 新能力

**非 HTTP 协议检测**（214 条协议模板）
新增原始拨号层，直接对 tcp / dns / ssl 目标发探测收响应：Redis、FTP、SSH、VNC、MySQL、SMTP 等服务的 banner 级检测；端口服务探测发现开放端口后自动路由协议模板。

**利用级无害验证**
对已确认的发现做影响证明，四种方式：回显（唯一标记未转义复现）、报错指纹（提取数据库类型与版本）、时延差（实测响应延迟）、出带回连（内置 beacon）。结论分三档：proven（影响已证明）/ observed（观测到可利用面）/ none（未发现）。
默认关闭。开启需要三重条件：请求开关 + 配置总闸 + 目标白名单。白名单外目标零请求——这个行为有单元测试固化，不是口头承诺。

**验证回归**
`sitelens regression <scan_id>`：按原 payload 重放历史发现，输出 仍在 / 已修复 统计，退出码表达回归结果，可直接接 CI。交付验收、整改复测用。

**模板情报层**
情报关联的每条结论，现在会附上模板池里能实际验证它的模板路径——报告从"疑似"直接给出复验入口。

## 数据源增长

| 数据 | v2.0.0 | v3.0.0 |
|---|---|---|
| 可运行模板（全量执行） | 5,400+ | 117,889 |
| 协议模板（tcp/dns/ssl） | 0 | 214 |
| Web 指纹库 | 370 | 13,727 |
| 漏洞情报 | 11,024（含商业来源） | 31,539（全部公开来源） |
| NVD CVE 字典 | 无 | 371,755 |
| KEV 在野利用 | 1,695 | 1,709（自动更新） |

新增数据源：webappanalyzer（GPL-3.0）、EHole 中文产品指纹、linuxadi/40k 聚合、coffinxp、极致攻防、官方协议族。全部公开渠道，商业来源数据已清除出库。

## Bug 修复

- 排除式模板被错误调度、空转浪费扫描时间
- 首次扫描卡在索引重建上不动
- 单条不兼容社区指纹导致整个扫描进程退出
- NVD 镜像等长任务静默无进度输出

## 性能

13,727 条指纹规则下单页匹配 **24.2ms**（上一版同规模实现为 413ms）。靠的是字面量前缀桶预筛：正文只扫一遍，替代逐条 Contains。基准固化在 `internal/sitelens/bench_test.go`。

## 靶场实测

六扫描并行（DVWA full + apocalypse、pikachu、sqli-labs、upload-labs、xsslabs），授权靶场、限速关闭、16 并发，全量模板执行：

| 靶场 | 强度 | 耗时 | 已验证发现 |
|---|---|---|---|
| DVWA（认证） | full | 1,378s | 29 |
| sqli-labs | full | 1,704s | 21 |
| xsslabs | full | 1,037s | 16 |
| DVWA | apocalypse | 401s | 10 |
| pikachu | full | 2,363s | 67 |
| upload-labs | full | 1,995s | 13 |

六扫合计 **156 条已验证发现**，全部带证据链与复现命令，扫描期间无人工干预。pikachu 以 67 条命中居首（SQLi 注入点 + 技术指纹长尾），upload-labs 的 13 条以模板探测为主。

## 下载哪个

- Windows 常规使用 → `setup-full.exe`（推荐，开箱即用）
- 先试用 / 磁盘紧张 → `setup-lite.exe`（之后用 `update-*` 在线补数据）
- 免安装 → `full-win64.zip`
- Linux amd64 → `linux-amd64.zip`
- 流水线 / 二次分发 → `intel_dump.json.gz`、`nuclei-templates.tar.gz`、`tpl_intel.json.gz`

内存建议 8GB 起；full 版磁盘约 1GB。SHA256 校验和由 CI 构建后发布于本页评论。

**升级与回滚**：`.sitelens.yml` 与 `data/state/` 完全兼容，覆盖安装即可；回滚换回 v2.0.0 二进制，数据无需迁移。详细步骤见 [升级指南](docs/upgrade-3.0.md)。

## 如何启用利用级验证

```yaml
exploit:
  enabled: true
  authorized:            # 只写你有权测试的目标；*.domain 仅匹配子域
    - "lab.example.com"
    - "*.client-lab.cn"
```

扫描页勾选「利用级验证」即可。不开，行为与 2.0 一致。

## 已知限制

- 反序列化检测是入口面信号（低危），不是漏洞级确认
- 协议检测 v1：UDP 单轮收发，ssl 客户端基线 TLS 1.2
- NVD 全量镜像约 50 分钟（无 API key），建议低峰执行
- EHole 社区指纹 conf 70 分层，准确率低于精编规则

## 致谢

检测数据与思路站在这些开源项目的肩膀上：[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)、[afrog](https://github.com/zan8in/afrog)、[Wordfence](https://www.wordfence.com/)、[webappanalyzer](https://github.com/enthec/webappanalyzer)、[EHole](https://github.com/EdgeSecurity/EHole)、[nmap](https://nmap.org/)、FingerDir，以及 CISA KEV 与微软安全公告。

## 协议与反馈

GPL-3.0 分发，完整条款见 LICENSE。仅限对自有或已获书面授权的目标使用，利用级能力默认关闭。

问题反馈请到仓库 Issues；文档见 `docs/`（产品说明 / 开发文档 / 升级指南），完整变更清单见 [CHANGELOG](CHANGELOG.md)。
