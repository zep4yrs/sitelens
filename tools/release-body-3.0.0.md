# SiteLens v3.0.0 — 利用器（Exploit Validation）

从证明漏洞真实存在，到证明漏洞能够影响。

3.0 在 2.0 验证器的证据链之上补齐「影响证明」层，并把检测面从 HTTP 扩展到非 HTTP 协议。全部利用级探针保持无害红线：不落盘、不提权、不持久化；授权闸默认关。

## 非 HTTP 协议检测

- 原始拨号层 `internal/netx`：TCP / TLS / UDP / DNS 收发（读写 deadline、单次读取上限、轮次上限、TLS 基线 1.2）
- 协议安全闸：`internal/target.ValidateHostPort`——协议白名单、字面 IP 无条件拦截、域名逐 IP 校验
- 模板漏斗准入 tcp / dns / ssl 三类协议模板（官方库 network/dns/ssl 目录 94 条入池，随 update-nuclei 自动镜像）
- 引擎编排：serviceprobe 探得的服务端口按模板声明端口路由，dns 模板查目标域名；命中进入实时事件流与结果 Extras

## 利用级无害验证

- 判定诚实分级：none / observed / proven——拿不出影响证据就报 none
- 四通道：回显（唯一标记未转义复现）、报错指纹（DBMS+版本提取）、时延差实测、出带回连（内置 beacon）；LFI 泛化读取
- 授权三重闸：请求开关 × config `exploit.enabled`（默认关）× 目标白名单（`*.domain` 仅匹配子域）
- 硬断言：未授权目标零请求（测试固化）

## 验证回归

- `sitelens regression <scan_id>`：按原 payload 重放历史发现，present / gone / unsupported 三分（不可复现项不进回归分母），退出码表达回归
- `GET /api/replay/{id}`：同能力 API
- 靶场夜间门禁（regression_nightly.sh）加入重放断言步

## 数据规模（随本版发行）

- 全库可运行模板 **117,675 条**：官方 nuclei-templates + afrog + Wordfence CVE 镜像 + linuxadi/40k 聚合 + coffinxp + UltimateSec 极致攻防，统一漏斗准入
- 指纹库 **2,749 条**：自建精编 372 + enthec/webappanalyzer（GPL-3.0）社区指纹 2,377，附 463 条 name→CPE 映射
- NVD CVE 字典全量镜像（update-nvd，旁路文件）：CVE 详情 / CVSS 补全 / 检索面
- 模板情报层：模板池 CVE 元数据进索引，情报关联直接给出「可跑模板」路径

## Bug 修复

- dsl PositiveGround 回归：内置 host 变量被误标为抽取变量，`contains(host,"x")` 被误判为正向命中依据——known 现仅标抽取变量
- 指纹加载器加固：单条 RE2 不兼容模式跳过，不再中断整个扫描进程

## 质量

- 28 包 54+ 测试文件全绿；CI `-race` 门禁；govulncheck 零发现
- 模板转换漏斗 / dsl 求值器 / netx 报文解析面 fuzz 覆盖
- 靶场回归门禁：零误报 + 真实命中 + 重放断言

## 合规声明

- 授权闸默认关；利用级验证仅对 `exploit.authorized` 白名单内目标发起
- 全部数据源为公开渠道；情报库本体为私有 Release 资产不随源码分发
- GPL-3.0 开源
