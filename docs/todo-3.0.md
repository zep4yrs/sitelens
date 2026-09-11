# 3.0 利用器（Exploit Validation）开发 TODO

> 立项 2026-09-12。主体代码 0 行，五块地基已在库内（见 P0 前置清单）。
> 本文件是唯一进度口径；做完一项勾一项，数字改动必须来自命令实测。
> 总红线：利用验证全程无害——不落盘、不提权、不持久化、不留驻；
> 一切主动能力默认关 + 授权闸（对齐 loginbrute 先例）。

## P0 前置：已存在、直接复用的地基（不重做）

- [x] 多请求模板 + extractor 抽取变量贯通（`Match.Extracts` + respEnv vars）
- [x] `compare_versions` 版本比较（利用前置条件判定可直接用）
- [x] 出带回调通道（`internal/beacon`，进程内注册表 /b/<token>）
- [x] dsl 安全子集求值器（`internal/dsl`，Compile 准入 + Eval 求值，96%+ 覆盖）
- [x] 最接近非 HTTP 的现存代码（`internal/netsec` TLS 证书解析、
      `internal/modules/serviceprobe.go` 端口服务探测）

## P1 非 HTTP 协议检测（先行的地基，不依赖利用语义设计）

- [ ] 新包 `internal/netx`：原始拨号层
  - [ ] TCP 连接 + 可选 TLS 握手（SNI/跳过校验可配）+ 超时/重试与 httpx 同语义
  - [ ] DNS 查询（A/AAAA/TXT/CNAME/MX，走 net.Resolver 自定义 Dialer）
  - [ ] UDP 发收（单轮即可，v1 不做会话跟踪）
  - [ ] 目标安全闸复用 `internal/target`：协议白名单扩展（tcp/dns/ssl）、
        保留地址拒绝、DNS 逐 IP 复检——缺一不可
- [ ] 模板漏斗准入（`internal/nuclei` convertAny）
  - [ ] 解析 network（tcp）/ dns / ssl 三类 request 形态 → 转 Check
  - [ ] 漏斗同名校验、索引缓存 schema 递增（v5 → v6）
  - [ ] `update-nuclei` 镜像范围加官方库 network/dns/ssl 目录
- [ ] dsl 求值环境扩展
  - [ ] 原始响应变量（response 字节/按行/status 文本）
  - [ ] 多轮交互（send/receive 对，extractor 在轮间传变量——沿用 respEnv 机制）
- [ ] 编排路由（`internal/engine`）
  - [ ] serviceprobe 探得的非 Web 服务端口 → 协议模板调度（Select 口径不变）
  - [ ] 扫描执行段（前端 11 段）加「协议模板」一段，实时事件流可见
- [ ] 验收：靶场加一个非 HTTP 服务（如 redis/ftp banner），零误报断言入
      `tools/regression_nightly.sh`；漏斗计数实测更新（官方 network/dns/ssl
      约一千余条预期入池）

## P2 利用级无害验证（影响证明层）

- [ ] 利用前置判定：命中 → 版本/指纹比对（affected_ranges.json + compare_versions）
      决定「可尝试利用」，不可验证的直接跳过并在结果里说明原因
- [ ] 影响证据三通道（全部复用现有机制，不新增出网面）
  - [ ] 回显通道：payload 响应携带可控标记（对齐 dast 反射判定）
  - [ ] 时延通道：sleep 类差分（对齐时间盲注既有实现，阈值复用）
  - [ ] 出带通道：`internal/beacon` 注入 + 回连命中记录
- [ ] `Hit` 结果模型扩展：impact 字段（none/observed/proven）+ 影响证据明细，
      证据链四件套（请求/响应/信号/复现命令）规格不变直接沿用
- [ ] 利用模板形态：2.0 多请求模板语义之上加 `impact:` 段声明判定式
      （dsl 子集内表达式，不得引入新函数面）
- [ ] 授权闸：config exploit 段（enabled 默认 false + authorized_targets），
      UI 工作台内开关带授权标注；未授权目标命中利用段一律降级为「仅验证」
- [ ] 验收：靶场对每个利用通道各有一条正例 + 一条不可利用反例；
      未授权路径零利用请求断言（从 httpx 请求日志层数）

## P3 验证回归（可重放、可断言）

- [ ] replay：单条已验证发现一键重放（serve API + CLI 子命令），
      复用复现命令构造器，产出新旧证据 diff
- [ ] 批量回归：`sitelens` 子命令按 history.json 圈定历史命中重跑，
      退出码表达回归率（0 = 全复现）；靶场门禁脚本先接入
- [ ] CI：regression_nightly.sh 加利用级断言（P2 靶场正例全 proven、
      反例全 none）
- [ ] 验收：双扫描 diff 报告里「新增/消失/回归」三类计数有端到端测试

## P4 收尾与发布

- [ ] 文档：开发文档 14 节改为「已落地」实况；README 路线图 3.0 行标 ✅；
      CHANGELOG v3.0.0（Bug 修复段一并记录）
- [ ] 全量测试 + govulncheck + fuzz 轮次照 2.0 口径重跑
- [ ] 发行：tag + 三端同步（CNB/GitHub/Gitee）+ 发行说明；
      push 逐次确认（老规矩）

## 顺序与依赖

P1 → P2 → P3 → P4 串行；P1 内部「netx 包」先行（其余项都依赖拨号层）。
P2 的授权闸模型照抄 loginbrute，不新发明。4.0（攻击链/黑白盒）在 P4 前
不动工。
