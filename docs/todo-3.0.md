# 3.0 利用器（Exploit Validation）开发 TODO

> 立项 2026-09-12。P0–P5 已于同夜完成（提交 ff3fa9d…f6acfe2），P6 停在
> tag/push 逐次确认前。Mimosa 深度审计 0 发现（封印 sha256:52ab3780…）；
> go test 全量绿；govulncheck 零发现；fuzz 过；-race 本机无 cgo 走 CI 门禁；
> 真机 serve 冒烟过（3.0.0 / NVD 371,755 / 指纹 2,749 / KEV 1,709）。
> 原始状态：主体代码 0 行，五块地基已在库内（见 P0 前置清单）。
> 本文件是唯一进度口径；做完一项勾一项，数字改动必须来自命令实测。
> **完成口径：P0–P6 全部勾完 = 可直接走完发布流程，无隐藏步骤。**
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

- [x] 新包 `internal/netx`：原始拨号层
  - [x] TCP 连接 + 可选 TLS 握手（TLS 基线 1.2）+ 超时与 httpx 同语义
  - [x] DNS 查询（A/AAAA/TXT/CNAME/MX/NS，PreferGo + 超时上下文）
  - [x] UDP 发收（单轮，v1 无会话跟踪）
  - [x] 目标安全闸复用 `internal/target`：ValidateHostPort（tcp/tls/udp/dns 白名单 + 字面 IP 无条件拦截 + 域名 resolve 开关逐 IP）
- [x] 模板漏斗准入（`internal/nuclei` ConvertNetwork）
  - [x] 解析 network（tcp）/ dns / ssl 三类形态 → NetCheck（payloads/hex/banner、dns 查询、ssl 证书摘要）
  - [x] 漏斗同名校验、索引缓存 schema 递增（v6 → v7）
  - [x] `update-nuclei` 镜像范围加官方库 network/dns/ssl 目录（94 条入池）
- [x] dsl 求值环境扩展（response 变量经 CompileWithVars 注入，零改 dsl 包）
  - [x] 原始响应变量（response 经 VarSource 注入；body 同指响应全文）
  - [x] 多轮交互（payloads 依次 Send+Recv，响应拼接参与匹配；轮次上限 4）
- [x] 编排路由（`internal/engine/netproto.go`）
  - [x] serviceprobe 探得端口按「模板声明端口=探测端口」路由，dns 查域名；严重度优先全量调度
  - [x] stage9 协议扫描段 + 实时事件流 emit("hit")；命中落 Extras["netproto"]（前端面板渲染随发版前端批）
- [x] 验收：伪 redis（loopback）端到端命中断言（netrun_test）；官方协议族
      实测 94 条入池（低于预估千级：官方 network/dns/ssl 目录本身即此量级）；
      全库计数实测 117,883；regression_nightly 已接重放门禁

## P2 利用级无害验证（影响证明层）

- [x] 利用通道分派按 dast check id（xss-reflect/sqli-error/sqli-blind-time/open-redirect/lfi-passwd/ssrf-oob）；
      版本区间前置判定（affected_ranges × compare_versions）留在 vuln_kb confirmed 语义内，
      NVD CPE 通道按 possible 出行（区间推导 3.1）
- [x] 影响证据通道（全部复用现有机制，不新增出网面）
  - [x] 回显通道：唯一标记未转义复现（XSS）+ 报错 DBMS 指纹提取（SQLi）
  - [x] 时延通道：基线/注入双实测差值 ≥ 阈值（config delay_threshold_ms，默认 3000）
  - [x] 出带通道：全新 token 注入 + PollFor 回连窗口（beacon 复用）
- [x] verified map 增 impact / impact_evidence 键（异构 map 免迁移）；证据链四件套沿用；
      Extras["exploit"] 汇总 proven/observed 计数
- [x] 利用判定式实现为 Prover 通道函数（编译期语义、更可控）；`impact:` 模板段
      推迟到协议/利用模板统一格式化（3.1，避免两处 DSL 漂移）
- [x] 授权闸：config exploit 段（enabled 默认 false + authorized），`*.domain` 仅子域从严；
      请求开关 × 总闸 × host 白名单三重校验；UI 开关随发版前端批
- [x] 验收：exploit 包八测（各通道正例 + 反例 + 无 beacon/未知类别）；
      未授权零请求断言（engine 层 http 计数器实测 0）

## P3 验证回归（可重放、可断言）

- [x] replay：internal/replay 单条重放 + GET /api/replay/{id} + regression CLI；
      present/gone/unsupported 三分，unsupported 不进回归分母（诚实口径）
- [x] 批量回归：`sitelens regression <scan_id>` 退出码 0/1/2（无回归/有回归/记录不存在）
- [x] regression_nightly.sh 3.5 步重放门禁（最近扫描全量重放，退出码并入总断言）
- [x] 验收：replay 包四测（present/gone 转换、批量统计、unsupported 分母、缺 payload）

## P4 收口（文档与数据，全对齐实测值）

- [ ] 版本号定稿 3.0.0：版本常量 / UA 字符串 / 产物名全部对齐
      （照 2.0 定稿动作：文档、产物名一次改齐，不留 preview/RC 残留）
- [ ] CHANGELOG v3.0.0：新能力逐条全录 + **Bug 修复段**
      （P1–P3 过程中的修复随手回填，不许发版前补写）
- [ ] 发行说明文件 `tools/release-body-3.0.0.md`（Markdown，CI 接文件上传）
- [ ] README：路线图 3.0 行标 ✅、当前版本标记移到 3.0；工程质量段数字
      实测更新（包数/测试文件数/模板池规模）；能力矩阵加 3.0 能力行；
      主视觉换预置的 `assets/banner-3.0-exploit.png`
- [ ] docs/产品说明.md 同步 3.0 能力；docs/开发文档.md 14 节改「已落地」实况
- [ ] 数据资产：情报库如刷新则同步 Release 私有资产；full 版模板库打包清单
      加 network/dns/ssl 目录（文件数实测写死进 CI，防体积失控无感）

## P5 质量门禁（全绿才准进 P6）

- [ ] `go test ./...` 全绿（新增 netx/exploit 相关包各带单元测试，与 52 文件基线合并计数）
- [ ] CI `-race` 竞态门禁绿
- [ ] govulncheck 零发现（P1 若引入新依赖，全量重扫）
- [ ] fuzz 轮次照 2.0 口径：模板转换漏斗 + dsl 求值器 + **新增 netx 报文解析面**
- [ ] 靶场回归双断言绿（零误报 + 真实命中）+ P2 利用级正反例断言 + 未授权零利用请求断言
- [ ] Mimosa 深度审计收口（commit 前完整扫描结论，发现清零或逐项闭环）
- [ ] 真机 e2e：授权目标全流水线跑通一遍，含「协议模板」段与 replay

## P6 发布流程（照 2.0 实际走法，坑位已标）

- [ ] 提交纪律：`git add` 逐文件点名（**禁 `git add -A`，会卷临时文件**）；
      测试验证与 commit 分开跑（**管道吞退出码，红着提交坑**）
- [ ] 提交身份核对：QQ 邮箱 + 姓名统一
- [ ] 恢复 tag 自动构建（日常处于暂停态，2.0 同款操作）
- [ ] CI 全链绿：lite/linux 阶段 + NSIS 安装包
      （**makensis 必须 LANG=C.UTF-8，否则中文文件名段错误**）
      + full 版内置模板库与情报库
- [ ] 产物核对：安装包/绿色版齐全，文件名版本号 3.0.0 对齐，校验和一致
- [ ] tag v3.0.0 + 三端 push **逐次确认**（CNB → GitHub → Gitee；
      GitHub 公开时间窗由用户决定）
- [ ] Release 挂发行说明：CI 环境变量用命令级前缀
      （**export 行独立 shell 不生效坑，2.0 踩过：发行说明为空**）
- [ ] 发布后验证：三端 Release 页资产可下载；安装包本机装完能起 serve、
      能跑通一次含协议模板的扫描；README 徽章/链接指向正确
- [ ] 收尾：tag 自动构建重新暂停；预置 4.0 宣发图位（路线图不动）

## 顺序与依赖

P1 → P2 → P3 串行开发；P4 文档收口可与 P3 并行；
P5 门禁全绿是 P6 的硬前置，缺一项不发。
P1 内部「netx 包」先行（其余项都依赖拨号层）。
P2 的授权闸模型照抄 loginbrute，不新发明。
4.0（攻击链/黑白盒）在 P6 完成前不动工。
