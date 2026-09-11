# 3.0 利用器（Exploit Validation）开发 TODO

> 立项 2026-09-12。主体代码 0 行，五块地基已在库内（见 P0 前置清单）。
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
