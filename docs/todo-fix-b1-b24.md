# 修复 TODO（Mimosa 深度审计 B1–B24，2026-09-12）

来源：容器内 go1.26.8 实跑审计（与 CI 镜像一致），24 项可复现缺陷，每项含最小复现。
顺序按审计建议：**B1 → B8 → B2 → B3 → B4/B5 → B9/B10 → 其余**。
每批完成门禁：`gofmt -l` 为空、`go vet`、`go test -count=1` 全量、CI `-race`、Mimosa 复扫。

## 第一批（CI 阻断 + 零误报承诺）

- [x] **B1 gofmt 门禁红**（阻断，方案 A）：`gofmt -w` 三个文件（fpmerge/ehole.go、sitelens/fingerprint.go、sitelens/bench_test.go，字段对齐差异），独立提交。验证：`gofmt -l internal/ cmd/` 为空，CI 后续 vet/test/race/govulncheck 恢复执行
- [x] **B8 情报误报 confirmed**（方案 C = A + 数据侧）：`versioncmp.Parse` 前置校验版本号形态——段内含字母且非纯数字前缀（如 `14c49408…`）判不可比，`VersionIn` 返回 false；数据侧 intel_dump 生成期剥离 hash 段。验证：`VersionIn("8.2.5","<=14c49408…")==false` 断言；`>=8.2.0,<8.2.7` 仍 true；grafana 复扫 CVE-2021-43798 不出 confirmed
- [x] **B2 软 404 基线口径**（方案 A）：`soft404Baseline` 与比对侧统一走同一 stripEcho 函数，长度比较两侧同源。验证：定长回显 404 桩从漏拦变拦截；干净站回归零误报
- [x] **B3 extractor 正则崩溃**（方案 C）：`extractSpecs` 加与 matcher 相同的 RE2 准入（失败丢弃该 extractor），`extractVars` 改 `Compile`+错误忽略；`FuzzConvert` 纳入 extractor 种子；用户插件 `exs` 字段同闸。验证：`(?=foo)bar` 合成模板不再 panic

## 第二批（安全 + 并发）

- [x] **B4 beacon 跨扫描串扰**（方案 A）：注册表改扫描级实例，token 绑扫描 ID，去掉全局 `Reset`。验证：并发双扫互不干扰
- [x] **B5 /b/ 端点无鉴权**（方案 C 最终形态）：beacon 来源限制 + 频率限制 + token 服务端签名。设计约束：**不能挡掉目标真实回连**（回连来自目标出网 IP，需可配置放行段）
- [x] **B9 checks.Workers 竞态**（方案 A）：去包级可变全局，改 `RunList` 参数 / `Options` 字段由引擎按扫描注入。验证：并发 `-race` 干净
- [x] **B10 LRU 落盘**（方案 A）：`nucleiLRU` 收归 Engine 实例 + `saveNucleiLRU` 改 tmp+rename
- [x] **B23 hAudit 上传无上限**：`r.Body` 加 `MaxBytesReader` 后再 `ParseMultipartForm`

## 第三批（一致性 + 修复）

- [x] **B6 .corrupt 覆盖**（方案 A）：隔离命名加时间戳/序号，保留每次损坏副本
- [x] **B7 缓存无界**（方案 C）：`regexCache` / `dslVarsCache` 加计数上限（对齐 dsl.go 策略）
- [x] **B11 timeBlind 证据链缺失**：Finding 补 Replay / Signals / Response / Payload，对齐 boolBlind 规格
- [x] **B12 RunForms 未接证据链**：补 chainEvidence + Payload/Replay——同时修正 replay 分母被静默排除的问题（回归门禁自证式通过的隐患）
- [x] **B13 HistoryStats 均值截断**：改四舍五入
- [x] **B14 done 计数重复累加**：命中分支与组尾分支只计一次
- [x] **B15 knownTopKeys 缺段**：补 `auth` / `ssrf` / `exploit`（合法段被误报"将被忽略"）
- [x] **B16 captcha health 路径猜测**：sidecar 地址不以 /ocr 结尾时探测打错路径，需显式 health 地址或容错
- [x] **B19 ssrf 轮询空转**：无 token 时缩短轮询；有 token 时避免早退漏报
- [x] **B20 serviceprobe 指纹缓存定死**：`globalFP sync.Once` 随热更新失效
- [x] **B24 netproto 与 HTTP 模板 cap 耦合**：协议模板调度上限独立配置

## 口径修正（非代码）

- [x] **B21 文档宣称与实测不符**：「11,966 条服务指纹」实测 700+ 条因 RE2 不兼容被拒，有效约 94%——开发文档与 CHANGELOG 改实测有效口径。**（后被 B25 覆盖：rex 兜底后 11,966 条全部有效，口径再修正回全量）**

## B25 服务指纹 RE2 不兼容模式全量兼容（2026-09-12 完成）

Go RE2 实测拒收 702 条（对 11,966 条逐一编译验证）：Perl 环视语法 683——其中
负向先行 `(?!...)` 671 条为主体、正向先行 `(?=...)` 20、后行 `(?<=...)` 2；
反向引用 `\1` 16 条；超界重复 `{899,1536}` 1 条（超出 RE2 的 1000 上限）。
机械转写不可行（负向先行是非正则构造），落地受限回溯引擎：

- [x] **受限回溯匹配器** `internal/rex`（parse.go + exec.go，CPS 连续传递）：
  nmap 指纹子集——字面量/字符类（含首位 `]` 字面量的 PCRE/RE2 规则）/dot/锚点
  （文本+行）/交替/捕获与非捕获组/量词 `* + ? {n,m}` 含懒惰/先行后行环视
  （肯定+否定）/反向引用 `\1`–`\9`/`\xHH` 转义/`(?i)` 等内联 flag；
  单次尝试 10 万步预算封顶，超限判不匹配（宁少报，不挂死扫描协程）；
  fpMatcher 编译时 RE2 失败者自动落到 rex，其余照走 RE2 快路径
- [x] 覆盖测试：rex 9 项单测（语义/空迭代终止/预算有界/编译报错）；
  RE2 一致性抽样 221 条（子匹配逐组比对标准库）；702 条被拒模式全量
  编译冒烟 + python re（独立回溯实现）golden 向量交叉验证
  702 模式 × 5,469 用例（命中 556），匹配存在性/整体文本/捕获组全一致
- [x] 验收：**702 条全部有效（零丢弃），服务指纹恢复全量 11,966**；
  开发文档口径同步（B21 的 94% 修正作废）

## 明确不修 / 已确认健康

- 池内 extractor 正则实测 0 触发（B3 为潜在缺陷，防御性修复）
- htmlx 表单解析、前端 `esc()` 全站覆盖、fpmerge 正则黑名单、dsl 缓存上限、.cnb.yml vendor/LANG 门禁——审计确认健康
- `-race` 本机无 cgo，以 CI 门禁为准（B9 修复后以 CI 绿为验收）
