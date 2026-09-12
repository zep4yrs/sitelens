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

- [ ] **B4 beacon 跨扫描串扰**（方案 A）：注册表改扫描级实例，token 绑扫描 ID，去掉全局 `Reset`。验证：并发双扫互不干扰
- [ ] **B5 /b/ 端点无鉴权**（方案 C 最终形态）：beacon 来源限制 + 频率限制 + token 服务端签名。设计约束：**不能挡掉目标真实回连**（回连来自目标出网 IP，需可配置放行段）
- [ ] **B9 checks.Workers 竞态**（方案 A）：去包级可变全局，改 `RunList` 参数 / `Options` 字段由引擎按扫描注入。验证：并发 `-race` 干净
- [ ] **B10 LRU 落盘**（方案 A）：`nucleiLRU` 收归 Engine 实例 + `saveNucleiLRU` 改 tmp+rename
- [ ] **B23 hAudit 上传无上限**：`r.Body` 加 `MaxBytesReader` 后再 `ParseMultipartForm`

## 第三批（一致性 + 修复）

- [ ] **B6 .corrupt 覆盖**（方案 A）：隔离命名加时间戳/序号，保留每次损坏副本
- [ ] **B7 缓存无界**（方案 C）：`regexCache` / `dslVarsCache` 加计数上限（对齐 dsl.go 策略）
- [ ] **B11 timeBlind 证据链缺失**：Finding 补 Replay / Signals / Response / Payload，对齐 boolBlind 规格
- [ ] **B12 RunForms 未接证据链**：补 chainEvidence + Payload/Replay——同时修正 replay 分母被静默排除的问题（回归门禁自证式通过的隐患）
- [ ] **B13 HistoryStats 均值截断**：改四舍五入
- [ ] **B14 done 计数重复累加**：命中分支与组尾分支只计一次
- [ ] **B15 knownTopKeys 缺段**：补 `auth` / `ssrf` / `exploit`（合法段被误报"将被忽略"）
- [ ] **B16 captcha health 路径猜测**：sidecar 地址不以 /ocr 结尾时探测打错路径，需显式 health 地址或容错
- [ ] **B19 ssrf 轮询空转**：无 token 时缩短轮询；有 token 时避免早退漏报
- [ ] **B20 serviceprobe 指纹缓存定死**：`globalFP sync.Once` 随热更新失效
- [ ] **B24 netproto 与 HTTP 模板 cap 耦合**：协议模板调度上限独立配置

## 口径修正（非代码）

- [ ] **B21 文档宣称与实测不符**：「11,966 条服务指纹」实测 700+ 条因 RE2 不兼容被拒（685 lookaround + 16 backref），有效约 94%——开发文档与 CHANGELOG 改实测有效口径

## 明确不修 / 已确认健康

- 池内 extractor 正则实测 0 触发（B3 为潜在缺陷，防御性修复）
- htmlx 表单解析、前端 `esc()` 全站覆盖、fpmerge 正则黑名单、dsl 缓存上限、.cnb.yml vendor/LANG 门禁——审计确认健康
- `-race` 本机无 cgo，以 CI 门禁为准（B9 修复后以 CI 绿为验收）
