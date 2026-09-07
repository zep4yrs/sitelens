# 更新日志

## 未发布（预览版追加）

- 爬虫 `crawler.headless_all_pages` 开关：无头渲染默认仅首页，开启后
  扩展到全部已爬页（JS 路由二级页也贡献链接/路由；每页一次浏览器
  渲染，页面多时显著变慢，故默认关）
- 指纹×情报命名对齐 `internal/intel.lookupAliases`：全量比对 370 指纹
  名 × 6511 情报产品名，仅收录经核实同属一个软件的三对别名
  （Microsoft IIS/Yoast SEO/Akamai Bot Manager），命中 91→94，其余
  276 项未命中经核实为情报未覆盖而非命名缺陷
- **dsl 安全子集求值器（internal/dsl，新增第 17 个包）**：Nuclei dsl
  表达式的词法/递归下降解析 + 求值，支持 status_code/body/headers/host
  变量与 contains 族/regex/tolower/len 等函数、比较与逻辑运算；准入
  即拒子集外形态，求值失败一律不命中（宁少报不误报）；纯排除式
  （如 !contains(host,…)）静态判定不转换，杜绝恒真空转 check
- **可运行模板 4701 → 5412（+15%）**：dsl 安全子集接入后全库实测
  5412/11306（其中 768 条含 dsl 匹配器）；累计较原版同漏斗 2613 翻倍
- **修复（latent）：regex 匹配器从未装配**——36c3f8e 起模板的 regex
  matcher 被解析并转换进组，但 g.rx 漏写入 Match.RegexBody，纯 regex
  模板转成无条件 check（对任意响应恒真）；混合模板正则条件静默丢失
- **修复：模板索引缓存永不命中**——缓存有效性误拿「漏斗通过数」与
  「文件总数」比对（5412 ≠ 11306），每次扫描提交都全量重建索引；
  现缓存记录 Files 总数，命中后 3.0s → 0.44s
- MoE 三路调度完整回归 Go 版：tag 硬匹配置顶 + TF 余弦相似度路由
  （与原版 embedding 余弦同构，无模型依赖）+ 持久化 LRU 公平调度
  （跨重启保持轮转进度，⌈C/N⌉ 次扫描完成全量轮换）
- **可运行模板 2613 → 4701（+80%）**：漏斗大扩展支持 POST 模板/
  regex 匹配器/头匹配/根探测/多组 AND 合并；全库 11306 条经漏斗
  实测可运行 4701 条（原版同漏斗约 2613）

- 爬虫现代化四连：sitemap 种子（robots Sitemap 声明 + /sitemap.xml）、
  jsmap API 端点回灌爬虫、SPA 路由提取（__NEXT_DATA__/__NUXT__）、
  无头渲染（chromedp，crawler.headless 开关默认关，浏览器缺失自动降级）
- 修复：NUXT 路径提取正则字符类缺少斜杠导致恒空（细分诊断定位）

## v0.0.1-preview（预览版，2026-09-07）

Go 全量迁移完成：单二进制、零外部依赖（弃 PostgreSQL），Python 全量实现存档于 `python` 分支。

### 新增
- **内置 Web 服务**：`sitelens serve`，go:embed 嵌入前端单二进制交付；
  20 个 REST API 端点契约对齐 Flask 版，前端零改动迁移
- **验证型 check 扩展**：`Match.StatusAny/ContainsAny`（Nuclei 组语义，
  对 41 条内置规则向后兼容）
- **Nuclei 子集装载**：模板库索引（头部快扫 + 缓存）+ 两路调度
  （tag 硬匹配置顶、词面相关度排序、轮转覆盖三路调度）；漏斗对齐
  import_nuclei.py（单 GET/{{BaseURL}}/status|word，interactsh 跳过）
- **主动模块**：目录探测（软404 基线 + 403 绕过重试）、子域名枚举
  （DNS 并发、解析器可注入）、WebShell 探测、FingerDir 主动指纹
  （38 条精编 spec 全条件判定）、端口服务识别（11966 条 banner 指纹，
  TLS 自实现证书校验不跳过校验）
- **JS 攻击面**（internal/jsmap）：SourceMap 泄露检测 + bundle 内
  API 端点枚举
- **基础认证弱口令审计**：401 路径 Basic 字典尝试（凭据全部来自
  外部字典文件，代码不内嵌凭据）
- **KEV 情报自动更新守护**：CISA 公开源拉取，本地缓存
  data/state/kev_extra.json，间隔可配（intel.update_hours，0=关）
- **源码审计 / 登录爆破**：16 条 SAST 规则与宽容表单爆破从 Python
  移植；验证码识别能力缺失时明确报错拒绝而非静默误打
- **HTML 报告导出**：/api/export?fmt=html 自包含报告
- **性能**：指纹匹配字面量门控 + 正则 gate 预筛，13.6ms → 5.3ms/页（2.6x）
- **配置化**：全项目阈值统一 `.sitelens.yml`（示例 .sitelens.example.yml），
  零值/负值回退默认，布尔 false 是合法的"关"

### 修复
- **状态码比对缺失**（严重）：checks.matchBody 从未将 Match.Status 与
  实际响应状态码比较，纯状态码 check 会对任何响应命中；
  现按原版语义严格等值比较（含双确认路径）
- **批量扫描死锁**：runBatch 在 JobManager 写锁回调内调用
  CancelRequested（RWMutex 不可重入）导致永久挂起；
  改为回调外先取状态，并在 Update 注明非重入契约
- **HTML 解析越界崩溃**（模糊测试发现）：strings.ToLower 改变非
  ASCII 字节长度使索引错位，特殊 Unicode 页面可打崩扫描器；
  全部替换为长度保持的 asciiLower，120 秒 8700 万次 fuzz 零崩溃
- **协议校验绕过**：`ftp://x` 被盲补 https:// 前缀后放行为主机名
  "ftp"，现显式非 http(s) 协议直接拒绝
- **插件链路断开**：RegisterPlugins 从未被调用，用户插件端到端失效；
  ConfigurePlugins 幂等挂载，server/CLI 接入
- **指纹库形状 bug**：370 条精编指纹中 194 条 html 通道为历史对象
  形状，加载失败被静默丢弃；加载器双形状兼容，并恢复嵌套 dom 数据
- **仓库卫生**：.gitignore 裸写 `sitelens` 曾把 internal/sitelens 包
  整体挡在版本库外，改根锚定 `/sitelens` 并补录

### 变更
- 历史存储：PostgreSQL → 文件式 JSON（data/state/history.json，
  tmp+rename 原子写），API 字段契约不变
- Set-Cookie 逐条保真（Go http.Header 天然分离），替代 Python 版
  合并头启发式切分
- 爬虫：robots.txt Disallow 解析；非 2xx 页不入结果页
- 引擎取消：作业取消标志在阶段边界与 check 循环轮询生效

### 已知差距（详见 docs/Go迁移对照表.md）
验证码 OCR（ddddocr）、AST 级污点分析（已以 TAINT-lite 行级近似替代）、
dsl 匹配器。
