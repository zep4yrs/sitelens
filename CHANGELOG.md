# 更新日志

## v1.0.0（2026-09-09，正式版）

- **DVWA 官方镜像认证扫描实测**（ghcr 双容器 + 认证断言门）：full 模式
  命中 LFI（读到 /etc/passwd）与 phpinfo 真实缺陷；apocalypse 9 verified
  残余噪声仅 1 条（已知上游模板问题），矩阵报告更新至 docs/

- **1.0.0 校准基建第一轮**：误报/漏报矩阵报告（docs/误报漏报矩阵报告.md）
  ——干净站零误报断言×2 通过；DVWA 官方镜像认证扫描命中 LFI→/etc/passwd
  与 phpinfo 真实缺陷；修复重定向逐跳校验写死 resolve=true（本地靶场
  一跳即拦的历史遗留）；update-nuclei 子命令（codeload 镜像官方模板库，
  按 HTTP 类别收录约 4355 条）；guard 常量时间比较；连接错误带出底层原因
- 已知差距（1.0 前）：认证态爬虫覆盖（DVWA 仅回 1 页）、第二公开靶场
  镜像获取、上游模板 ID 黑名单

## v0.0.2（2026-09-08）

dsl 安全子集 / 7 扫描模式 / 靶场校准三轮收敛 / 图形安装向导 /
Evidence 自解释等全部条目见下。

## v0.0.2 内容（原"未发布"条目）

- **图形安装向导**：SiteLens-Setup.exe 双击安装——品牌化 WinForms
  向导（选目录→进度条→完成页，深板岩头带+呼吸点词标），--silent
  静默模式供脚本；零第三方工具（.NET 自带 csc 编译），构建链见
  tools/build_installer.py
- **靶场规模回归（lingyun，7 模式全量）揪出并修复两类误报**：
  ① AND-merge 丢弃 status 的"宁少报"写法方向反了——exposure 模板在
  404 回显页仅凭路径子串即误中（apocalypse 单次 15 条假阳性，修复后
  -11）；② 纯状态码组不再转换（任意路径即可命中，漏斗仅 -5：
  5412→5407）；③ stripEcho 补剔去 query 路径变体（Apache 404 回显
  不含 query，路径关键词残留喂给词匹配）
- **Evidence 自解释**：每条命中标注命中原因（词/正则/响应头/dsl
  命中了什么），误报定谳有取证依据（如 zenscrape 的 `[0-9a-z-]{36}`
  万能正则、acme-xss 的 `/html` 子串词，均为上游模板质量问题）
- **扫描模式扩展 4→7**：新增 资产测绘（assets：子域名+接管+目录，
  发现面不跑验证）、隐匿（stealth：浏览器 UA 穿透 WAF+被动检测）、
  **毁天灭地**（apocalypse：全部主动模块+checks:all+nuclei_cap 6000
  全量模板验证，仅限授权目标，UI 红字警示）。`level` 参数服务端落地
  （预设先套、显式键逐项覆盖，与前端 LEVELS 同语义），API/批量用户
  同样可用
- **修复：nuclei_cap 请求参数从未被解析**——api-docs 早已宣称支持
  "调大覆盖全部模板"，服务端却静默忽略（文档-实现漂移）；现请求级
  覆盖真实生效
- **DAST 表单探测**：爬虫采集的表单字段（每表单截取前 16 个字段名）
  纳入参数级无害探测——反射 XSS / 报错 SQLi / 开放重定向 / 目录遍历
  四类判定与 URL 参数同语义（基线求差，页面天然特征不算命中）；
  字段预算并入 dast.max_params；时间盲注暂不覆盖表单（无计时报文，
  如实留作边界）
- **验证引擎同路径请求聚类（§12 P1 落地）**：Method+Path+Body+
  ContentType 相同的 check 共享一次请求，命中后按组一次独立重放完成
  全组二次确认（每条命中仍经独立重放验证，语义不变）。请求数从
  O(模板数) 降到 O(路径数)——Nuclei 子集大量模板探测同一路径，300
  模板典型场景降至 ~30 次请求；对目标更友好，扫描更快
- **子域名接管探测（takeover，opt-in）**：18 服务 CNAME+边缘 404 特征
  双条件判定（GitHub Pages/Heroku/S3/Azure/CloudFront/Shopify/Fastly/
  Netlify 等，取 can-i-take-over-xyz 核验子集）；随子域名枚举产出候选，
  每候选 1 次请求、总量 `active.takeover_max`（默认 50）封顶；命中即
  高/中危发现并给处置建议。§12 改进路线 P1 落地
- Env 接口精简：删除从未被求值器调用的 HeaderValues（头 map 整体包含
  非子集语义，类型错误路径保持不变）
- **修复：htmlx script 块解析 panic（fuzz 实测）**——畸形标签
  `<sCript</sCript>` 使 `</script>` 闭合下标落进标签文本内，
  数据岛切片反向越界（body[16:7]）。爬虫会解析任意站点页面，
  此类输入即可让扫描进程崩溃；现要求闭合下标严格位于标签之后。
  崩溃语料入库作回归；htmlx fuzz 第二轮 8 分钟零失败
- **服务器浸泡 12 连扫**：RSS 38.8→67.3MB 后进入平台期（末三次
  增量 <0.4MB），无泄漏迹象；环回目标被 SSRF 校验正确拦截
  （「目标解析到内网/保留地址，已拦截」）
- **dsl 求值器模糊测试加固**：Go 原生 fuzz 15+8+8 分钟三轮（峰值
  ~30 万 exec/s，累计 >2 亿次执行）。第二轮揪出 worker 进程消亡：
  regex/prog 双缓存对不可信输入无限膨胀致内存耗尽；现已加
  4096/16384 上限（生产端模式来自有限模板库，上限只影响对抗场景），
  另加括号嵌套 ≤64 层与表达式 ≤8192 字符准入。第三轮 8 分钟零失败
  通过，两枚崩溃语料入库作回归
- **修复：MS 公告关联误配洪泛**——cve_ms 34931 条中 1545 条组件名为空，
  反向包含 `Contains(技术名, "")` 恒真，任意技术都能匹配全部空组件
  公告（实测 tools 扫描 21 条漏洞里 20 条是无关 Windows 公告）；
  现要求组件名 ≥4 字符且双向包含均有长度下限，实测同目标 21→1 条
  （保留的一条为真实 Nginx UI CVE 的 possible 提示）
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
