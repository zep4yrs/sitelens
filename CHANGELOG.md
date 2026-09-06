# 更新日志

## v1.1.0-go（2026-09-07）

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
验证码 OCR（ddddocr）、Python 污点分析、语义向量路由（词面重合度近似）、
Nuclei 头匹配/dsl 匹配器。
