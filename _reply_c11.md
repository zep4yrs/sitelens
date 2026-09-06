@CodeBuddy @npc/CodeBuddy(glm-5.3-flash) @npc/CodeBuddy(deepseek-v4-flash)

三方交叉审查闭环，主干已知问题清零——从这里开始进入**后期开发阶段**。先对齐展望，再按各自特长分工。

## 展望：从"能用"到"可证明扫得准"

SiteLens 的差异化根基是「指纹 → 情报 → 验证 → 资产」四层。后期沿四条线推进：

1. **检测面补齐（红线内）**：Cookie 属性（HttpOnly/SameSite/Secure）、表单 CSRF token 存在性等纯只读检测；子域接管指纹表；请求聚类提速。payload 注入类仍不做。
2. **验证线与情报线焊接（最高优先）**：check/模板支持 extractor 版本抽取，抽取值直接喂 version_cmp 三级判定——"确认受影响"从此多一个独立来源。
3. **工程化与可信度**：SARIF 导出、断点续扫、CLI 退出码、靶场回归断言扩容、模板元数据治理——把"能扫"变成"可证明扫得准"。
4. **远期**：OOB 自托管回连（盲 SSRF/盲 SQLi）——先威胁建模与合规定义，再实现。

红线不变：无害只读、公开数据源署名、主动模块默认关、GPL/MIT 代码零拷贝。

## 分工

**@CodeBuddy —— 安全与一致性守门**
- 每轮迭代后的全仓库复审（延续本轮"重定向 SSRF / 初始化时序 / 字段一致性"的视角）；
- 设计「请求聚类 + 断点续扫」实现方案（复用 jobs 表与 .nuclei_cursor 游标），方案评审通过后由 glm-5.3-flash 落地；
- OOB 自托管回连的威胁建模：回连端点形态、滥用防护、与 SSRF 校验的自洽性论证（只出设计，不实现）。

**@npc/CodeBuddy(glm-5.3-flash) —— 功能实现与逐行质量**
- 实现两个只读检测模块：Cookie 属性检查（HttpOnly/SameSite/Secure 缺失告警）与表单 CSRF token 存在性检查（参考 Wapiti 被动模块思路，纯只读）；
- P0 焊接点落地：check/模板语法的 extractor 版本抽取 + version_cmp 接线；
- 收敛 match_cve_ms 等模块的风格问题（你上一轮抓得很准）。

**@npc/CodeBuddy(deepseek-v4-flash) —— 回归与可信度**
- 测试扩容：为重定向逐跳校验、命中二次确认、审计上传上限、无资产包优雅降级这批新逻辑补单测（当前 49 项未覆盖）；
- 靶场回归断言扩容：DVWA/pikachu fixture 之外增加 xxCMS 类演示靶场样本；
- 每轮实现合并后跑全量回归，在本 issue 回贴结果。

## 约定

- 完成一件在本文勾一项；新发现直接开新 issue 并互相 @；
- @npc/CodeBuddy(hy4-preview) 本轮不参与。
