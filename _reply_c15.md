@fengqiao(枫桥) 三项任务已完成开发并通过全量测试（64 项全绿），但本轮未开启"替我上班"模式——CI 临时令牌只有 `repo-code:r` 只读权限，无法建分支/推代码/创建 PR。代码已在本地提交（`225eaf2`），附完整补丁交付，开启工作模式后重跑本评论即可自动推送建 PR。

## 交付内容

**① 被动安全检测模块 `scanner/passive.py`（红线内，纯只读，零额外请求）**
- `check_cookie_attrs`：从 Set-Cookie 响应头解析 HttpOnly/SameSite/Secure，缺失即告警；支持多 Set-Cookie 合并头切分；会话 Cookie（属性未知）只做 HTTPS 下 Secure 交叉提示，不误报 HttpOnly/SameSite
- `check_csrf_tokens`：Wapiti 被动模块思路——只对含 password/身份类输入的敏感表单检查隐藏域中 csrf/_token/nonce 类字段，并标注"token 可能经 JS 注入需人工确认"，severity=low，避免误导
- 引擎接线 `options.passive`，「全面识别」等级默认运行；前端 extras 展示已接

**② P0 焊接点：验证线 → 情报线**
- `version_cmp.extract_version(text, keyword)`：关键词行优先的版本号抽取（词边界正则，拒绝纯数字年份/ID 误判）
- `checks.py` 的 check 与 Nuclei 模板均支持 `extract: {keyword}` 字段，命中后输出 `extracted_version`
- `engine._apply_extracted_versions`：抽取值回填**无版本**的已识别技术（指纹识别版本优先不覆盖），直接喂 `version_in` 出 `confirmed` 三级判定，写回 `verdict`/`verdict_detail`——「确认受影响」从此多一个独立于指纹版本识别的来源
- 技术名匹配用词边界 + 缩写映射（wp→WordPress），避免 "go" 误命中 "golang" 类子串
- `tools/import_nuclei.py` 透传 Nuclei 模板 `extract.kic.k` 关键词；示例插件 `data/plugins/version-extract-demo.json`

**③ 风格收敛**
- `_safe_limit` docstring 措辞校正；fetcher/modules/security/crawler/report_html/loginbrute/app.py/tools 共 12 处未使用变量与 import 清理；`captcha.slider_gap` 冗余实例化修复；app.py 缩进笔误修复

## 验证

- 全量测试 49 → **64 项全绿**（新增 15 项：Cookie 属性 5、CSRF 4、extractor 3、焊接回填 3）
- 端到端链路验证：mock 引擎扫描 → 模板命中 → 抽取 6.4.2 → 回填 WordPress → confirmed

## 附件

- 完整补丁（`git apply` 即可应用）：[passive-extractor.patch](/-/files/issues/2096527038838595584/mefP4MggdEXdBrvpMV9i2F/6c6d5d9d-a470-4fe0-a213-877e6fe2a561/passive-extractor.patch)
- 新增文件打包：[sitelens-new-files.tar.gz](/-/files/issues/2096527038838595584/mefP4MggdEXdBrvpMV9i2F/6f098895-60c6-44f3-988e-c2bac489fa66/sitelens-new-files.tar.gz)

---

**移交说明**：
- @npc/CodeBuddy(deepseek-v4-flash) 新增 15 项单测覆盖被动检测与焊接链路；你负责的"重定向逐跳校验/命中二次确认/审计上传上限/无资产包优雅降级"四块仍未覆盖，可在此基础上继续
- @CodeBuddy 请在补丁应用后按常规做安全复审，重点看 `_match_tech_for_hit` 词边界匹配与 Cookie 解析的多头切分逻辑