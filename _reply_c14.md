@fengqiao(枫桥) 本轮「回归与可信度」任务完成。提交 `ecf881b`（分支 `auto/regression-guard-b266`），全量回归 **49 → 69 项全绿**。

## 测试扩容（新增 18 项单测，`tests/test_late_stage.py`）

**① 重定向逐跳校验（5 项）** — `fetcher._get_follow`
- 单跳 302 → `127.0.0.1`：抛 `TargetError`，只发出初始请求不跟随
- 先公网后内网的两跳链：第二跳被拦下
- 公网跳转正常跟随并返回最终页
- 超过 6 跳停止跟随（返回最后一个 3xx，不向第 7 目标发请求）
- `post_form` / `fetch_bytes` 的 3xx 同样逐跳校验

**② 命中二次确认（5 项）** — check 引擎与 Nuclei 运行器
- 首次命中、重放未命中 → 判抖动误报丢弃（check 与 nuclei 各一）
- 两次命中 → 采信且 evidence 标注「二次确认」
- 重放异常 → 保留单次采样，evidence 标注「单次采样」

**③ 审计上传上限（6 项）** — `/api/audit`（Flask 端点级，DB 打桩离线跑）
- 普通 zip / 单文件源码审计返回发现
- 单个成员声明 530MB（实际压缩 ~0.5MB）→ 解压前按 file_size 累计拦截 400「512MB」
- zip 内 `../` 穿越条目 → 400「路径非法」
- 无文件 → 400；每次审计后临时目录清理干净

**④ 无资产包优雅降级（2 项）** — `match_cve_ms` 缺 `cve_ms` 表/kev 查询异常时静默返回空，不阻塞扫描（含技术别名场景）

## 顺带修复一个真实 Bug（在任务范围内发现）

`/api/audit` 对 **任何 zip 上传都会 500**：zip 炸弹防护循环里 `for m in z.namelist()` 拿到的是**字符串**，却访问 `m.file_size` → `AttributeError`。意味着「审计上传上限」这道防线从未真正生效。已修：`namelist()` → `infolist()`、`m.filename` 做路径校验。普通 zip 与 zip 炸弹两条新单测正好锁住此回归。

## 靶场回归断言扩容（xxCMS 类演示样本 +2）

`tests/test_regression_fixtures.py` 新增：
- `test_xxcms_style_hits`：PHP CMS 后台 `/admin/`、登录页、phpinfo、`www.zip` 站点整包、`dump.sql` 五类检出断言
- `test_xxcms_no_backup_no_false_positive`：干净样本不误报备份/phpinfo

## 结果

- `python3 -m unittest discover -s tests` → **69 passed**（原 49 + 新 20）
- ⚠️ **推送受阻**：当前凭据（CNB_TOKEN）缺 `repo-code:rw`，push 返回 403。因「替我上班」未开启，提交停留在本地分支 `auto/regression-guard-b266`。请开启替我上班模式或授权后我来推送开 PR；代码与测试已在工作区可随时合并。

另外自查发现一处**既有真实 Bug**，已列入本 issue 供跟踪：`/api/audit` zip 上传 500（上述修复已含）。无其他未决阻塞项。