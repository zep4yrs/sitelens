@fengqiao(枫桥) 第三轮复查：624ad9d 我按源码逐条核过了，13 项修复全部落地，49 项测试在我这边复跑也全绿。但**实跑发现 3 个新引入的回归**，其中一个把核心审计功能打死了，建议先修再往下走。

---

## 一、13 项修复核实结果（逐条对照源码）

| 项 | 核实 | 证据 |
|---|---|---|
| SSRF 逐跳校验 | ✅ | `fetcher._get_follow` 禁用自动重定向 + 每跳 `TargetValidator.validate(resolve=True)`，`post_form` 同处理 |
| cve_ms 空库建表 | ✅ | `db.py:149` 建表已在 `ensure_schema` 内 |
| jobs ALTER 顺序 | ✅ | `db.py:192` 已移到 CREATE 之后 |
| 富集列入 schema | ✅ | `sources/cvss_score/cvss_sev/cvss_vector_txt` 四个 ALTER 齐全 |
| verdict 字段 | ✅ | 前端已改 `v.verdict`，跳过不存在的 `v.level` |
| 死路由 302 | ✅ | 实测 `/netsec`→`/app#netsec`、`/loginbrute`→`/app#loginbrute`、`/verified`→`/history#verified` |
| 上传 200MB 上限 | ⚠️ 部分失效 | 见问题 1 |
| favicon b64encode | ✅ | 无换行，与 fofa 标准一致 |
| report_html dir_scan url | ✅ | 实测渲染出 `/admin/ → 200 (123B) 后台` |
| data/ 锚定仓库根 | ✅ | 5 个字典路径实测全部 exist |
| netsec 非 443 端口 | ✅ | `check_tls(host, port=...)` 已接上 |
| OCR 清洗 | ✅ | 数字验证码段已加正则 |
| limit 非数字回退 | ⚠️ 有缺口 | 见问题 2 |

我本地起真实 PG（drop schema 全清后重启）验证：全新部署首启动 → 建表 11 张 → 自动播种 370 条精编指纹 / 78 类别，`match_cve_ms` 空表静默跳过不报错。空库链路彻底通了。

SSRF 我用假 session 打了 4 个用例：302→`127.0.0.1`、302→`169.254.169.254`、302→`10.0.0.1`、302→`file:///etc/passwd` 全部被拦；正常跳转链放行；6 跳循环正常终止。这块做得扎实。

---

## 二、新引入的 3 个问题

### 🔴 问题 1：`/api/audit` 上传 zip 必崩（AttributeError，功能完全不可用）

`app.py:214` 用了 `m.file_size`，但 `zipfile.ZipFile.namelist()` 返回的是**字符串列表**，不是 `ZipInfo` 对象：

```
File "/workspace/app.py", line 214, in api_audit
    extracted_total += m.file_size
AttributeError: 'str' object has no attribute 'file_size'
```

**只要上传 zip 就 500**，非 zip 的单文件（.py 直传）走不到这行所以测不出来。我实跑确认：单文件 200 OK，zip 直接抛异常。

修法（用 `infolist()` + `getinfo`）：
```python
for m in z.infolist():
    if not (ex / m.filename).resolve().is_relative_to(ex_base):
        return jsonify({"error": "zip 内路径非法"}), 400
    extracted_total += m.file_size
```

顺带提醒：这一行是**解压前**按 zip 内声明的 `file_size` 累加，所以防 zip 炸弹的效果是在的，改完就能真正生效——目前它是 100% 崩，等于既没防护也没功能。

### 🔴 问题 2：`f.content_length` 恒为 0，200MB 上传上限形同虚设

`app.py:187` 的 `sum(f.content_length or 0 for f in files)` 实际永远算出来是 0。werkzeug 的 `FileStorage.content_length` 读的是**每个 part 自己的 Content-Length 头**，而浏览器 multipart 上传不给单个 part 写这个头，返回值固定 0（我实测 `FileStorage(BytesIO(b"abcd"))` → `content_length == 0`）。

真正的兜底其实已经在：`MAX_CONTENT_LENGTH = 200MB` 是 Flask 全局的，超了会返回 413。所以**防护没丢，只是这一行是死代码**，两个上限叠加也没有实际意义。要么删掉这行依赖全局配置，要么改成按已落盘字节数在循环里累加（`dest.stat().st_size` 那段已经这么做了，把 MAX_UPLOAD 判断挪进去即可）。

### 🟠 问题 3：`_safe_limit` 负数漏网，`/api/history?limit=-5` 仍 500

```python
return min(int(raw), cap) if raw else default   # 只夹了上界，没夹下界
```
`limit=-5` → `int()` 成功 → 直接进 SQL → `psycopg2.errors.InvalidRowCountInLimitClause: LIMIT must not be negative` → 500。我实跑复现了。

修法：`return max(1, min(int(raw), cap))`（顺带把 0 也兜住，0 目前会返回空列表不算错，但夹一下更稳）。

---

## 三、另外几点观察（本轮不阻塞，供参考）

1. **`fetch_bytes` 现在会抛 `TargetError`，但 3 个调用点没接**。`engine.py:200`（favicon）、`bundle_detector.py:67`、`loginbrute.py:164` 都是裸调，没有 try。目标 favicon/JS 若 302 到内网，异常会往上冒。引擎主路径有 `except Exception` 兜底不会 500，但采集器内部逻辑会被打断。`jsmap.py:26` 已经包了 try，照它抄一下即可。

2. **`match_cve_ms` 的 `except` 放在内层循环里，直接 `return`**——表存在但中途出任何错（比如连接闪断）都会静默返回已收集的部分结果。空表跳过这个需求是对的，但建议把"表不存在"和"其他错误"分开处理，否则以后真出故障会很难排查。

3. **重定向校验是逐跳 DNS 解析，存在理论上的 TOCTOU 窗口**（校验时解析 A 记录，requests 建连时再解析一次，DNS rebinding 可钻）。要彻底封死得上 `socket.create_connection` 前的自定义 resolver 或固定 IP 建连。对实训演示场景现有强度够了，写文档时可以提一句这是已知边界。

4. **HTML 报告里的 `ref` 外链没做协议白名单**。前端 `safeLink` 你已经加了 http/https 过滤，但 `report_html.py:27` 的 `%s` 直接拼进了 `href`，`javascript:` 开头的 ref 会原样输出（我构造数据验证过）。虽然 ref 来自情报库不是用户输入，但报告是要离线分发的文件，建议同步加上协议判断，和前端保持一致。

5. `web/css` 目录不存在（样式在 `common.js` 内联注入），`/css/<path>` 路由对任何输入都是 FileNotFoundError → 500。建议直接删掉这条路由或返回 404，避免无效请求打 500 日志。

---

**结论**：13 项修复我全部确认属实，之前提的四条关键发现处理得干净。但 zip 审计崩、limit 负数 500 这两个是本次提交带进来的，其中 zip 那条影响核心功能，建议优先修。要我直接开 PR 改这三处吗？

（我在本地起了 PG 15 + 真实扫描验证，`.env` 等临时文件已清理，工作区无残留改动。）