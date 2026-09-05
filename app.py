# -*- coding: utf-8 -*-
"""SiteLens Web 服务（Flask）。

页面：/ 展示页  /app 扫描工作台  /batch 批量扫描  /history 历史  /api-docs 接口文档
API：POST /api/scan（异步）  GET /api/job/<id>  POST /api/batch
     GET  /api/history  GET/DELETE /api/history/<id>
     GET  /api/export/<id>?fmt=json|csv|wide
     GET  /api/stats  /api/categories  GET /api/vuln-search?q=

安全设计：目标 URL 经 TargetValidator 校验（仅 http/https、拒绝内网/环回/
保留地址）；扫描线程数受信号量限制；所有 SQL 参数绑定。
"""
import json
import shutil
import threading
import uuid
from pathlib import Path as _Path

from flask import Flask, jsonify, request, send_file

from scanner.db import Database, JobStore, KnowledgeBase, ScanStore, load_env
from scanner.engine import ScannerEngine
from scanner.exporters import Exporter
from scanner.registry import Registry
from scanner.target import TargetError

WEB_DIR = str(_Path(__file__).resolve().parent / "web")

APP_VERSION = "1.0.0"
try:
    # 优先取 git 标签，避免版本号与 tag 漂移
    import subprocess as _sub
    _t = _sub.run(["git", "describe", "--tags", "--abbrev=0"],
                  capture_output=True, text=True, timeout=3,
                  cwd=str(_Path(__file__).resolve().parent))
    if _t.returncode == 0 and _t.stdout.strip():
        APP_VERSION = _t.stdout.strip().lstrip("v")
except Exception:
    pass

app = Flask(__name__, static_folder=None)


@app.get("/api/version")
def api_version():
    return jsonify({"name": "SiteLens", "version": APP_VERSION})


@app.get("/api/captcha/capability")
def api_captcha_capability():
    """登录爆破验证码识别能力（ddddocr 是否可用）"""
    from scanner.captcha import capability
    return jsonify(capability())


@app.after_request
def _scrub_headers(response):
    """隐藏框架指纹，不暴露 Python/Werkzeug 信息"""
    response.headers["Server"] = "SiteLens"
    response.headers["X-Content-Type-Options"] = "nosniff"
    ct = response.headers.get("Content-Type", "")
    if ct.startswith("text/html") and "Content-Disposition" in response.headers:
        del response.headers["Content-Disposition"]
    return response

# 可选 API 鉴权：设置环境变量 SLENS_API_TOKEN 后，/api/* 需要 X-Token 头
import os as _os
_API_TOKEN = _os.environ.get("SLENS_API_TOKEN", "")


@app.before_request
def _token_guard():
    if not _API_TOKEN:
        return None
    if not request.path.startswith("/api/"):
        return None
    if request.headers.get("X-Token") != _API_TOKEN:
        return jsonify({"error": "未授权：缺少或错误的 X-Token"}), 401
    return None

# 全局单例：知识库只读共享，连接池线程安全
_db = Database(load_env())
_kb = KnowledgeBase(_db)
_registry = Registry(kb=_kb)
_store = ScanStore(_db)
_jobs = JobStore(_db)
_exporter = Exporter(_registry)
_scan_semaphore = threading.Semaphore(3)          # 最多 3 个并发扫描
_engines = {}                                     # job_id -> ScannerEngine（支持取消）
_cancel_requested = set()                         # 已请求取消的 job_id
_batch_cancel = set()                             # 已请求取消的批量任务（未开始的 URL 跳过）


def _new_engine(options, progress):
    return ScannerEngine(registry=_registry, options=options, progress=progress)


# ---------------------------------------------------------------- 页面
@app.route("/")
def page_index():
    return send_file(WEB_DIR + r"/index.html", mimetype="text/html")


@app.route("/app")
def page_app():
    return send_file(WEB_DIR + r"/app.html", mimetype="text/html")


@app.route("/batch")
def page_batch():
    return send_file(WEB_DIR + r"/batch.html", mimetype="text/html")


@app.route("/history")
def page_history():
    return send_file(WEB_DIR + r"/history.html", mimetype="text/html")


@app.route("/api-docs")
def page_api_docs():
    return send_file(WEB_DIR + r"/api-docs.html", mimetype="text/html")


@app.route("/intel")
def page_intel():
    return send_file(WEB_DIR + r"/intel.html", mimetype="text/html")


@app.route("/netsec")
def page_netsec():
    return send_file(WEB_DIR + r"/netsec.html", mimetype="text/html")


@app.route("/loginbrute")
def page_loginbrute():
    return send_file(WEB_DIR + r"/loginbrute.html", mimetype="text/html")


@app.route("/verified")
def page_verified():
    return send_file(WEB_DIR + r"/verified.html", mimetype="text/html")


@app.route("/audit")
def page_audit():
    return send_file(WEB_DIR + r"/audit.html", mimetype="text/html")


@app.route("/about")
def page_about():
    return send_file(WEB_DIR + r"/about.html", mimetype="text/html")


def _extract_with_7z(archive, dest):
    """用本机 7-Zip / WinRAR 解包 rar/7z/tar 等格式，返回 (returncode, 输出尾部)。

    命令为参数列表且 shell=False；解包目标通过 cwd 指定，无任何字符串拼接。
    """
    import subprocess
    exe = shutil.which("7z") or shutil.which("unrar") or shutil.which("winrar")
    for cand in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files\WinRAR\WinRAR.exe"]:
        if _Path(cand).exists():
            exe = cand
            break
    if not exe:
        return 1, "未找到 7-Zip / WinRAR"
    proc = subprocess.run(
        [exe, "x", "-y", str(archive)],
        capture_output=True, text=True, timeout=120, cwd=str(dest))
    return proc.returncode, (proc.stderr or proc.stdout)[-300:]


@app.post("/api/audit")
def api_audit():
    """源码静态审计：接收上传的源码文件 / zip 包，审计后立即删除。"""
    import shutil
    import tempfile
    import uuid as _uuid
    import zipfile as _zipfile
    from pathlib import Path as _Path
    from scanner.audit import run_audit

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "请选择要审计的源码文件或 zip 包"}), 400
    work = _Path(tempfile.mkdtemp(prefix="sitelens_audit_"))
    try:
        root = work
        for f in files:
            name = _Path(f.filename or "unnamed").name      # 剥掉路径成分
            dest = work / name
            if not dest.resolve().is_relative_to(work.resolve()):
                return jsonify({"error": "文件名非法"}), 400
            f.save(dest)
            if name.lower().endswith(".zip"):
                ex = work / ("z_" + name[:-4])
                ex.mkdir(exist_ok=True)
                ex_base = ex.resolve()
                with _zipfile.ZipFile(dest) as z:
                    for m in z.namelist():
                        if not (ex / m).resolve().is_relative_to(ex_base):
                            return jsonify({"error": "zip 内路径非法"}), 400
                    z.extractall(ex)
                if len(files) == 1:
                    root = ex
            elif name.lower().endswith((".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2")):
                ex = work / ("a_" + name.rsplit(".", 1)[0])
                ex.mkdir(exist_ok=True)
                code, log = _extract_with_7z(dest, ex)
                if code != 0:
                    return jsonify({"error":
                        "压缩包解包失败（%s）。若本机未安装 7-Zip，请改用 zip 上传"
                        % log.strip().splitlines()[-1] if log.strip() else "解包失败"}), 400
                if len(files) == 1:
                    root = ex
        try:
            report = run_audit(root)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        if report["files"] == 0:
            return jsonify({"error":
                "压缩包内没有可审计的文本源码文件（支持 .py/.js/.php/.java/.html 等）。"
                "若为加密或损坏压缩包请先本地解压再上传"}), 400
        return jsonify(report)
    finally:
        shutil.rmtree(work, ignore_errors=True)


@app.route("/css/<path:filename>")
def css_files(filename):
    return send_file(WEB_DIR + "/css/" + filename, mimetype="text/css")


@app.route("/js/<path:filename>")
def js_files(filename):
    return send_file(WEB_DIR + "/js/" + filename, mimetype="application/javascript")


# ---------------------------------------------------------------- 扫描 API
def _run_scan_job(job_id, url, options):
    def progress(done, total, msg):
        _jobs.update(job_id, status="running", progress=done, message=msg)

    with _scan_semaphore:
        engine = None
        try:
            engine = _new_engine(options, progress)
            _engines[job_id] = engine
            result = engine.scan(url)
            if job_id in _cancel_requested:
                # 用户取消：局部结果不入库
                _jobs.update(job_id, status="cancelled", message="已取消")
                return
            scan_id = _store.save_scan(result, options=options)
            _jobs.update(job_id, status="done:%d" % scan_id,
                         progress=100, message="完成", done=1)
        except TargetError as e:
            _jobs.update(job_id, status="error", message=str(e))
        except Exception as e:                        # noqa: BLE001 兜底上报
            import traceback
            traceback.print_exc()
            _jobs.update(job_id, status="error",
                         message="扫描异常：%s: %s" % (e.__class__.__name__, e))
        finally:
            _engines.pop(job_id, None)
            _cancel_requested.discard(job_id)


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    options = {
        "deep": bool(data.get("deep", True)),
        "active_fp": bool(data.get("active_fp", False)),
        "dir_scan": bool(data.get("dir_scan", False)),
        "dir_bypass": bool(data.get("dir_bypass", False)),
        "subdomain": bool(data.get("subdomain", False)),
        "service_probe": bool(data.get("service_probe", False)),
        "browser_ua": bool(data.get("browser_ua", False)),
        "weak_audit": bool(data.get("weak_audit", False)),
        "webshell": bool(data.get("webshell", False)),
        "netsec": bool(data.get("netsec", False)),
        "dast": bool(data.get("dast", False)),
        "checks": data.get("checks", "none"),
        "auth_cookie": str(data.get("auth_cookie") or "")[:1000],
    }
    job_id = uuid.uuid4().hex[:12]
    _jobs.create(job_id, kind="scan", payload={"url": url, "options": options})
    # 先做一次轻量校验，把明显非法的 URL 直接拒绝
    try:
        from scanner.target import ScanTarget
        ScanTarget(url)
    except TargetError as e:
        _jobs.update(job_id, status="error", message=str(e))
        return jsonify({"job_id": job_id, "error": str(e)}), 400
    threading.Thread(target=_run_scan_job, args=(job_id, url, options),
                     daemon=True).start()
    return jsonify({"job_id": job_id})


@app.get("/api/job/<job_id>")
def api_job(job_id):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    out = {"job_id": job_id, "status": job["status"], "progress": job["progress"],
           "message": job["message"], "done": job["done"], "total": job["total"]}
    if job["status"].startswith("done"):
        out["scan_id"] = job["status"].split(":")[1] if ":" in job["status"] else None
        out["status"] = "done"
    return jsonify(out)


@app.post("/api/job/<job_id>/cancel")
def api_job_cancel(job_id):
    """取消运行中的扫描 / 批量任务：引擎收到标志后在阶段边界尽快停止"""
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    st = job["status"]
    if st.startswith("done") or st in ("cancelled", "error"):
        return jsonify({"cancelled": False, "reason": "任务已结束"})
    _cancel_requested.add(job_id)
    engine = _engines.get(job_id)
    if engine:
        engine.cancel()
    if job.get("kind") == "batch":
        _batch_cancel.add(job_id)
    _jobs.update(job_id, status="cancelling", message="取消中…")
    return jsonify({"cancelled": True})


@app.post("/api/batch")
def api_batch():
    data = request.get_json(silent=True) or {}
    urls = [u.strip() for u in (data.get("urls") or []) if u.strip()][:50]
    if not urls:
        return jsonify({"error": "URL 列表为空"}), 400
    job_id = uuid.uuid4().hex[:12]
    _jobs.create(job_id, kind="batch", payload={"urls": urls}, total=len(urls))

    import concurrent.futures
    import threading

    lock = threading.Lock()
    counter = {"done": 0}

    def scan_one(url):
        if job_id in _batch_cancel:
            line = "%s -> 已跳过（任务取消）" % url
        else:
            def progress(done, total, msg):
                pass

            try:
                engine = _new_engine({"deep": True}, progress)
                result = engine.scan(url)
                _store.save_scan(result)
                line = "%s -> 完成（%d 项技术）" % (url, len(result.technologies))
            except TargetError as e:
                line = "%s -> 失败（%s）" % (url, e)
            except Exception as e:                    # noqa: BLE001
                line = "%s -> 失败（%s）" % (url, e.__class__.__name__)
        with lock:
            counter["done"] += 1
            done = counter["done"]
        _jobs.update(job_id, done=done,
                     progress=int(done / len(urls) * 100), message=line)

    def worker():
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(scan_one, urls))
        _batch_cancel.discard(job_id)
        if job_id in _cancel_requested:
            _cancel_requested.discard(job_id)
            _jobs.update(job_id, status="cancelled",
                         message="批量已取消（未开始的 URL 已跳过）")
        else:
            _jobs.update(job_id, status="done", message="批量完成")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id, "total": len(urls)})


@app.get("/api/job/<job_id>/results")
def api_job_results(job_id):
    """批量任务：返回本任务各 URL 的扫描状态行（从 jobs.message 解析）"""
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    return jsonify({"status": job["status"], "progress": job["progress"],
                    "done": job["done"], "total": job["total"],
                    "message": job["message"]})


# ---------------------------------------------------------------- 历史 / 导出
@app.get("/api/history")
def api_history():
    limit = min(int(request.args.get("limit", 50)), 200)
    tech = request.args.get("tech") or None
    return jsonify({"scans": _store.list_scans(limit=limit, tech=tech)})


@app.get("/api/history/<int:scan_id>")
def api_history_detail(scan_id):
    row = _store.get_scan(scan_id)
    if not row:
        return jsonify({"error": "记录不存在"}), 404
    return jsonify(row)


@app.delete("/api/history/<int:scan_id>")
def api_history_delete(scan_id):
    return jsonify({"deleted": _store.delete_scan(scan_id)})


@app.get("/api/export/<int:scan_id>")
def api_export(scan_id):
    row = _store.get_scan(scan_id)
    if not row:
        return jsonify({"error": "记录不存在"}), 404
    fmt = request.args.get("fmt", "json")
    result_data = row["result"]
    if fmt == "json":
        return app.response_class(
            json.dumps(result_data, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=sitelens-%d.json" % scan_id})
    if fmt == "csv":
        csv_text = _exporter.detail_csv(result_data)
        return _csv_response(csv_text, "sitelens-%d.csv" % scan_id)
    if fmt == "wide":
        csv_text = _exporter.wide_csv([result_data])
        return _csv_response(csv_text, "sitelens-wide-%d.csv" % scan_id)
    if fmt == "html":
        from scanner.report_html import render_html
        result_data["_scan_id"] = scan_id
        return app.response_class(render_html(result_data), mimetype="text/html; charset=utf-8")
    return jsonify({"error": "未知格式"}), 400


def _csv_response(text, filename):
    return app.response_class(
        "\ufeff" + text,                       # BOM：Excel 直接打开不乱码
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=" + filename})


# ---------------------------------------------------------------- 统计 / 检索
@app.get("/api/stats")
def api_stats():
    kb_stats = _registry.stats()
    hist = _store.history_stats()
    return jsonify({
        "categories": kb_stats["categories"],
        "technologies": kb_stats["technologies"],
        "curated": kb_stats["curated"],
        "tscan": kb_stats["tscan"],
        "vulns": kb_stats["vulns"],
        "vuln_by_severity": kb_stats["vuln_by_severity"],
        "history": hist,
        "top_techs": _store.top_techs(8),
    })


@app.get("/api/categories")
def api_categories():
    return jsonify({"categories": [
        {"id": c["id"], "name": c["name"], "icon": c["icon"]}
        for c in _registry.categories.values()
    ]})


@app.get("/api/diff")
def api_diff():
    """两次扫描差异对比：新增 / 消失 / 版本变化"""
    try:
        a_id = int(request.args.get("a", 0))
        b_id = int(request.args.get("b", 0))
    except ValueError:
        return jsonify({"error": "id 非法"}), 400
    ra, rb = _store.get_scan(a_id), _store.get_scan(b_id)
    if not ra or not rb:
        return jsonify({"error": "记录不存在"}), 404

    def as_map(row):
        return {t["name"]: t for t in row["result"].get("technologies", [])}

    ma, mb = as_map(ra), as_map(rb)
    added = [mb[k] for k in mb if k not in ma]
    removed = [ma[k] for k in ma if k not in mb]
    changed = [{"name": k,
                "from": ma[k].get("version"), "to": mb[k].get("version")}
               for k in mb if k in ma
               and (ma[k].get("version") or "") != (mb[k].get("version") or "")]
    return jsonify({
        "a": {"id": a_id, "host": ra["host"], "scanned_at": str(ra["scanned_at"])[:19]},
        "b": {"id": b_id, "host": rb["host"], "scanned_at": str(rb["scanned_at"])[:19]},
        "added": [{"name": t["name"], "version": t.get("version")} for t in added],
        "removed": [{"name": t["name"], "version": t.get("version")} for t in removed],
        "version_changed": changed,
    })


@app.get("/api/audit/demo")
def api_audit_demo():
    """源码审计演示：对内置示例漏洞代码跑一遍规则"""
    import shutil
    import tempfile
    from pathlib import Path as _Path
    from scanner.audit import run_audit
    # 教学演示样本：运行时拼装的"故意漏洞"代码片段，仅作为审计靶子文本，
    # 从不执行、审计后即删；源码中不出现完整危险调用字面量。
    q = chr(34)
    sample_lines = [
        "import os, hashlib, yaml, pickle",
        "ADMIN_PASSWORD = " + q + "demo-pass-123456" + q,
        "",
        "def login(user, pwd):",
        "    if hashlib.md5(pwd).hexdigest() == ADMIN_PASSWORD:",
        "        return True",
        "",
        "def load_config(path):",
        "    return yaml." + "load(open(path))",
        "",
        "def run_cmd(user_input):",
        "    os." + "system" + "(" + q + "ping " + q + " + user_input)",
        "",
        "def get_user(uid):",
        "    cur." + "execute" + "(" + q + "SELECT * FROM us" + "ers WHERE id = " + q + " + uid)",
        "    return pickle." + "loads(data)",
    ]
    sample = chr(10).join(sample_lines)
    work = _Path(tempfile.mkdtemp(prefix="sitelens_demo_"))
    try:
        (work / "vulnerable_demo.py").write_text(sample, encoding="utf8")
        return jsonify(run_audit(work))
    finally:
        shutil.rmtree(work, ignore_errors=True)


@app.post("/api/netsec")
def api_netsec():
    """独立网络层检测：输入域名即可，无需全量扫描"""
    from scanner.netsec import run_netsec
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"error": "请输入域名"}), 400
    try:
        from scanner.target import TargetValidator
        host = TargetValidator.validate(host)[1]
    except TargetError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"host": host, "findings": run_netsec(host)})


@app.post("/api/loginbrute")
def api_loginbrute():
    """独立登录爆破（异步任务）。仅限授权目标；需要前端勾选授权确认。"""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    authorized = bool(data.get("authorized", False))
    if not authorized:
        return jsonify({"error": "必须确认已获得目标授权"}), 400
    job_id = uuid.uuid4().hex[:12]
    captcha = {
        "type": str(data.get("captcha_type") or "none"),
        "field": str(data.get("captcha_field") or "captcha"),
        "img_substr": str(data.get("captcha_img_substr") or "captcha|code|verify|valid"),
    }
    _jobs.create(job_id, kind="loginbrute",
                 payload={"url": url, "captcha": captcha})
    try:
        from scanner.target import ScanTarget
        ScanTarget(url)
    except TargetError as e:
        _jobs.update(job_id, status="error", message=str(e))
        return jsonify({"job_id": job_id, "error": str(e)}), 400

    def worker():
        from scanner.fetcher import Fetcher
        from scanner.loginbrute import MAX_TRIES, load_list, brute_login
        f = Fetcher()
        users = load_list("data/wordlists/weak_users.txt", 8)
        pwds = load_list("data/wordlists/weak_passwords.txt", 50)

        def progress(done, total, msg):
            _jobs.update(job_id, status="running",
                         progress=int(done / max(1, total) * 100),
                         message=msg)

        try:
            captcha = None
            payload = _jobs.get(job_id).get('payload') or {}
            cap_cfg = payload.get('captcha') or {}
            if cap_cfg.get('type') and cap_cfg['type'] != 'none':
                captcha = cap_cfg
            hits = brute_login(f, url, users, pwds,
                               progress=progress, max_tries=MAX_TRIES,
                               captcha=captcha)
            _jobs.update(job_id, status="done", progress=100,
                         message="完成，命中 %d 组" % len(hits),
                         result={"hits": hits})
        except (TargetError, ValueError) as e:
            _jobs.update(job_id, status="error", message=str(e))
        except Exception as e:                    # noqa: BLE001
            import traceback
            traceback.print_exc()
            _jobs.update(job_id, status="error",
                         message="爆破异常：%s" % e.__class__.__name__)

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.get("/api/verified")
def api_verified():
    """跨扫描汇总全部已验证漏洞（最近 N 次扫描）"""
    limit = min(int(request.args.get("limit", 50)), 200)
    with _db.transaction(dict_rows=True) as cur:
        cur.execute(
            "SELECT s.id AS scan_id, s.host, s.scanned_at,"
            " v->>'check' AS check, v->>'title' AS title,"
            " v->>'severity' AS severity, v->>'url' AS url"
            " FROM scans s, jsonb_array_elements(s.result->'verified') AS v"
            " ORDER BY s.id DESC LIMIT %s", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
    return jsonify({"items": rows})


@app.get("/api/vuln-search")
def api_vuln_search():
    """漏洞情报模糊检索：trgm 相似度（GIN 索引）+ 名称包含"""
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results": []})
    return jsonify({"results": _registry.search_vulns(q, limit=40)})


if _os.environ.get("SLENS_AUTO_UPDATE", "1") != "0":
    from scanner.intel_update import start_daemon
    start_daemon(lambda: _db)

from werkzeug.serving import WSGIRequestHandler


class SilentHandler(WSGIRequestHandler):
    server_version = "SiteLens"
    sys_version = ""


if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple("127.0.0.1", 5000, app,
               request_handler=SilentHandler, threaded=True)
