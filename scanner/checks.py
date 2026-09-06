# -*- coding: utf-8 -*-
"""验证型 Check 引擎：yaml 思路的数据驱动无害检测（M1）。

每条 check：一个请求 + 一组判定（status / body 包含 / body 排除 / 响应头）。
全部为只读类检测，命中即「已验证漏洞」，与情报关联分开呈现。
模板可选 extract 字段（如 {"keyword": "nginx"}）：命中后从响应体抽取版本号，
输出 extracted_version，由引擎交给 version_cmp 做三级判定（焊接点，见 engine.py）。
lv 字段：0 = 核心集（深度识别起运行），1 = 扩展集（全面识别运行）。
"""
from pathlib import Path
from urllib.parse import urljoin

from .version_cmp import extract_version

# (id, lv, 路径, 匹配{状态码,包含[],排除[],头包含,extract{keyword}}, 标题, 严重度, 修复建议)
# extract: 可选，命中后从响应体抽取版本号（extract_version）
CHECKS = [
    ("git-leak", 0, "/.git/HEAD", {"s": 200, "c": ["ref: refs/"]}, "Git 仓库泄露", "high", "删除 Web 根下 .git 目录"),
    ("git-index", 0, "/.git/index", {"s": 200, "c": ["DIRC"]}, "Git index 文件泄露", "high", "同上"),
    ("env-leak", 0, "/.env", {"s": 200, "c": ["=", "\n"]}, ".env 环境变量泄露", "high", "移除 .env，配置走环境变量"),
    ("svn-leak", 1, "/.svn/entries", {"s": 200, "c": ["dir"]}, "SVN 目录泄露", "high", "删除 .svn"),
    ("ds-store", 1, "/.DS_Store", {"s": 200, "c": ["Bud1"]}, ".DS_Store 泄露目录结构", "low", "部署过滤点开头文件"),
    ("bak-dump", 0, "/dump.sql", {"s": 200}, "数据库 dump 文件暴露", "high", "删除备份文件"),
    ("bak-site", 1, "/www.zip", {"s": 200}, "站点源码打包暴露", "high", "删除源码包"),
    ("bak-config", 1, "/wp-config.php.bak", {"s": 200}, "配置备份文件泄露", "high", "删除编辑器备份"),
    ("phpinfo", 0, "/phpinfo.php", {"s": 200, "c": ["phpinfo()"]}, "phpinfo 页面暴露", "high", "删除 phpinfo 探针"),
    ("adminer", 1, "/adminer.php", {"s": 200, "c": ["Adminer"]}, "Adminer 数据库管理入口", "medium", "删除或加访问控制"),
    ("actuator", 0, "/actuator", {"s": 200, "c": ["_links"]}, "Spring Actuator 未授权", "high", "关闭暴露端点或加鉴权"),
    ("actuator-env", 1, "/actuator/env", {"s": 200}, "Actuator env 端点暴露", "high", "同上"),
    ("swagger", 0, "/swagger-ui.html", {"s": 200}, "Swagger 文档暴露", "medium", "生产关闭或加鉴权"),
    ("api-docs", 1, "/v2/api-docs", {"s": 200, "c": ["swagger"]}, "API 文档未授权访问", "medium", "同上"),
    ("druid", 1, "/druid/index.html", {"s": 200, "c": ["Druid"]}, "Druid 控制台未授权", "high", "加访问控制"),
    ("tomcat-manager", 1, "/manager/html", {"s": 401}, "Tomcat Manager 暴露", "medium", "删除或强口令"),
    ("server-status", 1, "/server-status", {"s": 200, "c": ["Apache"]}, "Apache server-status 暴露", "low", "关闭 mod_status 对外"),
    ("debug-page", 1, "/console", {"s": 200, "c": ["console"]}, "调试控制台暴露", "medium", "生产关闭调试端点"),
    ("dir-list", 0, "/static/", {"s": 200, "c": ["Parent Directory", "<h1>Index of", "Directory listing"]}, "目录列表开启", "medium", "关闭 autoindex"),
    ("wp-users", 1, "/?rest_route=/wp/v2/users", {"s": 200, "c": ["\"slug\""]}, "WP REST 用户枚举", "medium", "禁用 users 端点"),
    ("wp-xmlrpc", 1, "/xmlrpc.php", {"s": 405, "c": ["XML-RPC"]}, "xmlrpc.php 开启", "low", "不需要时禁用"),
    ("wp-readme", 1, "/readme.html", {"s": 200, "c": ["WordPress"]}, "WP 版本泄露(readme)", "low", "删除 readme.html"),
    ("composer", 1, "/composer.json", {"s": 200, "c": ["require"]}, "composer.json 泄露", "low", "移除依赖清单"),
    ("package-json", 1, "/package.json", {"s": 200, "c": ["dependencies"]}, "package.json 泄露", "low", "移除依赖清单"),
    ("webconfig", 1, "/web.config", {"s": 200, "c": ["<configuration"]}, "IIS web.config 泄露", "medium", "禁止下载配置文件"),
    ("crossdomain", 1, "/crossdomain.xml", {"s": 200, "c": ["<cross-domain-policy"]}, "过时跨域策略文件", "low", "删除 crossdomain.xml"),
    ("metrics", 1, "/metrics", {"s": 200, "c": ["# HELP", "# TYPE"]}, "Prometheus metrics 暴露", "medium", "加内网访问限制"),
    ("admin-path", 0, "/admin/", {"s": 200}, "后台入口 /admin/", "info", "加访问控制与双因素"),
    ("login-root", 0, "/login", {"s": 200}, "登录入口 /login", "info", "加访问控制"),
    ("grafana", 1, "/grafana/login", {"s": 200, "c": ["Grafana"]}, "Grafana 登录暴露", "low", "加访问控制"),
    ("kibana", 1, "/app/kibana", {"s": 200}, "Kibana 暴露", "medium", "加访问控制"),
    ("nacos", 1, "/nacos/", {"s": 200, "c": ["nacos"]}, "Nacos 控制台暴露", "high", "开启鉴权"),
    ("jenkins", 1, "/jenkins/login", {"s": 200, "c": ["Jenkins"]}, "Jenkins 暴露", "medium", "加访问控制"),
    ("solr", 1, "/solr/#/", {"s": 200}, "Solr 控制台暴露", "medium", "加访问控制"),
    ("eureka", 1, "/eureka/apps", {"s": 200, "c": ["<application"]}, "Eureka 注册表未授权", "high", "开启鉴权"),
    ("harbor", 1, "/harbor/sign-in", {"s": 200, "c": ["Harbor"]}, "Harbor 暴露", "low", "加访问控制"),
    ("wp-json", 1, "/wp-json/wp/v2/users", {"s": 200, "c": ["\"slug\""]}, "WP REST 用户泄露", "medium", "禁用 users 端点"),
    ("wp-login", 1, "/wp-login.php", {"s": 200, "c": ["user_login", "wp-submit"]}, "WordPress 登录页", "info", "加访问控制"),
    ("joomla-admin", 1, "/administrator/", {"s": 200, "c": ["Joomla"]}, "Joomla 后台入口", "info", "加访问控制"),
    ("drupal-login", 1, "/user/login", {"s": 200, "c": ["Drupal"]}, "Drupal 登录页", "info", "加访问控制"),
    ("typecho-login", 1, "/admin/login.php", {"s": 200, "c": ["Typecho"]}, "Typecho 登录页", "info", "加访问控制"),
    ("tp-admin", 1, "/admin.php", {"s": 200}, "后台入口 admin.php", "info", "加访问控制"),
]

# CMS 联动：指纹命中 -> 强制调度的专项 check（无视等级过滤）
CMS_TECH_CHECKS = {
    "WordPress": ["wp-json", "wp-xmlrpc", "wp-readme", "wp-login"],
    "Joomla": ["joomla-admin"],
    "Drupal": ["drupal-login"],
    "Typecho": ["typecho-login"],
}


def _load_plugins():
    """插件热加载：data/plugins/*.json 里的自定义 check 自动并入 CHECKS"""
    import json as _json
    d = Path(__file__).resolve().parents[1] / "data" / "plugins"
    if not d.exists():
        return
    for f in sorted(d.glob("*.json")):
        try:
            arr = _json.loads(f.read_text(encoding="utf8"))
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict) and item.get("id") and item.get("m"):
                        CHECKS.append((
                            item["id"], int(item.get("lv", 1)),
                            item.get("p", "/"), item["m"],
                            item.get("title", item["id"]),
                            item.get("sev", "medium"),
                            item.get("advice", "人工复查"),
                        ))
        except Exception:
            continue


_load_plugins()


def run_checks(fetcher, target, level="core", progress=None, include_ids=None,
               cancel_check=None):
    """执行 check 集。level: core（核心集）/ all（核心+扩展）。

    include_ids: 指纹联动强制包含的 check id（如 CMS 专项）。
    cancel_check: 返回 True 时立即停止（用于扫描取消），返回已命中的部分结果。
    返回已验证漏洞列表；带软 404 基线过滤。
    """
    progress = progress or (lambda done, total, msg: None)
    include_ids = set(include_ids or ())
    checks = [c for c in CHECKS
              if level == "all" or c[1] == 0 or c[0] in include_ids]
    # 软 404 基线
    base = None
    try:
        base = fetcher.get_small(urljoin(target.url + "/", "__sl_none__"))
    except Exception:
        base = None
    base_size = base.get("size") if base else None
    base_body = (base or {}).get("body", "")[:200]

    hits, total = [], len(checks) + 1
    for i, (cid, _lv, path, match, title, sev, adv) in enumerate(checks):
        if cancel_check and cancel_check():
            break
        url = urljoin(target.url + "/", path.lstrip("/"))
        try:
            r = fetcher.get_small(url)
        except Exception:
            r = None
        if r is None:
            progress(i + 1, total, path)
            continue
        ok = (r.get("status") == match.get("s"))
        body = r.get("body") or ""
        # 剔除回显的请求路径：Apache 404 页面会回显路径本身，
        # 若模板关键词恰为路径片段会造成自指误报
        body = body.replace(url, "").replace(path, "")
        if ok and base_size is not None and r.get("size") == base_size and base_body and body[:200] == base_body:
            ok = False                      # 软 404：与不存在路径响应一致
        for kw in match.get("c", []):
            if kw not in body:
                ok = False                  # 包含条件全满足
        if ok:
            # 二次确认：命中后立即重放，两次都命中才采信（防 CDN 多节点
            # 内容不一致 / WAF 抖动造成的单次采样误报）
            ok2 = None
            try:
                r2 = fetcher.get_small(url)
            except Exception:
                r2 = None
            if r2 is not None:
                ok2 = (r2.get("status") == match.get("s"))
                body2 = (r2.get("body") or "").replace(url, "").replace(path, "")
                for kw in match.get("c", []):
                    if kw not in body2:
                        ok2 = False
            if ok2 is False:
                progress(i + 1, total, path)
                continue                  # 复核未复现，判定为误报丢弃
            hit = {"check": cid, "title": title, "severity": sev,
                   "url": url,
                   "evidence": "HTTP %d（二次确认）" % r.get("status", 0)
                   if ok2 else "HTTP %d（单次采样）" % r.get("status", 0),
                   "advice": adv}
            extract = match.get("extract")
            if isinstance(extract, dict):
                ver = extract_version(body, keyword=extract.get("keyword"))
                if ver:
                    hit["extracted_version"] = ver
                    hit["evidence"] += "，版本抽取: %s" % ver
            hits.append(hit)
        progress(i + 1, total, path)
    return hits


# ---------------------------------------------------------------- Nuclei 社区模板运行器
import json as _json

NUCLEI_FILE = Path(__file__).resolve().parents[1] / "data" / "nuclei_checks.json"
_nuclei_cache = None
_nuclei_vecs = None
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _nuclei_vectors(rows):
    """模板语义向量（名称+tags 的哈希 TF-IDF），随模板数变化自动重建"""
    global _nuclei_vecs
    if _nuclei_vecs is None or len(_nuclei_vecs) != len(rows):
        from .embedding import embed_text
        _nuclei_vecs = [embed_text(r["name"] + " " + " ".join(r.get("tags", [])))
                        for r in rows]
    return _nuclei_vecs


def load_nuclei():
    """加载已转换的 Nuclei 模板（进程内缓存）"""
    global _nuclei_cache
    if _nuclei_cache is None:
        try:
            _nuclei_cache = _json.loads(NUCLEI_FILE.read_text(encoding="utf8"))
        except Exception:
            _nuclei_cache = []
    return _nuclei_cache


def select_nuclei(cap=80, tech_tags=(), query_text=""):
    """MoE 式三路调度挑选 Nuclei 检测（每轮只激活小子集）：

    1. tag 联动置顶：与已识别技术 tag 硬匹配的模板（命中概率最高）；
    2. 向量语义路由：其余模板按与目标上下文的余弦相似度排序
       （内容寻址——tags 没写但语义相近的模板也会浮上来）；
    3. 轮转游标：无语义信号时按游标轮转，保证长期全覆盖。
    """
    from .embedding import embed_text, cosine
    rows = load_nuclei()
    vecs = _nuclei_vectors(rows)
    tags = {t.lower().strip() for t in tech_tags if t}

    hit, rest = [], []
    qvec = embed_text(query_text) if query_text else None
    for r, vec in zip(rows, vecs):
        rtags = {t.lower() for t in r.get("tags", [])}
        if tags & rtags:
            hit.append(r)
        else:
            sim = cosine(qvec, vec) if qvec else 0.0
            rest.append((_SEV_ORDER.get(r.get("sev"), 4) - sim * 10, r))
    hit.sort(key=lambda r: _SEV_ORDER.get(r.get("sev"), 4))
    rest.sort(key=lambda x: x[0])
    rest = [r for _, r in rest]

    cursor_f = Path(__file__).resolve().parents[1] / "data" / ".nuclei_cursor"
    try:
        offset = int(cursor_f.read_text(encoding="utf8").strip() or 0)
    except Exception:
        offset = 0
    if rest and not qvec:
        k = offset % len(rest)
        rest = rest[k:] + rest[:k]
        cursor_f.write_text(str((offset + cap) % max(1, len(rest))), encoding="utf8")
    return (hit + rest)[:cap]


def _group_match(group, status, body_l, header_l):
    if group.get("s") and status not in group["s"]:
        return False
    for w in group.get("wall", []):
        if w not in body_l:
            return False
    if group.get("wany") and not any(w in body_l for w in group["wany"]):
        return False
    for h in group.get("h", []):
        if h not in header_l:
            return False
    for n in group.get("n", []):
        if n in body_l:
            return False
    return True


def run_nuclei(fetcher, target, rows, progress=None, cancel_check=None):
    """执行 Nuclei 模板集：组间 OR、组内 AND；命中即已验证漏洞。"""
    progress = progress or (lambda done, total, msg: None)
    try:
        base = fetcher.get_small(urljoin(target.url + "/", "__sl_none__"))
    except Exception:
        base = None
    base_body = (base or {}).get("body", "")[:200].lower()
    hits = []
    for i, row in enumerate(rows):
        if cancel_check and cancel_check():
            break
        path = row.get("path") or "/"
        if not path.startswith("/") or path.startswith("//"):
            continue                      # 只允许站内相对路径，防伪造目标
        url = urljoin(target.url + "/", path.lstrip("/"))
        try:
            r = fetcher.get_small(url)
        except Exception:
            r = None
        if r is None or (base_body and (r.get("body") or "")[:200].lower() == base_body):
            progress(i + 1, len(rows), path)
            continue
        status = r.get("status")
        body_l = (r.get("body") or "").lower()
        # 剔除回显的请求路径（404 页面回显路径 → 含路径关键词的自指误报）
        body_l = body_l.replace(url.lower(), "").replace(path.lower(), "")
        header_text = " | ".join("%s: %s" % (k, v) for k, v in (r.get("headers") or {}).items())
        header_l = header_text.lower()
        if any(_group_match(g, status, body_l, header_l) for g in row.get("groups", [])):
            # 二次确认：立即重放，两次都命中才采信（防 CDN 多节点抖动误报）
            ok2 = None
            try:
                r2 = fetcher.get_small(url)
            except Exception:
                r2 = None
            if r2 is not None:
                s2 = r2.get("status")
                b2 = (r2.get("body") or "").lower().replace(
                    url.lower(), "").replace(path.lower(), "")
                h2 = " | ".join("%s: %s" % (k, v)
                                for k, v in (r2.get("headers") or {}).items()).lower()
                ok2 = any(_group_match(g, s2, b2, h2)
                          for g in row.get("groups", []))
            if ok2 is not False:
                hit = {"check": row["id"], "title": row["name"],
                       "severity": row["sev"], "url": url,
                       "evidence": "HTTP %d（二次确认）" % status
                       if ok2 else "HTTP %d（单次采样）" % status,
                       "advice": "参考 Nuclei 模板人工确认",
                       "src": "nuclei"}
                extract = row.get("extract")
                if isinstance(extract, dict):
                    ver = extract_version((r.get("body") or ""),
                                          keyword=extract.get("keyword"))
                    if ver:
                        hit["extracted_version"] = ver
                        hit["evidence"] += "，版本抽取: %s" % ver
                hits.append(hit)
        progress(i + 1, len(rows), path)
    return hits
