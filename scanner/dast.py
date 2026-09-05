# -*- coding: utf-8 -*-
"""轻量 DAST：参数级无害注入检测（反射 XSS / 报错 SQLi / 开放重定向 / 目录遍历）。

原理：对爬取到的带参数链接逐参数注入安全标记/探测值，
按响应特征判定，全部为只读探测。请求总量有上限。
"""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

XSS_MARK = 'slq9z7"><svg/onload=slq9z7>'
XSS_RAW = "slq9z7\"><svg"                       # 未转义回显 = 危险
TRAVERSAL = "../../../../../../../../etc/passwd"
TRAVERSAL_HIT = "root:x:0:0:"
REDIRECT = "//sitelens-dt.example.com"
SQL_ERRORS = ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
              "unclosed quotation", "jdbc", "pg_query", "odbc", "sqlstate"]


def run_dast(fetcher, target, links, progress=None, max_params=15):
    """links: [(href, base)] 带参数链接集合；返回已验证发现列表"""
    progress = progress or (lambda done, total, msg: None)
    targets = _collect_params(links, max_params)
    hits = []
    total = max(1, len(targets) * 4)
    done = 0
    for url, param, value in targets:
        for kind, probe in (("xss", XSS_MARK), ("sqli", "'"),
                            ("redirect", REDIRECT), ("traversal", TRAVERSAL)):
            probe_url = _set_param(url, param, probe)
            try:
                r = fetcher.get_small(probe_url)
            except Exception:
                r = None
            done += 1
            if not r:
                continue
            hit = _judge(kind, probe, r, url, param)
            if hit:
                hits.append(hit)
                break                        # 同参数同类命中即止
            progress(done, total, "%s?%s=" % (urlsplit(url).path, param))
    return hits


def _collect_params(links, cap):
    """提取带 query 的 GET 链接参数（每参数一个探测任务）"""
    seen, out = set(), []
    for href, base in links:
        try:
            parts = urlsplit(href)
        except ValueError:
            continue
        if not parts.query:
            continue
        for k, _v in parse_qsl(parts.query, keep_blank_values=True):
            key = (parts.scheme + "://" + parts.netloc + parts.path, k)
            if key in seen:
                continue
            seen.add(key)
            out.append((href.split("?")[0], k, ""))
            if len(out) >= cap:
                return out
    return out


def _set_param(url, key, value):
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if key in [k for k, _ in query]:
        query = [(k, value if k == key else v) for k, v in query]
    else:
        query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _judge(kind, probe, r, url, param):
    status = r.get("status", 0)
    body = (r.get("body") or "").lower()
    headers = r.get("headers") or {}
    if kind == "xss":
        if XSS_RAW in body:
            return {"check": "xss-reflect", "title": "反射型 XSS（标记未转义回显）",
                    "severity": "high", "url": url, "evidence": "参数 %s 回显未转义标记" % param,
                    "advice": "对该参数输出做 HTML 转义或上下文编码", "param": param}
        return None
    if kind == "sqli":
        if any(e in body for e in SQL_ERRORS):
            return {"check": "sqli-error", "title": "报错型 SQL 注入特征",
                    "severity": "high", "url": url,
                    "evidence": "参数 %s 注入单引号触发数据库报错" % param,
                    "advice": "使用参数化查询；关闭详细报错回显", "param": param}
        return None
    if kind == "redirect":
        loc = ""
        for k, v in headers.items():
            if k.lower() == "location":
                loc = v
        if status in (301, 302, 303, 307) and "sitelens-dt.example.com" in loc:
            return {"check": "open-redirect", "title": "开放重定向",
                    "severity": "medium", "url": url,
                    "evidence": "参数 %s 可控制跳转目标" % param,
                    "advice": "重定向目标使用白名单校验", "param": param}
        return None
    if kind == "traversal":
        if TRAVERSAL_HIT in body:
            return {"check": "lfi-passwd", "title": "目录遍历读取 /etc/passwd",
                    "severity": "high", "url": url,
                    "evidence": "参数 %s 注入 ../ 序列读到系统文件" % param,
                    "advice": "路径白名单校验，禁止 .. 序列", "param": param}
    return None
