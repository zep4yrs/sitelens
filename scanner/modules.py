# -*- coding: utf-8 -*-
"""可选扫描模块（默认全部关闭，仅限授权目标使用）。

- dir_scan          目录/后台路径探测（字典驱动，软404基线过滤，可选 403 绕过重试）
- subdomain_enum    子域名枚举（字典 + DNS 并发解析）
- service_probe     常见 Web 端口服务识别（nmap 风格指纹匹配）
- active_fingerprint FingerDir 主动路径指纹（如 Nacos /actuator 类）

所有模块遵守：限速、少量请求、可随时取消；结果以 dict 列表返回。
"""
import concurrent.futures
import socket
from urllib.parse import urljoin, urlparse

from .target import TargetError

DEFAULT_DIR_LIST = "data/wordlists/seclists/web-content-common.txt"
DEFAULT_SUB_LIST = "data/wordlists/seclists/subdomains-5000.txt"
PROBE_PORTS = [80, 443, 8080, 8443, 8000, 8888]


def dir_scan(fetcher, target, progress=None, max_paths=300, bypass_403=False):
    """目录探测：返回 [{path, status, size, title}]"""
    progress = progress or (lambda done, total, msg: None)
    wl = target_wordlist(DEFAULT_DIR_LIST, max_paths)
    total = len(wl)
    found, soft404_sizes = [], set()

    # 先取一个不存在的路径做软404基线
    base_resp = _try(fetcher, target.url + "/__sitelens_none__")
    if base_resp:
        soft404_sizes.add(base_resp["size"])

    for i, path in enumerate(wl):
        url = urljoin(target.url + "/", path)
        r = _try(fetcher, url)
        if r is None:
            continue
        if r["status"] == 403 and bypass_403:
            r = _try(fetcher, url, headers={"X-Forwarded-For": "127.0.0.1"})
        if r and r["status"] in (200, 401, 403) and r["size"] not in soft404_sizes:
            found.append(r)
        progress(i + 1, total, "目录探测 %s" % path)
    return found


def subdomain_enum(host, progress=None, max_subs=2000, workers=20):
    """子域名枚举：字典 + getaddrinfo 并发解析，返回 [{subdomain, ip}]"""
    progress = progress or (lambda done, total, msg: None)
    words = target_wordlist(DEFAULT_SUB_LIST, max_subs)
    total = len(words)
    found = []

    def resolve(word):
        word = word.strip().lower().rstrip(".")
        if not word:
            return None
        sub = word + "." + host
        try:
            infos = socket.getaddrinfo(sub, None, proto=socket.IPPROTO_TCP)
            ip = infos[0][4][0]
            return {"subdomain": sub, "ip": ip}
        except (OSError, UnicodeError, ValueError):
            # OSError=解析失败；UnicodeError/ValueError=字典词含非法标签
            # （空行、双点、超长标签触发 idna 编码失败），单条跳过不影响整体
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for i, res in enumerate(pool.map(resolve, words)):
            if res:
                found.append(res)
            if i % 50 == 0:
                progress(i + 1, total, "子域名解析 %d/%d" % (i + 1, total))
    return found


def service_probe(host, kb_db, progress=None, ports=None, timeout=2.5):
    """常见 Web 端口服务识别：banner 抓取 + nmap 风格指纹匹配"""
    progress = progress or (lambda done, total, msg: None)
    patterns = _load_service_patterns(kb_db)
    ports = ports or PROBE_PORTS
    found = []
    for i, port in enumerate(ports):
        banner, http_resp = _grab(host, port, timeout)
        blob = (banner + "\n" + http_resp)
        service, product, version = None, None, None
        for pat, p_service, p_product, p_version, regex in patterns:
            try:
                m = regex.search(blob)
            except Exception:
                continue
            if m:
                service, product = p_service, p_product or p_service
                version = p_version.replace("$1", m.group(1) if m.groups() and m.group(1) else "")
                break
        if service or product:
            found.append({"port": port, "service": service, "product": product, "version": version})
        progress(i + 1, len(ports), "端口 %d" % port)
    return found


def active_fingerprint(fetcher, target, fingerdir, progress=None, max_requests=30):
    """FingerDir 主动路径指纹：按产品探测特征路径并匹配响应特征"""
    progress = progress or (lambda done, total, msg: None)
    tasks = [(product, path) for product, spec in fingerdir.items()
             for path in spec.get("paths", [])][:max_requests]
    found = []
    for i, (product, path) in enumerate(tasks):
        spec = fingerdir[product]
        url = urljoin(target.url + "/", path.lstrip("/"))
        ev = _try_raw(fetcher, url)
        if ev and _spec_match(ev, spec):
            found.append({"product": product, "path": path, "status": ev["status"]})
        progress(i + 1, len(tasks), "主动指纹 %s" % product)
    return found


def _spec_match(resp, spec):
    """FingerDir matchers：status / body_contains / body_not_contains / content_type / header"""
    status_ok = not spec.get("status") or resp["status"] in spec["status"]
    if not status_ok:
        return False
    body = resp.get("body") or ""
    for kw in spec.get("body_contains") or []:
        if kw not in body:
            return False
    for kw in spec.get("body_not_contains") or []:
        if kw in body:
            return False
    ctype = resp.get("content_type") or ""
    for kw in spec.get("content_type") or []:
        if kw not in ctype:
            return False
    headers = resp.get("headers") or ""
    for kw in spec.get("header_contains") or []:
        if kw not in headers:
            return False
    return True


def _try(fetcher, url, headers=None):
    """GET 并返回精简响应；失败返回 None"""
    ev = _try_raw(fetcher, url, headers)
    if not ev:
        return None
    return ev


def _try_raw(fetcher, url, headers=None):
    """统一的小请求封装：返回 {status,size,title,body,content_type,headers}"""
    try:
        ev = fetcher.get_small(url, headers=headers)
    except TargetError:
        return None
    except Exception:
        return None
    if ev is None:
        return None
    return ev


def target_wordlist(path, limit):
    """读取字典前 N 行（去空行/注释）"""
    try:
        lines = [l.strip() for l in open(path, encoding="utf8", errors="ignore")]
    except OSError:
        return []
    return [l for l in lines if l and not l.startswith("#")][:limit]


def _load_service_patterns(kb_db):
    """service_fp 表 → [(pattern, service, product, version, compiled)]"""
    import re as _re
    out = []
    with kb_db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT service, pattern, product, version, soft FROM service_fp")
        for r in cur.fetchall():
            try:
                out.append((r["pattern"], r["service"], r["product"], r["version"],
                            _re.compile(r["pattern"], _re.I)))
            except Exception:
                continue
    return out


def _grab(host, port, timeout):
    """连接端口：先被动读 banner，无响应再发 HTTP 探测"""
    banner, http_resp = "", ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(512).decode("latin1", errors="replace")
            except OSError:
                banner = ""
            if not banner.strip():
                sock.sendall(("GET / HTTP/1.0\r\nHost: %s\r\n"
                              "User-Agent: SiteLens/1.0\r\n\r\n" % host).encode())
                chunks = []
                while True:
                    try:
                        part = sock.recv(1024)
                    except OSError:
                        break
                    if not part:
                        break
                    chunks.append(part.decode("latin1", errors="replace"))
                    if sum(len(c) for c in chunks) > 4096:
                        break
                http_resp = "".join(chunks)
    except OSError:
        return "", ""
    return banner, http_resp


# ---------------------------------------------------------------- 授权审计模块
WEAK_USERS = "data/wordlists/weak_users.txt"
WEAK_PASSWORDS = "data/wordlists/weak_passwords.txt"
SHELL_LIST = "data/wordlists/full/WebShell字典.json"


def weak_audit(fetcher, target, progress=None, max_tries=120):
    """弱口令审计（默认关闭，仅限授权目标）：

    1) 对 401 路径做 HTTP Basic 认证尝试；
    2) 对疑似登录页做常见字段名表单提交尝试。
    用户名/密码来自漏洞收集包弱口令字典的精选 TOP（8 用户 × 50 密码，封顶 max_tries）。
    凭据字典来自外部数据文件，代码不内嵌任何可用凭据组合。
    """
    import base64
    import itertools
    import json as _json
    progress = progress or (lambda done, total, msg: None)
    users = _wordlist(WEAK_USERS)[:8]
    pwds = _wordlist(WEAK_PASSWORDS)[:50]
    combos = list(itertools.product(users, pwds))[:max_tries]
    hits = []

    # 1) HTTP Basic：对扫描发现的 401 路径逐个尝试
    basic_urls = [u for u in getattr(fetcher, "seen_401", [])][:3]
    total = max(1, len(combos) * (1 + len(basic_urls)))
    done = 0
    for url in basic_urls:
        for user, pwd in combos:
            token = base64.b64encode(("%s:%s" % (user, pwd)).encode()).decode()
            try:
                resp = fetcher.get_small(url, headers={"Authorization": "Basic " + token})
            except Exception:
                resp = None
            done += 1
            if resp and resp.get("status") == 200:
                hits.append({"type": "basic-auth", "url": url,
                             "user": user, "password": pwd})
                break
            progress(done, total, "Basic %s %s" % (user, "*" * len(pwd)))
        _jobs_note(progress, done, total)

    # 2) 登录表单：对标题/路径含 login/signin/admin 的页面尝试常见字段名
    login_urls = getattr(fetcher, "seen_login_pages", [])[:3]
    field_pairs = [("username", "password"), ("user", "pass"),
                   ("account", "passwd"), ("email", "password"), ("name", "pwd")]
    for page in login_urls:
        for (fu, fp_), (user, pwd) in itertools.product(field_pairs, combos[:20]):
            done += 1
            try:
                resp = fetcher.post_form(page, {fu: user, fp_: pwd})
            except Exception:
                resp = None
            if resp and resp.get("status") in (200, 302) and not resp.get("still_login", True):
                hits.append({"type": "login-form", "url": page,
                             "user": user, "password": pwd})
                break
            progress(done, total, "表单 %s=%s" % (fu, "*" * len(pwd)))
    return hits


def webshell_probe(fetcher, target, progress=None, max_paths=200):
    """WebShell 路径存活探测（默认关闭，仅限授权目标）：

    用漏洞收集包 WebShell 字典的路径清单逐个 GET，
    200 且体积>0 记为「可疑存活」，仅供人工复查。
    """
    progress = progress or (lambda done, total, msg: None)
    paths = _load_shell_paths()[:max_paths]
    found = []
    for i, path in enumerate(paths):
        url = target.url.rstrip("/") + "/" + path.lstrip("/")
        try:
            r = fetcher.get_small(url)
        except Exception:
            r = None
        if r and r.get("status") == 200 and r.get("size", 0) > 0:
            found.append({"path": path, "status": 200, "size": r.get("size")})
        progress(i + 1, len(paths), path)
    return found


def _wordlist(path, limit=64):
    from pathlib import Path as _P
    try:
        lines = (_P(path).read_text(encoding="utf8", errors="ignore").splitlines())
        return [l.strip() for l in lines if l.strip()][:limit]
    except OSError:
        return []


def _load_shell_paths():
    import json as _json
    from pathlib import Path as _P
    try:
        data = _json.loads(_P(SHELL_LIST).read_text(encoding="utf8"))
    except Exception:
        return []
    # 兼容 list / dict(value 为路径列表) 两种结构
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [x for v in data.values() for x in (v if isinstance(v, list) else [v])]
    else:
        items = []
    out = []
    for x in items:
        x = str(x).strip()
        if x and not x.startswith("#"):
            out.append(x.lstrip("/"))
    return out


def _jobs_note(progress, done, total):
    progress(done, total, "")
