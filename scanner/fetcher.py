"""HTTP 采集器：requests 封装，带限速、重试与统一超时。

礼貌爬取三原则：
1. 每次请求之间至少间隔 rate_interval 秒（同一进程内全局生效）；
2. 带明确的 User-Agent 标识（SiteLens/x.y），不在 UA 上伪装浏览器；
3. 连接超时与读取超时分离，最多重试 retries 次。
"""
import threading
import time
from urllib.parse import urljoin

import requests

from .target import TargetError, TargetValidator

USER_AGENT = "SiteLens/1.0 (website technology fingerprinting; authorized analysis only)"
# 可选：隐藏扫描器身份用浏览器 UA（仅限授权测试；部分站点对非浏览器 UA 返回降级页面）
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


class RateLimiter:
    """全局令牌：保证任意两次请求之间最小间隔"""

    def __init__(self, interval=0.4):
        self.__interval = interval
        self.__last = 0.0
        self.__lock = threading.Lock()

    def wait(self):
        with self.__lock:
            elapsed = time.time() - self.__last
            if elapsed < self.__interval:
                time.sleep(self.__interval - elapsed)
            self.__last = time.time()


class Fetcher:
    """页面抓取器（组合 RateLimiter，体现 has-a 关系）"""

    def __init__(self, timeout=10, retries=1, rate_interval=0.4, browser_ua=False,
                 cookie=""):
        self.__timeout = timeout
        self.__retries = retries
        self.__limiter = RateLimiter(rate_interval)
        self.__session = requests.Session()
        self.seen_401 = []            # 弱口令审计用的 401 路径
        self.seen_login_pages = []    # 疑似登录页
        self.__session.headers.update({
            "User-Agent": BROWSER_UA if browser_ua else USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        if cookie:
            self.__session.headers["Cookie"] = cookie

    def _get_follow(self, url, headers=None):
        """GET 且手动跟随重定向：每一跳都做 SSRF 校验。

        自动重定向模式下 requests 不经过 TargetValidator，目标可用 302
        把扫描器引向内网/云元数据地址。此方法禁用自动重定向，逐跳校验
        （协议白名单 + DNS 解析 + 私网地址拒绝）后才继续。
        """
        cur = url
        resp = None
        for _ in range(6):
            kwargs = dict(timeout=(5, self.__timeout), allow_redirects=False)
            if headers:
                kwargs["headers"] = headers
            resp = self.__session.get(cur, **kwargs)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location")
                if not loc:
                    return resp
                nxt = urljoin(cur, loc)
                TargetValidator.validate(nxt, resolve=True)
                cur = nxt
                continue
            return resp
        return resp

    def fetch(self, url):
        """抓取 URL，返回 PageEvidence；失败抛 TargetError（消息可直接展示）"""
        last_err = None
        for _ in range(self.__retries + 1):
            self.__limiter.wait()
            try:
                resp = self._get_follow(url)
                cookies = {}
                for c in self.__session.cookies:
                    if url.startswith("http"):
                        cookies[c.name] = c.value
                return self.__to_evidence(url, resp, cookies)
            except requests.exceptions.Timeout as e:
                last_err = TargetError("请求超时（%ds）" % self.__timeout)
            except requests.exceptions.ConnectionError as e:
                last_err = TargetError("连接失败：%s" % url)
            except requests.exceptions.RequestException as e:
                last_err = TargetError("请求异常：%s" % e.__class__.__name__)
        raise last_err

    def fetch_bytes(self, url):
        """抓取二进制资源（favicon 等），失败返回 None"""
        self.__limiter.wait()
        try:
            resp = self._get_follow(url)
            if resp.status_code == 200 and resp.content:
                return resp.content
        except requests.exceptions.RequestException:
            return None
        return None

    def get_small(self, url, headers=None):
        """轻量 GET（目录探测/主动指纹用），返回精简 dict；失败抛 TargetError"""
        self.__limiter.wait()
        merged = {}
        if headers:
            merged.update(headers)
        try:
            resp = self._get_follow(url, headers=merged)
        except requests.exceptions.Timeout as e:
            raise TargetError("请求超时")
        except requests.exceptions.RequestException as e:
            raise TargetError("请求失败")
        from bs4 import BeautifulSoup
        title = ""
        body = resp.text or ""
        if body and resp.headers.get("Content-Type", "").startswith(("text/", "application/")):
            try:
                t = BeautifulSoup(body[:20000], "html.parser").find("title")
                title = t.get_text(strip=True)[:120] if t else ""
            except Exception:
                title = ""
        low = url.lower()
        if resp.status_code == 401 and url not in self.seen_401 and len(self.seen_401) < 5:
            self.seen_401.append(url)
        if (("login" in low or "signin" in low or "登录" in title)
                and url not in self.seen_login_pages and len(self.seen_login_pages) < 5):
            self.seen_login_pages.append(url)
        return {
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content or b""),
            "title": title,
            "body": body[:20000],
            "content_type": resp.headers.get("Content-Type", ""),
            "headers": dict(resp.headers),
        }

    def post_form(self, url, fields):
        """表单提交（弱口令审计用）：返回 {status, still_login}"""
        self.__limiter.wait()
        try:
            # POST 本身不跟随重定向；确有跳转时改用经校验的 GET 跟随
            resp = self.__session.post(url, data=fields, timeout=(5, self.__timeout),
                                       allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location")
                if loc:
                    TargetValidator.validate(urljoin(url, loc), resolve=True)
                    resp = self._get_follow(urljoin(url, loc))
        except requests.exceptions.RequestException:
            return None
        text = (resp.text or "")[:20000].lower()
        still = any(k in text for k in ("password", "登录", "login", "sign in"))
        return {"status": resp.status_code, "still_login": still}

    def __to_evidence(self, url, resp, cookies):
        from .models import PageEvidence
        import socket as _socket

        try:
            host = resp.url.split("/")[2].split(":")[0]
            ip = _socket.gethostbyname(host)
        except Exception:
            ip = ""
        body = resp.text if "text" in resp.headers.get("Content-Type", "html") or len(resp.content) < 3_000_000 else ""
        return PageEvidence(
            url=url,
            status=resp.status_code,
            headers=dict(resp.headers),
            cookies=cookies,
            body=body,
            response_time=resp.elapsed.total_seconds(),
            ip=ip,
            final_url=resp.url,
        )
