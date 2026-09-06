# -*- coding: utf-8 -*-
"""离线靶场回归断言：用内置的 DVWA/pikachu 风格 fixture 页面，
断言 check 引擎能检出对应的已知项——无需真实靶场即可验证检测有效性。

对应开发方案 Phase 2 验收标准的离线版；实弹回归用 tools/regression.py。
"""
import unittest

from scanner import checks as checks_mod
from scanner.target import ScanTarget


class FakeRangeFetcher:
    """可编程假站点：按路径返回预置响应（模拟 DVWA/pikachu 靶场特征）"""

    def __init__(self, pages):
        self.pages = pages          # {path: (status, body)}
        self.baseline = {"status": 200, "size": 7, "body": "no page"}

    def get_small(self, url, headers=None):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        status, body = self.pages.get(path, (self.baseline["status"], self.baseline["body"]))
        return {"url": url, "status": status, "size": len(body), "title": "",
                "body": body, "content_type": "text/html", "headers": {}}


class TestOfflineRange(unittest.TestCase):
    def _run(self, pages, level="all", include=None):
        t = ScanTarget("https://range.example.com", resolve=False)
        return checks_mod.run_checks(FakeRangeFetcher(pages), t, level=level,
                                     progress=None, include_ids=include)

    def test_dvwa_style_hits(self):
        """DVWA 特征：弱口令登录页 / phpinfo / 配置备份"""
        pages = {
            "/login.php": (200, "<title>DVWA</title><form>user_login password</form>"),
            "/phpinfo.php": (200, "phpinfo() PHP Version 8.1"),
            "/wp-config.php.bak": (200, "DB_PASSWORD 'secret'"),
        }
        hits = {h["check"] for h in self._run(pages, level="all")}
        self.assertIn("phpinfo", hits)
        self.assertIn("bak-config", hits)

    def test_pikachu_style_hits(self):
        """pikachu 特征：登录入口与 admin 目录"""
        pages = {
            "/admin/": (200, "<title>后台管理</title>"),
            "/login": (200, "<form>login</form>"),
        }
        hits = {h["check"] for h in self._run(pages, level="all")}
        self.assertIn("admin-path", hits)
        self.assertIn("login-root", hits)

    def test_clean_site_no_false_positive(self):
        """干净站点不应误报"""
        pages = {"/": (200, "<html>normal site</html>")}
        hits = self._run(pages, level="all")
        self.assertEqual(len(hits), 0)

    def test_soft404_baseline(self):
        """自定义 404 页统一返回 200 时不应误报"""
        pages = {"/.git/HEAD": (200, "<html>404 not found page</html>")}
        f = FakeRangeFetcher(pages)
        f.baseline = {"status": 200, "size": len("404 not found page"), "body": "404 not found page"}
        t = ScanTarget("https://range.example.com", resolve=False)
        hits = checks_mod.run_checks(_Fixed(f, baseline=(f.baseline["status"], f.baseline["body"])),
                                     t, level="all")
        self.assertEqual([h["check"] for h in hits if h["check"] == "git-leak"], [])


class _Fixed:
    """把软 404 基线固定为给定响应的适配器"""

    def __init__(self, inner, baseline):
        self._inner = inner
        self._base = baseline

    def get_small(self, url, headers=None):
        r = self._inner.get_small(url, headers)
        if "__sl_none__" in url:
            return {"status": self._base[0], "size": len(self._base[1]),
                    "body": self._base[1], "content_type": "text/html", "headers": {}}
        return r


if __name__ == "__main__":
    unittest.main()


class TestXxCmsFixture(unittest.TestCase):
    """xxCMS 类演示靶场样本：泛 PHP 内容管理站（非 DVWA/pikachu）。

    特征：后台 /admin/、登录入口 /login、phpinfo 探针、
    站点整包 www.zip、数据库 dump.sql —— 验证这类"备份/探针/后台"
    泄露在通用 check 引擎下能被独立检出。
    """

    def _run(self, pages):
        t = ScanTarget("https://xxcms.example.com", resolve=False)
        return checks_mod.run_checks(FakeRangeFetcher(pages), t, level="all",
                                     include_ids=None)

    def test_xxcms_style_hits(self):
        """xxCMS 演示样本：五类泄露检出"""
        pages = {
            "/admin/": (200, "<html><title>xxCMS 后台管理</title></html>"),
            "/login": (200, "<form action='/do-login'><input name='u'></form>"),
            "/phpinfo.php": (200, "phpinfo() PHP Version 7.4.33"),
            "/www.zip": (200, "PK\x03\x04源码整包站点备份"),
            "/dump.sql": (200, "CREATE TABLE xxcms_users;"),
        }
        hits = {h["check"] for h in self._run(pages)}
        self.assertIn("admin-path", hits)     # 后台入口
        self.assertIn("login-root", hits)     # 登录入口
        self.assertIn("phpinfo", hits)        # phpinfo 探针
        self.assertIn("bak-site", hits)       # www.zip 站点整包
        self.assertIn("bak-dump", hits)       # dump.sql

    def test_xxcms_no_backup_no_false_positive(self):
        """干净 xxCMS 样本：不误报备份/探针/后台泄露"""
        pages = {
            "/": (200, "<html><title>xxCMS 官网</title><body>normal</body></html>"),
            "/index.php": (200, "<html><title>首页</title></html>"),
            "/article.php?id=1": (200, "<html><article>hello</article></html>"),
        }
        hits = {h["check"] for h in self._run(pages)}
        for leak in ("bak-site", "bak-dump", "phpinfo", "bak-config",
                     "git-leak", "env-leak"):
            self.assertNotIn(leak, hits, "%s 不应在干净样本上误报" % leak)


if __name__ == "__main__":
    unittest.main()
