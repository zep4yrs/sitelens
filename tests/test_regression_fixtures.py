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


class TestXxCmsRange(unittest.TestCase):
    """xxCMS 类演示靶场：PHP CMS 常见暴露面回归断言。

    样本特征：/admin/ 后台、登录页、phpinfo 探针、www.zip 站点整包、
    dump.sql 数据库备份——五类应全部检出；干净样本不误报。
    """

    def _run(self, pages, level="all"):
        t = ScanTarget("https://xxcms.example.com", resolve=False)
        return checks_mod.run_checks(FakeRangeFetcher(pages), t, level=level)

    def test_xxcms_style_hits(self):
        """xxCMS 演示站：后台 / admin.php + 五类敏感项全检出"""
        pages = {
            "/admin/": (200, "<title>xxCMS 管理后台</title>"),
            "/admin.php": (200, "<title>xxCMS</title>"),
            "/login.php": (200, "<form>user_login password</form>"),
            "/phpinfo.php": (200, "phpinfo() PHP Version 7.4.30"),
            "/www.zip": (200, "PK\x03\x04"),
            "/dump.sql": (200, "CREATE TABLE xxcms_user"),
        }
        hits = {h["check"] for h in self._run(pages, level="all")}
        self.assertIn("admin-path", hits)      # /admin/ 后台
        self.assertIn("phpinfo", hits)         # phpinfo 探针
        self.assertIn("bak-site", hits)        # www.zip 站点整包
        self.assertIn("bak-dump", hits)        # dump.sql 备份
        # 不存在则不误报
        self.assertNotIn("git-leak", hits)
        self.assertNotIn("swagger", hits)

    def test_xxcms_no_backup_no_false_positive(self):
        """干净样本：无备份/phpinfo 时不应误报"""
        pages = {
            "/": (200, "<html>xxCMS home</html>"),
            "/index.php": (200, "<html>xxCMS</html>"),
        }
        hits = {h["check"] for h in self._run(pages, level="all")}
        self.assertNotIn("bak-site", hits)
        self.assertNotIn("bak-dump", hits)
        self.assertNotIn("phpinfo", hits)
        self.assertNotIn("git-leak", hits)

    def test_xxcms_clean_does_not_flag_backup_when_absent(self):
        """xxCMS 干净样本：soft404 基线过滤后 admin 等正常目录不误报备份"""
        notfound = "404 not found page"
        pages = {
            "/admin/": (200, notfound),
            "/www.zip": (200, notfound),
            "/dump.sql": (200, notfound),
            "/phpinfo.php": (200, notfound),
        }
        f = FakeRangeFetcher(pages)
        f.baseline = {"status": 200, "size": len(notfound), "body": notfound}
        t = ScanTarget("https://xxcms.example.com", resolve=False)
        hits = checks_mod.run_checks(_Fixed(f, baseline=(200, notfound)),
                                     t, level="all")
        self.assertEqual([h["check"] for h in hits if h["check"] in (
            "bak-site", "bak-dump", "admin-path", "phpinfo")], [])
