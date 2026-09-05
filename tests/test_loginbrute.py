# -*- coding: utf-8 -*-
"""登录爆破模块测试：表单解析 / 命中判定 / 字典上限。"""
import unittest

from scanner.loginbrute import MAX_TRIES, analyze_login_form, brute_login, load_list

LOGIN_HTML = """<html><body>
<form action="/do-login" method="post">
  <input type="hidden" name="csrf" value="tok123">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">登录</button>
</form></body></html>"""


class FakeFetcher:
    """模拟登录端点：正确口令 secret123 返回跳转态，其余返回登录页"""

    def __init__(self, good_password):
        self.good = good_password
        self.posts = []

    def get_small(self, url, headers=None):
        return {"status": 200, "size": len(LOGIN_HTML),
                "body": LOGIN_HTML, "content_type": "text/html", "headers": {}}

    def post_form(self, url, fields):
        self.posts.append((url, dict(fields)))
        if fields.get("password") == self.good:
            return {"status": 302, "still_login": False, "size": 0}
        return {"status": 200, "still_login": True, "size": 900,
                "body": "<form>password</form>", "headers": {}}


class TestAnalyzeForm(unittest.TestCase):
    def test_fields_and_hidden(self):
        form = analyze_login_form(LOGIN_HTML, "https://x.com/login")
        self.assertEqual(form["action"], "https://x.com/do-login")
        self.assertEqual(form["method"], "post")
        self.assertEqual(form["user_field"], "username")
        self.assertEqual(form["pass_field"], "password")
        self.assertEqual(form["hidden"].get("csrf"), "tok123")

    def test_no_password_form(self):
        self.assertIsNone(
            analyze_login_form("<form><input name='q'></form>", "https://x.com"))


class TestBrute(unittest.TestCase):
    def test_hit_and_stop(self):
        f = FakeFetcher("letmein9")
        users = ["admin", "root"]
        pwds = ["123456", "letmein9", "password"]
        hits = brute_login(f, "https://x.com/login", users, pwds)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["user"], "admin")
        self.assertEqual(hits[0]["password"], "letmein9")
        self.assertLessEqual(len(f.posts), 7)       # 命中即停（基线 1 + 5 组）

    def test_max_tries_cap(self):
        f = FakeFetcher("never-matches")
        brute_login(f, "https://x.com/login", ["a", "b"], ["1", "2", "3"], max_tries=4)
        self.assertLessEqual(len(f.posts), 4)

    def test_load_list(self):
        rows = load_list("data/wordlists/weak_users.txt", 5)
        self.assertTrue(1 <= len(rows) <= 5)


if __name__ == "__main__":
    unittest.main()
