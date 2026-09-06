# -*- coding: utf-8 -*-
"""Phase 1 新增能力测试：版本区间判定 + 验证型 Check 引擎。"""
import os
import unittest

from scanner.target import ScanTarget
from tests.test_sitelens import make_evidence  # 复用取证构造


class TestVersionCmp(unittest.TestCase):
    def test_compare(self):
        from scanner.version_cmp import cmp_version
        self.assertEqual(cmp_version("8.3.7", "8.3.7"), 0)
        self.assertTrue(cmp_version("8.3.7", "8.3") > 0)
        self.assertTrue(cmp_version("6.4", "10.0") < 0)

    def test_ranges(self):
        from scanner.version_cmp import version_in
        self.assertTrue(version_in("8.3.5", ">=8.3,<8.3.7"))
        self.assertFalse(version_in("8.3.7", ">=8.3,<8.3.7"))
        self.assertTrue(version_in("2.4.1", "<=2.4.1"))
        self.assertTrue(version_in("9.9", "*"))
        self.assertFalse(version_in("", ">=1.0"))


class FakeFetcher:
    def __init__(self):
        self.called = []

    def get_small(self, url, headers=None):
        self.called.append(url)
        if "__sl_none__" in url:
            return {"status": 200, "size": 5, "body": "nope", "headers": {}}
        if url.endswith("/.git/HEAD"):
            return {"status": 200, "size": 41, "body": "ref: refs/heads/main",
                    "headers": {}, "title": ""}
        return {"status": 404, "size": 5, "body": "nope", "headers": {}}


class TestCheckEngine(unittest.TestCase):
    def test_hit_and_no_false_positive(self):
        from scanner import checks as checks_mod
        f = FakeFetcher()
        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(f, t, level="all")
        ids = {h["check"] for h in hits}
        self.assertIn("git-leak", ids)
        self.assertNotIn("phpinfo", ids)          # 404 不误报

    def test_levels(self):
        from scanner import checks as checks_mod
        f = FakeFetcher()
        t = ScanTarget("https://example.com", resolve=False)
        core = checks_mod.run_checks(f, t, level="core")
        self.assertTrue(all(h["check"] for h in core))

    def test_baseline_filter(self):
        from scanner import checks as checks_mod
        class SameFetcher(FakeFetcher):
            def get_small(self, url, headers=None):
                return {"status": 200, "size": 10, "body": "same page",
                        "headers": {}, "title": ""}
        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(SameFetcher(), t, level="all")
        self.assertEqual(hits, [])                # 与软 404 基线一致 → 全部过滤


    def test_nuclei_runner_hit(self):
        from scanner import checks as checks_mod
        rows = [{"id": "test-git-config", "name": "Git Config Exposure",
                 "sev": "high", "method": "GET", "path": "/.git/config",
                 "groups": [{"s": [200], "wany": ["[core]"]}]}]

        class FakeFetcher:
            def get_small(self, url, headers=None):
                if url.endswith("/.git/config"):
                    body = chr(91) + "core" + chr(93) + " repository = x"
                    return {"status": 200, "size": 22,
                            "body": body, "headers": {}}
                return {"status": 404, "size": 5, "body": "nope", "headers": {}}

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_nuclei(FakeFetcher(), t, rows)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["check"], "test-git-config")
        self.assertEqual(hits[0]["src"], "nuclei")


    def test_cms_scheduling(self):
        from scanner import checks as checks_mod
        calls = []

        class FakeFetcher:
            def get_small(self, url, headers=None):
                calls.append(url)
                if url.endswith("/__sl_none__"):
                    return {"status": 404, "size": 5, "body": "x", "headers": {}}
                if url.endswith("/wp-login.php"):
                    return {"status": 200, "size": 900,
                            "body": "user_login wp-submit", "headers": {}}
                return {"status": 404, "size": 5, "body": "x", "headers": {}}

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(FakeFetcher(), t, level="core",
                                     include_ids={"wp-login"})
        ids = {h["check"] for h in hits}
        self.assertIn("wp-login", ids)            # 联动强制包含（等级不足也跑）

    def test_cms_map_covers(self):
        from scanner.checks import CHECKS, CMS_TECH_CHECKS
        known = {c[0] for c in CHECKS}
        for tech, ids in CMS_TECH_CHECKS.items():
            for cid in ids:
                self.assertIn(cid, known, f"{tech} 的 {cid} 不在 check 库")


    def test_taint_flow(self):
        import tempfile
        from scanner.taint import analyze_file
        nl = chr(10)
        code = nl.join([
            "import os",
            "def run():",
            "    cmd = input()",
            '    os.' + 'system(cmd)',
        ])
        f = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
        f.write(code)
        f.close()
        hits = analyze_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any(h["sink"] == "os.system" for h in hits))


    def test_semantic_routing(self):
        """无 tag 硬匹配时，语义向量应把相关模板排到前面"""
        from scanner import checks as checks_mod
        rows = [
            {"id": "telnet-old", "name": "Telnet banner without encryption",
             "sev": "high", "tags": ["telnet"], "method": "GET",
             "path": "/t", "groups": []},
            {"id": "grafana-ssrf", "name": "Grafana dashboard SSRF proxy",
             "sev": "medium", "tags": ["grafana"], "method": "GET",
             "path": "/g", "groups": []},
        ]
        old_loader = checks_mod.load_nuclei
        old_vecs = checks_mod._nuclei_vecs
        checks_mod.load_nuclei = lambda: rows
        checks_mod._nuclei_vecs = None
        try:
            sel = checks_mod.select_nuclei(
                cap=2, query_text="grafana dashboard proxy ssrf")
            self.assertEqual(sel[0]["id"], "grafana-ssrf")   # 语义路由命中
        finally:
            checks_mod.load_nuclei = old_loader
            checks_mod._nuclei_vecs = old_vecs

    def test_tag_match_beats_semantic(self):
        from scanner import checks as checks_mod
        rows = [
            {"id": "grafana-ssrf", "name": "Grafana dashboard SSRF proxy",
             "sev": "medium", "tags": ["grafana"], "method": "GET",
             "path": "/g", "groups": []},
            {"id": "wp-core", "name": "WordPress core file",
             "sev": "high", "tags": ["wordpress"], "method": "GET",
             "path": "/w", "groups": []},
        ]
        old_loader = checks_mod.load_nuclei
        old_vecs = checks_mod._nuclei_vecs
        checks_mod.load_nuclei = lambda: rows
        checks_mod._nuclei_vecs = None
        try:
            sel = checks_mod.select_nuclei(
                cap=2, tech_tags=("wordpress",),
                query_text="grafana dashboard proxy")
            self.assertEqual(sel[0]["id"], "wp-core")        # tag 硬匹配优先
        finally:
            checks_mod.load_nuclei = old_loader
            checks_mod._nuclei_vecs = old_vecs


    def test_org_domain(self):
        from scanner.netsec import org_domain
        self.assertEqual(org_domain("tools.example.com"), "example.com")
        self.assertEqual(org_domain("blog.co.uk"), "blog.co.uk")
        self.assertEqual(org_domain("example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()


class TestDastJudge(unittest.TestCase):
    def test_reflected_xss_judge(self):
        from scanner import dast as dast_mod
        class F:
            def get_small(self, url, headers=None):
                body = "<p>x " + dast_mod.XSS_RAW + "</p>"
                return {"status": 200, "size": 50, "body": body, "headers": {}}
        links = [("https://example.com/search?q=a", "https://example.com")]
        t = ScanTarget("https://example.com", resolve=False)
        hits = dast_mod.run_dast(F(), t, links)
        self.assertTrue(any(h["check"] == "xss-reflect" for h in hits))

    def test_sqli_error_judge(self):
        from scanner import dast as dast_mod
        class F:
            def get_small(self, url, headers=None):
                if "'" in url or "%27" in url:
                    return {"status": 200, "size": 50,
                            "body": "warning: mysql_fetch_array() expects", "headers": {}}
                return {"status": 200, "size": 10, "body": "ok", "headers": {}}
        links = [("https://example.com/item?id=3", "https://example.com")]
        t = ScanTarget("https://example.com", resolve=False)
        hits = dast_mod.run_dast(F(), t, links)
        self.assertTrue(any(h["check"] == "sqli-error" for h in hits))


    def test_cms_scheduling(self):
        from scanner import checks as checks_mod
        calls = []

        class FakeFetcher:
            def get_small(self, url, headers=None):
                calls.append(url)
                if url.endswith("/__sl_none__"):
                    return {"status": 404, "size": 5, "body": "x", "headers": {}}
                if url.endswith("/wp-login.php"):
                    return {"status": 200, "size": 900,
                            "body": "user_login wp-submit", "headers": {}}
                return {"status": 404, "size": 5, "body": "x", "headers": {}}

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(FakeFetcher(), t, level="core",
                                     include_ids={"wp-login"})
        ids = {h["check"] for h in hits}
        self.assertIn("wp-login", ids)            # 联动强制包含（等级不足也跑）

    def test_cms_map_covers(self):
        from scanner.checks import CHECKS, CMS_TECH_CHECKS
        known = {c[0] for c in CHECKS}
        for tech, ids in CMS_TECH_CHECKS.items():
            for cid in ids:
                self.assertIn(cid, known, f"{tech} 的 {cid} 不在 check 库")


    def test_semantic_routing(self):
        """无 tag 硬匹配时，语义向量应把相关模板排到前面"""
        from scanner import checks as checks_mod
        rows = [
            {"id": "telnet-old", "name": "Telnet banner without encryption",
             "sev": "high", "tags": ["telnet"], "method": "GET",
             "path": "/t", "groups": []},
            {"id": "grafana-ssrf", "name": "Grafana dashboard SSRF proxy",
             "sev": "medium", "tags": ["grafana"], "method": "GET",
             "path": "/g", "groups": []},
        ]
        old_loader = checks_mod.load_nuclei
        old_vecs = checks_mod._nuclei_vecs
        checks_mod.load_nuclei = lambda: rows
        checks_mod._nuclei_vecs = None
        try:
            sel = checks_mod.select_nuclei(
                cap=2, query_text="grafana dashboard proxy ssrf")
            self.assertEqual(sel[0]["id"], "grafana-ssrf")   # 语义路由命中
        finally:
            checks_mod.load_nuclei = old_loader
            checks_mod._nuclei_vecs = old_vecs

    def test_tag_match_beats_semantic(self):
        from scanner import checks as checks_mod
        rows = [
            {"id": "grafana-ssrf", "name": "Grafana dashboard SSRF proxy",
             "sev": "medium", "tags": ["grafana"], "method": "GET",
             "path": "/g", "groups": []},
            {"id": "wp-core", "name": "WordPress core file",
             "sev": "high", "tags": ["wordpress"], "method": "GET",
             "path": "/w", "groups": []},
        ]
        old_loader = checks_mod.load_nuclei
        old_vecs = checks_mod._nuclei_vecs
        checks_mod.load_nuclei = lambda: rows
        checks_mod._nuclei_vecs = None
        try:
            sel = checks_mod.select_nuclei(
                cap=2, tech_tags=("wordpress",),
                query_text="grafana dashboard proxy")
            self.assertEqual(sel[0]["id"], "wp-core")        # tag 硬匹配优先
        finally:
            checks_mod.load_nuclei = old_loader
            checks_mod._nuclei_vecs = old_vecs


    def test_org_domain(self):
        from scanner.netsec import org_domain
        self.assertEqual(org_domain("tools.example.com"), "example.com")
        self.assertEqual(org_domain("blog.co.uk"), "blog.co.uk")
        self.assertEqual(org_domain("example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- M7 被动检测 + P0 版本焊接
from scanner.models import Technology


class TestPassiveChecks(unittest.TestCase):
    """Cookie 属性 + CSRF token 存在性（纯只读）"""

    def _evidence(self, **kw):
        from tests.test_sitelens import make_evidence
        return make_evidence(**kw)

    def test_cookie_missing_httponly_and_samesite(self):
        from scanner.passive import check_cookie_attrs
        ev = self._evidence(headers={
            "Content-Type": "text/html",
            "Set-Cookie": "PHPSESSID=abc123; Path=/"})
        hits = check_cookie_attrs(ev, "https://example.com")
        self.assertEqual(len(hits), 1)
        self.assertIn("HttpOnly", hits[0]["evidence"])
        self.assertIn("SameSite", hits[0]["evidence"])
        self.assertIn("Secure", hits[0]["evidence"])      # https 下也提示 Secure
        self.assertEqual(hits[0]["severity"], "medium")

    def test_cookie_all_attrs_ok(self):
        from scanner.passive import check_cookie_attrs
        ev = self._evidence(headers={
            "Content-Type": "text/html",
            "Set-Cookie": "sid=t; Path=/; HttpOnly; Secure; SameSite=Lax"})
        self.assertEqual(check_cookie_attrs(ev, "https://example.com"), [])

    def test_cookie_multi_header_and_session_fallback(self):
        """多 Set-Cookie 合并头切分 + 仅会话 Cookie 的 Secure 交叉提示"""
        from scanner.passive import check_cookie_attrs
        ev = self._evidence(
            headers={"Content-Type": "text/html",
                     "Set-Cookie": "a=1; HttpOnly, b=2; SameSite=Strict"},
            cookies={"session_x": "v"})
        hits = check_cookie_attrs(ev, "https://example.com")
        names = {h["title"] for h in hits}
        self.assertTrue(any("a" in n for n in names))     # a：缺 Secure/SameSite
        self.assertTrue(any("b" in n for n in names))     # b：缺 HttpOnly/Secure
        self.assertTrue(any("session_x" in n for n in names))
        sess = next(h for h in hits if "session_x" in h["title"])
        self.assertIn("Secure", sess["evidence"])         # 属性未知只提示 Secure
        self.assertNotIn("HttpOnly", sess["evidence"])
        self.assertEqual(sess["severity"], "low")

    def test_cookie_http_no_secure_warning(self):
        from scanner.passive import check_cookie_attrs
        ev = self._evidence(headers={
            "Content-Type": "text/html", "Set-Cookie": "s=1; HttpOnly"})
        hits = check_cookie_attrs(ev, "http://example.com")
        self.assertEqual(len(hits), 1)
        self.assertNotIn("Secure", hits[0]["evidence"])   # http 站不提示 Secure

    def test_csrf_token_present_and_absent(self):
        from scanner.passive import check_csrf_tokens
        body_with = ("<form action='/login'><input name='csrf_token' type='hidden'>"
                     "<input type='password' name='pass'></form>")
        ev = self._evidence(body=body_with)
        self.assertEqual(check_csrf_tokens(ev, "https://example.com"), [])
        body_without = ("<form action='/login'><input name='user'>"
                        "<input type='password' name='pass'></form>")
        ev2 = self._evidence(body=body_without)
        hits = check_csrf_tokens(ev2, "https://example.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["check"], "form-no-csrf")
        self.assertEqual(hits[0]["severity"], "low")

    def test_csrf_ignores_non_sensitive_forms(self):
        from scanner.passive import check_csrf_tokens
        body = ("<form action='/search'><input name='q'></form>"
                "<form action='/sub'><input name='email'></form>")
        ev = self._evidence(body=body)
        hits = check_csrf_tokens(ev, "https://example.com")
        self.assertEqual(len(hits), 1)                    # 仅 email 表单提示（email 属身份输入）
        self.assertIn("/sub", hits[0]["url"])             # 搜索表单（q）被忽略

    def test_csrf_no_form(self):
        from scanner.passive import check_csrf_tokens
        ev = self._evidence(body="<p>no form</p>")
        self.assertEqual(check_csrf_tokens(ev, "https://example.com"), [])

    def test_run_passive_zero_extra_requests(self):
        """被动检测不得发起任何请求：run_passive 只吃 PageEvidence"""
        from scanner.passive import run_passive
        ev = self._evidence(
            headers={"Content-Type": "text/html",
                     "Set-Cookie": "sid=1; Path=/"},
            body="<form><input type='password' name='pwd'></form>")
        hits = run_passive(ev, "https://example.com")
        self.assertEqual({h["check"] for h in hits},
                         {"cookie-attr", "form-no-csrf"})


class TestExtractVersion(unittest.TestCase):
    """P0 焊接点：extractor 版本抽取"""

    def test_basic_extract(self):
        from scanner.version_cmp import extract_version
        self.assertEqual(extract_version("nginx/1.24.0", "nginx"), "1.24.0")
        self.assertEqual(extract_version("X: v2.4.1-beta", "x"), "2.4.1")
        self.assertEqual(extract_version("no version here"), "")

    def test_keyword_line_priority(self):
        from scanner.version_cmp import extract_version
        text = "server: nginx 1.18.0\nmodule: php 8.2.1"
        self.assertEqual(extract_version(text, "php"), "8.2.1")
        self.assertEqual(extract_version(text, "nginx"), "1.18.0")

    def test_plain_number_not_version(self):
        from scanner.version_cmp import extract_version
        self.assertEqual(extract_version("copyright 2024 id 99"), "")


class TestVersionWelding(unittest.TestCase):
    """check 抽取值 → 版本回填 → version_cmp 三级判定"""

    def test_check_extract_output(self):
        from scanner import checks as checks_mod

        class F:
            def get_small(self, url, headers=None):
                if "__sl_none__" in url:
                    return {"status": 404, "size": 5, "body": "x", "headers": {}}
                if url.endswith("/readme.html"):
                    return {"status": 200, "size": 40,
                            "body": "WordPress 6.4.2 Version 6.4.2", "headers": {}}
                return {"status": 404, "size": 5, "body": "x", "headers": {}}

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(F(), t, level="all",
                                     include_ids={"wp-version-leak-readme"})
        target = next(h for h in hits if h["check"] == "wp-version-leak-readme")
        self.assertEqual(target["extracted_version"], "6.4.2")

    def test_engine_version_backfill_and_verdict(self):
        """extracted_version 回填无版本技术，并按受影响区间出 confirmed"""
        from scanner.engine import ScannerEngine
        eng = ScannerEngine.__new__(ScannerEngine)
        eng._ranges = {"wordpress": [
            {"affected": "<6.4.3", "cve": "CVE-TEST-1", "title": "test"}]}

        class Tech:
            name = "WordPress"
            version = None

            def set_version(self, v):
                self.version = v

        class Result:
            def __init__(self):
                self.technologies = [Tech()]
                self.verified = [{
                    "check": "wp-version-leak-readme",
                    "extracted_version": "6.4.2"}]

        res = Result()
        eng._apply_extracted_versions(res)
        self.assertEqual(res.technologies[0].version, "6.4.2")   # 版本已回填
        hit = res.verified[0]
        self.assertEqual(hit["verdict"], "confirmed")            # 三级判定命中
        self.assertIn("CVE-TEST-1", hit["verdict_detail"])

    def test_engine_no_backfill_when_version_known(self):
        """已有版本的技術不被回填（指纹识别优先）"""
        from scanner.engine import ScannerEngine
        eng = ScannerEngine.__new__(ScannerEngine)
        eng._ranges = {}

        class Tech:
            name = "WordPress"
            version = "6.5.0"

            def set_version(self, v):
                raise AssertionError("已有版本不应被覆盖")

        class Result:
            technologies = [Tech()]
            verified = [{"check": "wp-x", "extracted_version": "6.4.2"}]

        eng._apply_extracted_versions(Result())   # 不抛即通过

    def test_nuclei_extract_output(self):
        from scanner import checks as checks_mod
        rows = [{"id": "t-extract", "name": "Ver Leak", "sev": "low",
                 "method": "GET", "path": "/ver.txt",
                 "groups": [{"s": [200], "wany": ["ver"]}],
                 "extract": {"keyword": "app"}}]

        class F:
            def get_small(self, url, headers=None):
                if "__sl_none__" in url:
                    return {"status": 404, "size": 5, "body": "x", "headers": {}}
                if url.endswith("/ver.txt"):
                    return {"status": 200, "size": 20,
                            "body": "app version: 3.1.4", "headers": {}}
                return {"status": 404, "size": 5, "body": "x", "headers": {}}

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_nuclei(F(), t, rows)
        self.assertEqual(hits[0].get("extracted_version"), "3.1.4")


class TestPunctTechMatch(unittest.TestCase):
    """守门边界：含标点/别名的单名技术必须能被 hit 命中（焊接路不断）"""

    def _run(self, names, hit):
        from scanner.engine import ScannerEngine

        class T:
            def __init__(s, n):
                s.name = n
                s.version = None

            def set_version(s, v):
                s.version = v

        eng = ScannerEngine.__new__(ScannerEngine)
        techs = [T(n) for n in names]
        by_name = {t.name.lower(): t for t in techs}
        return eng._match_tech_for_hit(hit, by_name)

    def test_punct_single_name_hit(self):
        """含标点单名（Next.js）不再永远匹配不上"""
        got = self._run(["Next.js"], {"url": "/next.js readme 12.0.1"})
        self.assertIsNotNone(got)
        self.assertEqual(got.name, "Next.js")

    def test_bracket_alias_hit(self):
        """括号别名（11ty (Eleventy)）：任一别名出现即命中"""
        for text in ("/blog 11ty readme 2.0", "generator eleventy 2.0"):
            got = self._run(["11ty (Eleventy)"], {"title": text})
            self.assertIsNotNone(got, text)
        self.assertIsNone(self._run(["11ty (Eleventy)"],
                                    {"title": "generator hugo 0.1"}))

    def test_word_boundary_still_holds(self):
        """拆词匹配不破坏词边界：子串/单词/错误复数不命中"""
        self.assertIsNone(self._run(["node.js"], {"url": "/nodes.js fake 1.0"}))
        self.assertIsNone(self._run(["next.js"], {"url": "/next 1.0"}))
        self.assertIsNone(self._run(["next.js"], {"url": "/js 1.0"}))
        self.assertIsNone(self._run(["php"], {"check": "phpinfo leak"}))
        self.assertIsNone(self._run(["wordpress"], {"url": "/wordpresss-x"}))

    def test_multiword_and_abbrev_regression(self):
        """原有多词与缩写路径回归不串"""
        got = self._run(["apache", "apache tomcat"], {"title": "apache tomcat 9"})
        self.assertEqual(got.name, "apache tomcat")
        got = self._run(["WordPress"], {"check": "wp-x", "title": "wp login"})
        self.assertEqual(got.name, "WordPress")


class TestCookieValueComma(unittest.TestCase):
    """守门边界：Set-Cookie 值内逗号不再过切出幽灵 cookie"""

    def _hits(self, raw):
        from scanner.models import PageEvidence
        from scanner.passive import check_cookie_attrs
        ev = PageEvidence(url="https://example.com", status=200,
                          headers={"Content-Type": "text/html",
                                   "Set-Cookie": raw},
                          cookies={}, body="", title="")
        return check_cookie_attrs(ev, "https://example.com")

    def test_value_comma_not_split(self):
        """值内 ,name= 不产生幽灵 cookie"""
        hits = self._hits("t=foo,bar=baz; Path=/")
        self.assertEqual(len(hits), 1)
        self.assertIn("t", hits[0]["title"])

    def test_quoted_value_comma_not_split(self):
        """引号值内逗号保持一体"""
        hits = self._hits('cfg="a,b=c"; Path=/')
        self.assertEqual(len(hits), 1)
        self.assertIn("cfg", hits[0]["title"])

    def test_real_boundary_still_split(self):
        """真实多头边界仍正常拆分"""
        hits = self._hits("a=1;HttpOnly, b=2;SameSite=Strict")
        self.assertEqual(len(hits), 2)
        names = " ".join(h["title"] for h in hits)
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_expires_comma_and_mixed(self):
        """Expires 日期逗号不误切 + 值内逗号与真实边界混合场景"""
        hits = self._hits(
            'cfg="a,b=c"; Path=/, u=2; HttpOnly')
        titles = " ".join(h["title"] for h in hits)
        self.assertIn("cfg", titles)
        self.assertIn("u", titles)
        self.assertEqual(len(hits), 2)
