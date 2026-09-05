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
