# -*- coding: utf-8 -*-
"""SiteLens 单元测试（标准库 unittest，不依赖网络与真实 PG 的用例为主）。

运行：python -m unittest discover -s tests -v
"""
import unittest
from unittest.mock import MagicMock

from scanner.detectors import build_detectors
from scanner.detectors.tscan_detector import TscanDetector
from scanner.embedding import cosine, embed_text
from scanner.evidence import extract_signals
from scanner.engine import ScannerEngine
from scanner.models import PageEvidence, ScanResult, Technology
from scanner.registry import validate_fingerprints
from scanner.security import SecurityReport
from scanner.target import ScanTarget, TargetError, TargetValidator


def make_evidence(body="", headers=None, cookies=None, title=""):
    headers = headers or {"Content-Type": "text/html"}
    return PageEvidence(url="https://example.com", status=200, headers=headers,
                        cookies=cookies or {}, body=body, title=title)


# ---------------------------------------------------------------- 目标校验（SSRF）
class TestTargetValidator(unittest.TestCase):
    def test_accepts_public_https(self):
        scheme, host, port = TargetValidator.validate("example.com", resolve=False)
        self.assertEqual(("https", "example.com", None), (scheme, host, port))

    def test_rejects_non_http_scheme(self):
        for url in ("ftp://example.com", "file:///etc/passwd", "gopher://x"):
            with self.assertRaises(TargetError):
                TargetValidator.validate(url)

    def test_rejects_localhost_and_private(self):
        for url in ("localhost", "http://127.0.0.1/", "http://10.0.0.1/",
                    "http://192.168.1.1/", "http://172.16.0.9/", "http://169.254.1.1/",
                    "http://[::1]/", "http://metadata.google.internal/"):
            with self.assertRaises(TargetError):
                TargetValidator.validate(url)

    def test_rejects_empty(self):
        with self.assertRaises(TargetError):
            TargetValidator.validate("   ")

    def test_same_site_scope(self):
        target = ScanTarget("https://example.com/x", resolve=False)
        self.assertTrue(target.same_site("https://example.com/a"))
        self.assertFalse(target.same_site("https://evil.com/a"))


# ---------------------------------------------------------------- 指纹检测器
class TestDetectors(unittest.TestCase):
    def _detectors(self, extra_tscan=None):
        fps = [
            {"name": "Nginx", "cats": ["web-server"], "conf": 100,
             "rules": {"headers": {"server": [r"nginx(?:/([\d.]+))?"]}}},
            {"name": "WordPress", "cats": ["cms"], "conf": 100,
             "rules": {"meta": {"generator": r"WordPress\s*([\d.]+)?"},
                       "html": {"html": ["wp-content"], "dom": ["#wpadminbar"]}}},
            {"name": "Django", "cats": ["web-framework"], "conf": 95,
             "rules": {"cookies": [r"^csrftoken$"]}},
            {"name": "jQuery", "cats": ["js-library"], "conf": 95,
             "rules": {"scripts": {"src": [r"jquery[.-]?([\d.]+)?(\.min)?\.js"]}}},
            {"name": "Bootstrap", "cats": ["ui-framework"], "conf": 85,
             "rules": {"html": {"dom": ["[data-bs-toggle]"]}}},
        ]
        return fps, build_detectors(fps, extra_tscan)

    def test_header_detector_version(self):
        _, detectors = self._detectors()
        ev = make_evidence(headers={"Server": "nginx/1.24.0", "Content-Type": "text/html"})
        hits = {}
        for d in detectors:
            for name, detail, ver in d.detect(ev, None):
                hits.setdefault(name, set()).add(ver)
        self.assertIn("Nginx", hits)
        self.assertIn("1.24.0", hits["Nginx"])

    def test_meta_and_cookie_and_script(self):
        _, detectors = self._detectors()
        body = ('<meta name="generator" content="WordPress 6.4.2">'
                '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>')
        from scanner.evidence import extract_signals
        ev = make_evidence(body=body, cookies={"csrftoken": "abc"})
        sig = extract_signals(ev)
        names = set()
        versions = {}
        for d in detectors:
            for name, detail, ver in d.detect(ev, sig):
                names.add(name)
                if ver:
                    versions.setdefault(name, ver)
        self.assertIn("WordPress", names)
        self.assertIn("Django", names)
        self.assertIn("jQuery", names)
        self.assertEqual(versions.get("WordPress"), "6.4.2")

    def test_dom_selector_hit(self):
        _, detectors = self._detectors()
        ev = make_evidence(body='<button data-bs-toggle="modal">x</button>')
        sig = extract_signals(ev)
        names = set()
        for d in detectors:
            for name, _, _ in d.detect(ev, sig):
                names.add(name)
        self.assertIn("Bootstrap", names)


# ---------------------------------------------------------------- Tscan 表达式
class TestTscanDetector(unittest.TestCase):
    def _tscan(self):
        return [
            {"name": "Nacos", "cat": "middleware",
             "groups": [[{"f": "body", "n": False, "v": "console-ui"},
                         {"f": "title", "n": False, "v": "Nacos"}]]},
            {"name": "ShortName", "cat": "misc",
             "groups": [[{"f": "body", "n": False, "v": "plex"}]]},
            {"name": "NotCloud", "cat": "misc",
             "groups": [[{"f": "header", "n": True, "v": "cf-ray"}]]},
        ]

    def test_and_group(self):
        det = TscanDetector(self._tscan())
        ev = make_evidence(body="window.console-ui config", title="Nacos Console")
        names = [h[0] for h in det.detect(ev, None)]
        self.assertIn("Nacos", names)

    def test_and_group_negative(self):
        det = TscanDetector(self._tscan())
        ev = make_evidence(body="console-ui only", title="no")
        names = [h[0] for h in det.detect(ev, None)]
        self.assertNotIn("Nacos", names)

    def test_short_word_boundary(self):
        det = TscanDetector(self._tscan())
        ev = make_evidence(body="this is a complex sentence")
        names = [h[0] for h in det.detect(ev, None)]
        self.assertNotIn("ShortName", names)     # complex 不应命中 plex

    def test_header_negation(self):
        det = TscanDetector(self._tscan())
        ev = make_evidence(body="x", headers={"Server": "nginx"})
        names = [h[0] for h in det.detect(ev, None)]
        self.assertIn("NotCloud", names)          # 没有 cf-ray → 非 条件成立
        ev2 = make_evidence(body="x", headers={"cf-ray": "abc"})
        names2 = [h[0] for h in det.detect(ev2, None)]
        self.assertNotIn("NotCloud", names2)


# ---------------------------------------------------------------- 安全评分 / 向量 / 校验
class TestSecurityAndEmbedding(unittest.TestCase):
    def test_security_grade(self):
        rep = SecurityReport()
        rep.assess(make_evidence(headers={
            "strict-transport-security": "max-age=0",
            "content-security-policy": "default-src 'self'",
        }))
        self.assertLessEqual(rep.score, 50)
        self.assertEqual(rep.grade, "D")

    def test_embedding_similarity(self):
        a = embed_text("grafana directory traversal CVE-2021-43798")
        b = embed_text("grafana path traversal")
        c = embed_text("mysql password reset")
        self.assertGreater(cosine(a, b), cosine(a, c))

    def test_validate_fingerprints(self):
        fps = [{"name": "ok", "cats": ["cms"], "rules": {"headers": {"server": ["nginx"]}}},
               {"name": "bad-cat", "cats": ["nope"], "rules": {}},
               {"name": "bad-re", "cats": ["cms"], "rules": {"html": {"html": ["([bad"]}}}]
        errors = validate_fingerprints(fps, {"cms"})
        self.assertEqual(len(errors), 2)

    def test_dom_selectors_not_compiled_as_regex(self):
        fps = [{"name": "sel", "cats": ["cms"], "rules": {"html": {"dom": ["[x-data]"]}}}]
        self.assertEqual(validate_fingerprints(fps, {"cms"}), [])


# ---------------------------------------------------------------- 引擎与导出（mock 取证）
class FakeFetcher:
    """假抓取器：返回预置响应，隔离网络"""

    def __init__(self, evidence):
        self._evidence = evidence

    def fetch(self, url):
        return self._evidence

    def fetch_bytes(self, url):
        return None

    def get_small(self, url, headers=None):
        return {"url": url, "status": 404, "size": 0, "title": "",
                "body": "", "content_type": "", "headers": {}}


class TestEngine(unittest.TestCase):
    def test_engine_end_to_end_mock(self):
        body = ('<html><head><title>Demo</title>'
                '<meta name="generator" content="WordPress 6.4">'
                '</head><body><div id="wpadminbar"></div>'
                '<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>'
                "</body></html>")
        ev = make_evidence(body=body,
                           headers={"Server": "Caddy", "Content-Type": "text/html"},
                           title="Demo")
        engine = ScannerEngine.__new__(ScannerEngine)   # 跳过 PG 初始化
        engine._resolve = False
        from scanner.detectors import build_detectors
        engine._detectors = build_detectors(engine_registry_stub().fingerprints, None)
        engine.fetcher = FakeFetcher(ev)
        engine.options = {"deep": False}
        engine._progress = lambda *a: None
        engine._cancelled = False
        engine._tscan = None
        engine._vulns = MagicMock()
        engine._vulns.match.return_value = []
        engine._vulns.match_cve_ms.return_value = []
        engine.registry = engine_registry_stub()

        result = engine.scan("https://example.com")
        names = {t.name for t in result.technologies}
        self.assertIn("WordPress", names)
        self.assertIn("Vue.js", names)
        self.assertIn("Caddy", names)
        self.assertEqual(result.security.grade, "F")

    def test_result_dict_shape(self):
        r = ScanResult("https://example.com", host="example.com")
        r.add_technology(Technology("X", ["misc"], 70))
        d = r.to_dict()
        for key in ("url", "host", "technologies", "vulnerabilities", "extras", "security"):
            self.assertIn(key, d)


def engine_registry_stub():
    """最小注册表桩：类别 + 精编指纹（不连库）"""
    reg = MagicMock()
    from scanner.fingerprints.builtin_fp import FINGERPRINTS
    reg.fingerprints = FINGERPRINTS
    reg.by_name = {f["name"]: f for f in FINGERPRINTS}
    reg.tscan = []
    reg.fingerdir = {}
    reg.category_name = lambda c: c
    reg.kb = MagicMock()
    return reg


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- A–D 补强
class TestBundleDetector(unittest.TestCase):
    def test_signature_hit_and_short_word_guard(self):
        from scanner.detectors.bundle_detector import BundleDetector

        class FakeFetcher:
            def fetch_bytes(self, url):
                return b"react-dom.production.min.js ... MonacoEnvironment:{get:..}"

        det = BundleDetector(FakeFetcher())
        ev = make_evidence(body='<script src="/_next/static/main.js"></script>')
        sig = extract_signals(ev)
        hits = {h[0] for h in det.detect(ev, sig)}
        self.assertIn("React", hits)
        self.assertIn("Monaco Editor", hits)

    def test_no_bundles_no_hits(self):
        from scanner.detectors.bundle_detector import BundleDetector

        class FakeFetcher:
            def fetch_bytes(self, url):
                raise AssertionError("无脚本时不应发请求")

        det = BundleDetector(FakeFetcher())
        ev = make_evidence(body="<p>plain</p>")
        self.assertEqual(det.detect(ev, extract_signals(ev)), [])


class TestRobots(unittest.TestCase):
    def test_crawler_respects_robots(self):
        import io
        import urllib.robotparser
        from scanner.crawler import SiteCrawler
        from scanner.target import ScanTarget

        rp = urllib.robotparser.RobotFileParser()
        rp.parse(["User-agent: *", "Disallow: /private"])

        class FakeFetcher:
            def fetch(self, url):
                self.fetched = url
                return make_evidence(body="<html></html>", title="t")

        target = ScanTarget("https://example.com", resolve=False)
        c = SiteCrawler(FakeFetcher(), target, robots=rp)
        first = make_evidence(body='<a href="/private/x">a</a><a href="/ok">b</a>')
        sig = extract_signals(first)
        pages = c.crawl(first, sig)
        fetched = [getattr(c._fetcher, "fetched", "")]
        self.assertTrue(all("/private" not in u for u in fetched))


if __name__ == "__main__":
    unittest.main()
