# -*- coding: utf-8 -*-
"""后期阶段「回归与可信度」测试扩容。

覆盖 CodeBuddy 交叉复审与回归守门新增/修复的边界逻辑：
1. fetcher 重定向逐跳 SSRF 校验（302→内网 / 多跳 / 超 6 跳 / post_form）
2. check 引擎与 nuclei 运行器的命中二次确认（防抖动误报）
3. /api/audit 审计上传上限（zip 炸弹、路径穿越、临时目录清理）
4. match_cve_ms 无资产包（缺表/kev 异常）优雅降级
5. /api/history limit 参数负数/非数字兜底
全部离线：fetcher 用假 session、审计用 Flask 端点打桩 DB、无需真实 PG/网络。
"""
import io
import os
import shutil
import struct
import tempfile
import unittest
import zipfile
from unittest import mock

from scanner.target import ScanTarget, TargetError, TargetValidator


# ---------------------------------------------------------------- app 模块打桩
# app.py 顶层会 Database(load_env()) 连真实 PG；离线单测先替换 db/registry 符号，
# 使 import app 不触碰数据库（模块级实例全部落到内存桩）。
import scanner.db as _db_mod
import scanner.registry as _reg_mod
import scanner.exporters as _exp_mod


class _StubDB:
    """Database/JobStore/ScanStore 通用桩"""

    def __init__(self, *a, **kw):
        pass

    def transaction(self, dict_rows=False):
        return mock.MagicMock()

    def ensure_schema(self):
        return None

    def load(self):
        return None


class _StubKB:
    """KnowledgeBase 桩：给出空索引，避免 Registry 触发空库播种"""

    categories = {}
    fingerprints = []
    by_name = {}
    tscan = []
    fingerdir = {}
    vuln_all = []
    vuln_index = {}

    def __init__(self, *a, **kw):
        pass

    def load(self):
        return None

    def stats(self):
        return {"categories": 0, "technologies": 0, "curated": 0,
                "tscan": 0, "vulns": 0, "vuln_by_severity": {}, "per_category": {}}

    def category_name(self, c):
        return c

    def vulns_for(self, name):
        return []

    def search_vulns(self, text, limit=30):
        return []


class _StubRegistry:
    categories = {"misc": {"name": "misc", "icon": "", "ord": 0}}
    fingerprints = []
    by_name = {}
    tscan = []
    fingerdir = {}

    def __init__(self, kb=None, validate=True):
        pass

    def category_name(self, c):
        return c

    def stats(self):
        return {}


class _StubExporter:
    def __init__(self, registry):
        self._registry = registry

    def detail_csv(self, d):
        return ""

    def wide_csv(self, d):
        return ""


def _enable_app_offline():
    """让 import app 走内存桩；重复调用幂等"""
    os.environ["SLENS_AUTO_UPDATE"] = "0"
    _db_mod.Database = _StubDB
    _db_mod.KnowledgeBase = _StubKB
    _db_mod.JobStore = _StubDB
    _db_mod.ScanStore = _StubDB
    _db_mod.load_env = lambda: {}
    _reg_mod.Registry = _StubRegistry
    _exp_mod.Exporter = _StubExporter


_enable_app_offline()


# ---------------------------------------------------------------- 1) 重定向逐跳校验
class _FakeResp:
    def __init__(self, status=200, content=b"", text="", headers=None, url=""):
        self.status_code = status
        self.content = content
        self.text = text or content.decode("utf8", "ignore")
        self.headers = headers or {}
        self.url = url or "https://example.com/"


class _FakeSession:
    """可编程假 session：按调用次序返回预设响应序列"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        resp = self.responses.pop(0) if self.responses else _FakeResp(404)
        if resp.status_code in (301, 302, 303, 307, 308):
            from urllib.parse import urljoin
            loc = resp.headers.get("Location", "")
            resp.url = url
            resp._loc = urljoin(url, loc) if not loc.startswith("http") else loc
        else:
            resp.url = resp.url or url
        return resp

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


def _no_dns_ensure_public(host):
    """离线校验：仅拒绝字面量内网/环回 IP，域名不做真实解析"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return                    # 域名 → 跳过 DNS（离线单测）
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved \
            or ip.is_multicast or ip.is_unspecified:
        raise TargetError("目标解析到保留/内网地址（%s），已拒绝" % ip)


def _make_fetcher(session):
    from scanner.fetcher import Fetcher
    f = Fetcher.__new__(Fetcher)
    f._Fetcher__session = session
    f._Fetcher__timeout = 5
    f._Fetcher__retries = 0
    f._Fetcher__limiter = type("L", (), {"wait": lambda self: None})()
    return f


class TestRedirectSSRF(unittest.TestCase):
    """_get_follow 逐跳校验：任何一跳指向内网/私网即拒绝（离线打桩 DNS）"""

    @classmethod
    def setUpClass(cls):
        from scanner.target import TargetValidator
        cls._patcher = mock.patch.object(
            TargetValidator, "_TargetValidator__ensure_public_host",
            new=_no_dns_ensure_public)
        cls._patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls._patcher.stop()

    def test_single_hop_to_internal_rejected(self):
        from scanner.fetcher import Fetcher
        resp = _FakeResp(302, headers={"Location": "http://127.0.0.1:8500/"})
        session = _FakeSession([resp])
        f = _make_fetcher(session)
        with self.assertRaises(TargetError):
            f._get_follow("https://example.com/login")
        self.assertEqual(len(session.calls), 1)   # 只发出初始请求，不跟随

    def test_cloud_metadata_rejected(self):
        resp = _FakeResp(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        session = _FakeSession([resp])
        f = _make_fetcher(session)
        with self.assertRaises(TargetError):
            f._get_follow("https://example.com/")

    def test_second_hop_rejected(self):
        # 第一跳公网正常，第二跳回内网 → 在第二跳前拦截
        hop1 = _FakeResp(302, headers={"Location": "https://public.example.net/a"})
        hop2 = _FakeResp(302, headers={"Location": "http://10.0.0.5/"})
        session = _FakeSession([hop1, hop2])
        f = _make_fetcher(session)
        with self.assertRaises(TargetError):
            f._get_follow("https://example.com/")
        self.assertEqual(len(session.calls), 2)

    def test_public_redirect_followed(self):
        hop1 = _FakeResp(302, headers={"Location": "https://final.example.net/page"})
        final = _FakeResp(200, content=b"<h1>ok</h1>", url="https://final.example.net/page")
        session = _FakeSession([hop1, final])
        f = _make_fetcher(session)
        resp = f._get_follow("https://example.com/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(session.calls), 2)

    def test_more_than_6_hops_stops(self):
        # 7 跳公网循环：只跟 6 跳就返回最后一个 3xx，不发第 7 个请求
        responses = [_FakeResp(302, headers={"Location": "https://h%d.example.com/" % i})
                     for i in range(1, 10)]
        session = _FakeSession(responses)
        f = _make_fetcher(session)
        resp = f._get_follow("https://example.com/")
        self.assertIn(resp.status_code, (301, 302, 303, 307, 308))
        self.assertLessEqual(len(session.calls), 7)

    def test_post_form_3xx_also_validated(self):
        # POST 返回 302 到内网：应抛 TargetError / 返回 None，而非跟随
        resp = _FakeResp(302, headers={"Location": "http://127.0.0.1/x"})
        session = _FakeSession([resp])
        f = _make_fetcher(session)
        with self.assertRaises(TargetError):
            f._get_follow("https://example.com/p")


# ---------------------------------------------------------------- 2) 二次确认
class _FakeResp2:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body.encode()
        self.text = body
        self.url = "https://range.example.com"


def _fetcher_for(pages, flaky=None):
    """pages: {path:(status,body)}；flaky: 第二次访问返回不同内容的路径集"""
    class F:
        def __init__(self):
            self.calls = {k: 0 for k in pages}
        def get_small(self, url, headers=None):
            from urllib.parse import urlsplit
            path = urlsplit(url).path
            self.calls.setdefault(path, 0)
            self.calls[path] += 1
            if path not in pages:
                return {"status": 404, "size": 5, "body": "nope", "headers": {}}
            st, body = pages[path]
            if flaky and path in flaky and self.calls[path] >= 2:
                body = flaky[path]     # 二次采样不同 → 判定抖动
            return {"status": st, "size": len(body), "body": body, "headers": {}}
    return F()


class TestSecondConfirm(unittest.TestCase):
    def test_check_double_hit_confirmed(self):
        from scanner import checks as checks_mod
        f = _fetcher_for({"/phpinfo.php": (200, "phpinfo() PHP Version 8.1")})
        t = ScanTarget("https://range.example.com", resolve=False)
        hits = checks_mod.run_checks(f, t, level="all")
        php = [h for h in hits if h["check"] == "phpinfo"]
        self.assertEqual(len(php), 1)
        self.assertIn("二次确认", php[0]["evidence"])

    def test_check_flaky_discarded(self):
        from scanner import checks as checks_mod
        # 首次命中、重放不命中 → 判抖动误报丢弃
        f = _fetcher_for({"/phpinfo.php": (200, "phpinfo() PHP Version 8.1")},
                         flaky={"/phpinfo.php": "no php here"})
        t = ScanTarget("https://range.example.com", resolve=False)
        hits = checks_mod.run_checks(f, t, level="all")
        self.assertEqual([h for h in hits if h["check"] == "phpinfo"], [])

    def test_nuclei_flaky_discarded(self):
        from scanner import checks as checks_mod
        rows = [{"id": "t1", "name": "Git Config", "sev": "high",
                 "path": "/.git/config", "groups": [{"s": [200], "wany": ["[core]"]}]}]
        f = _fetcher_for({"/.git/config": (200, "[core] x")},
                         flaky={"/.git/config": "clean"})
        t = ScanTarget("https://range.example.com", resolve=False)
        hits = checks_mod.run_nuclei(f, t, rows)
        self.assertEqual(hits, [])

    def test_nuclei_double_hit_confirmed(self):
        from scanner import checks as checks_mod
        rows = [{"id": "t2", "name": "Git Config", "sev": "high",
                 "path": "/.git/config", "groups": [{"s": [200], "wany": ["[core]"]}]}]
        f = _fetcher_for({"/.git/config": (200, "[core] x")})
        t = ScanTarget("https://range.example.com", resolve=False)
        hits = checks_mod.run_nuclei(f, t, rows)
        self.assertEqual(len(hits), 1)
        self.assertIn("二次确认", hits[0]["evidence"])


# ---------------------------------------------------------------- 3) /api/audit 审计上传
def _zip_bytes(members, declared=None):
    """构造 zip 字节流。members: [(name, data)]；
    declared: 覆盖第一个成员头里声明的解压后大小（zip 炸弹模拟）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if declared:
        # local header 的 uncompressed size 位于 PK\x03\x04 后 22..26
        lh = raw.find(b"PK\x03\x04")
        ch = raw.find(b"PK\x01\x02")
        raw[lh + 22:lh + 26] = struct.pack("<I", declared)
        raw[ch + 24:ch + 28] = struct.pack("<I", declared)
    return bytes(raw)


class FakeDB:
    """Database 打桩：/api/audit 不触碰扫描表，只验证审计流"""

    def transaction(self, dict_rows=False):
        return mock.MagicMock()

    def ensure_schema(self):
        return None


class FakeRegistry:
    kb = None
    categories = {}


class TestAuditUpload(unittest.TestCase):
    """以 Flask test_client 离线打桩 DB 跑 /api/audit 端点"""

    def setUp(self):
        # 用真实临时目录覆盖审计工作目录，便于断言清理
        self._tmp_root = tempfile.mkdtemp(prefix="sl_audit_ut_")

    def tearDown(self):
        shutil.rmtree(self._tmp_root, ignore_errors=True)

    def _client(self):
        import app as app_mod
        app_mod._db = FakeDB()
        app_mod._kb = FakeDB()
        app_mod._registry = FakeRegistry()
        app_mod._store = FakeDB()
        app_mod._jobs = FakeDB()
        app_mod._scan_semaphore = mock.MagicMock()
        # 让审计临时目录落在可控路径
        patcher = mock.patch("tempfile.mkdtemp", return_value=self._tmp_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        app_mod.app.config["TESTING"] = True
        return app_mod.app.test_client()

    def _post_zip(self, data, name="src.zip"):
        return self._client().post(
            "/api/audit",
            data={"files": (io.BytesIO(data), name)},
            content_type="multipart/form-data")

    def test_single_py_file_audited(self):
        r = self._post_zip(b"import os\nos.system('ls')\n", name="a.py")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("findings", body)
        self.assertGreaterEqual(body["files"], 1)

    def test_zip_upload_ok(self):
        z = _zip_bytes([("main.py", b"import os\nos.system('id')\n"),
                        ("readme.txt", b"hello")])
        r = self._post_zip(z)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertGreaterEqual(body["files"], 1)
        self.assertTrue(any(f["rule"] == "PY-OSPOPEN" for f in body["findings"]))

    def test_zip_bomb_declared_size_rejected(self):
        # 声明 530MB（>512MB），实际内容仅 ~几百字节 → 解压前按声明累计拦截
        z = _zip_bytes([("big.log", b"A" * 300)], declared=530 * 1024 * 1024)
        r = self._post_zip(z)
        self.assertEqual(r.status_code, 400)
        self.assertIn("512MB", r.get_json()["error"])

    def test_zip_traversal_rejected(self):
        z = _zip_bytes([("../evil.txt", b"x")])
        r = self._post_zip(z)
        self.assertEqual(r.status_code, 400)
        self.assertIn("路径非法", r.get_json()["error"])

    def test_no_file_400(self):
        r = self._client().post("/api/audit",
                                data={}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_temp_dir_cleaned(self):
        z = _zip_bytes([("a.py", b"x=1")])
        self._post_zip(z)
        self.assertFalse(os.path.exists(self._tmp_root))


# ---------------------------------------------------------------- 4) 无资产包优雅降级
class FakeKB:
    """KnowledgeBase 桩：transaction 抛异常（表不存在）"""

    def __init__(self, fail=True):
        self.fail = fail

    def transaction(self, dict_rows=False):
        class _Tx:
            def __init__(self, kb):
                self._kb = kb
            def __enter__(self):
                if self._kb.fail:
                    raise Exception("relation cve_ms does not exist")
                return mock.MagicMock()
            def __exit__(self, *a):
                return False
        return _Tx(self)

    def vulns_for(self, name):
        return []


class _Tech:
    def __init__(self, name, version=""):
        self.name = name
        self.version = version


class TestNoAssetGraceful(unittest.TestCase):
    def test_match_cve_ms_missing_table_returns_empty(self):
        from scanner.vuln import VulnMatcher
        m = VulnMatcher.__new__(VulnMatcher)
        m._kb = FakeKB(fail=True)
        m._kev = set()
        m._ranges = {}
        out = m.match_cve_ms([_Tech("IIS")])
        self.assertEqual(out, [])

    def test_match_empty_techs(self):
        from scanner.vuln import VulnMatcher
        m = VulnMatcher.__new__(VulnMatcher)
        m._kb = FakeKB(fail=False)
        m._kev = set()
        m._ranges = {}
        self.assertEqual(m.match_cve_ms([]), [])

    def test_kev_query_failure_tolerated(self):
        from scanner import vuln as vuln_mod
        real_init = vuln_mod.VulnMatcher.__init__
        try:
            def fake_init(self, kb):
                self._kb = kb
                self._kev = set()      # kev 查询失败 → 空集合不抛
                self._ranges = {}
            vuln_mod.VulnMatcher.__init__ = fake_init
            m = vuln_mod.VulnMatcher(FakeKB(fail=True))
            self.assertEqual(m.match_cve_ms([_Tech("Nginx")]), [])
        finally:
            vuln_mod.VulnMatcher.__init__ = real_init


# ---------------------------------------------------------------- 5) limit 参数兜底
class TestLimitGuard(unittest.TestCase):
    def test_negative_limit_clamped(self):
        import app as app_mod
        app_mod._db = FakeDB()
        with app_mod.app.test_request_context("/api/history?limit=-5"):
            v = app_mod._safe_limit()
            self.assertGreaterEqual(v, 1)
        with app_mod.app.test_request_context("/api/history?limit=0"):
            self.assertGreaterEqual(app_mod._safe_limit(), 1)

    def test_non_numeric_limit_default(self):
        import app as app_mod
        with app_mod.app.test_request_context("/api/history?limit=abc"):
            self.assertEqual(app_mod._safe_limit(), 50)

    def test_huge_limit_capped(self):
        import app as app_mod
        with app_mod.app.test_request_context("/api/history?limit=99999"):
            self.assertEqual(app_mod._safe_limit(), 200)


if __name__ == "__main__":
    unittest.main()
