# -*- coding: utf-8 -*-
"""后期回归与可信度测试（Phase 2 验收 + 上轮交付逻辑锁定）。

四块单测覆盖上轮 deepseek-v4-flash 承接、但因推送受阻未落地的部分：
① 重定向逐跳校验   fetcher._get_follow（单跳内网/两跳链/公网跟随/6 跳上限）
② 命中二次确认     checks.run_checks / run_nuclei 的抖动丢弃与采信
③ 审计上传上限     /api/audit（Flask 端点级，DB 打桩离线跑）
④ 无资产包优雅降级 match_cve_ms 缺表/异常静默返回

顺带锁定同批修复的真实 bug：
- /api/audit zip 上传 500（namelist() 字符串访问 file_size → 已改 infolist()）
- /api/history?limit=-5 500（_safe_limit 未夹下界）
"""
import io
import os
import struct
import unittest
import zlib
from unittest import mock

from scanner import checks as checks_mod
from scanner.target import ScanTarget

# ---------------------------------------------------------------------------
# ① 重定向逐跳校验（fetcher._get_follow）
# ---------------------------------------------------------------------------
class _Resp:
    def __init__(self, status, headers=None, content=b"ok", url=""):
        self.status_code = status
        self.headers = headers or {}
        self.content = content
        self.url = url
        self.text = content.decode("utf8", "ignore")
        self.elapsed = type("_E", (), {"total_seconds": lambda s: 0.01})()


class _FakeSession:
    """按调用顺序回放 (status, Location|None)；记录每次请求 URL 与 allow_redirects"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.cookies = []

    def get(self, url, **kw):
        self.calls.append(url)
        status, loc = self.responses[min(len(self.calls), len(self.responses)) - 1]
        headers = {"Location": loc} if loc else {}
        return _Resp(status, headers, b"ok", url)


def _make_fetcher(responses):
    from scanner.fetcher import Fetcher
    f = Fetcher.__new__(Fetcher)                  # 跳过真实网络会话构造
    f._Fetcher__session = _FakeSession(responses)
    f._Fetcher__retries = 0
    f._Fetcher__timeout = 5
    f._Fetcher__limiter = type("_L", (), {"wait": lambda s: None})()
    return f


class TestRedirectHopValidation(unittest.TestCase):
    def test_single_hop_to_loopback_blocked(self):
        """单跳 302 → 127.0.0.1：抛 TargetError，且只发出初始请求不跟随"""
        from scanner.target import TargetError
        f = _make_fetcher([(302, "http://127.0.0.1/steal")])
        with self.assertRaises(TargetError):
            f._get_follow("https://pub.example/start")
        self.assertEqual(f._Fetcher__session.calls, ["https://pub.example/start"])

    def test_single_hop_cloud_metadata_blocked(self):
        """302 → 169.254.169.254（云元数据）同样被拦"""
        from scanner.target import TargetError
        f = _make_fetcher([(302, "http://169.254.169.254/latest/meta-data/")])
        with self.assertRaises(TargetError):
            f._get_follow("https://pub.example/start")
        self.assertEqual(len(f._Fetcher__session.calls), 1)

    def test_public_then_internal_chain_blocked(self):
        """先公网后内网的两跳链：第二跳被拦，未向内网发请求"""
        from scanner.target import TargetError
        f = _make_fetcher([(302, "http://93.184.216.34/mid"),
                           (302, "http://10.0.0.8/steal")])
        with self.assertRaises(TargetError):
            f._get_follow("https://pub.example/start")
        calls = f._Fetcher__session.calls
        self.assertEqual(len(calls), 2)           # 第二跳被校验拦截，未发请求
        self.assertNotIn("http://10.0.0.8/steal", calls)

    def test_public_redirect_followed(self):
        """公网跳转正常跟随并返回最终页"""
        f = _make_fetcher([(302, "http://93.184.216.34/next"), (200, None)])
        resp = f._get_follow("https://pub.example/start")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(f._Fetcher__session.calls), 2)

    def test_max_six_hops_no_seventh_request(self):
        """超过 6 跳停止跟随：返回最后一个 3xx，不向第 7 目标发请求"""
        hops = [(302, "http://93.184.216.34/%d" % i) for i in range(8)]
        f = _make_fetcher(hops)
        resp = f._get_follow("https://pub.example/start")
        self.assertEqual(resp.status_code, 302)   # 停在 6 跳上限
        self.assertEqual(len(f._Fetcher__session.calls), 6)

    def test_post_form_3xx_validated(self):
        """post_form 的 POST 不跟随；3xx 跳转前做逐跳校验再转 GET"""
        from scanner.fetcher import Fetcher
        from scanner.target import TargetError

        class _PSession(_FakeSession):
            def post(self, url, data=None, **kw):
                self.calls.append(("POST", url))
                return _Resp(302, {"Location": "http://127.0.0.1/steal"})

        f = Fetcher.__new__(Fetcher)
        f._Fetcher__session = _PSession([(302, "http://127.0.0.1/steal")])
        f._Fetcher__retries = 0
        f._Fetcher__timeout = 5
        f._Fetcher__limiter = type("_L", (), {"wait": lambda s: None})()
        with self.assertRaises(TargetError):
            f.post_form("https://pub.example/login", {"u": "a"})
        self.assertEqual(f._Fetcher__session.calls, [("POST", "https://pub.example/login")])

    def test_fetch_bytes_3xx_not_followed_to_internal(self):
        """fetch_bytes 同样经 _get_follow：302 到内网不产生请求"""
        from scanner.target import TargetError
        f = _make_fetcher([(302, "http://127.0.0.1/x")])
        with self.assertRaises(TargetError):
            f.fetch_bytes("https://pub.example/favicon.ico")
        self.assertEqual(len(f._Fetcher__session.calls), 1)


# ---------------------------------------------------------------------------
# ② 命中二次确认（check 引擎 / Nuclei 运行器）
# ---------------------------------------------------------------------------
class _SeqFetcher:
    """可编程序列：前 n 次命中、之后抖动未命中，或两次都命中"""

    def __init__(self, seq=None):
        self.seq = seq or {}       # url -> [ (status, body), ... ] 每次 get 消费一个
        self.calls = []
        self.base = {"status": 404, "size": 5, "body": "no", "headers": {}}

    def get_small(self, url, headers=None):
        self.calls.append(url)
        if "__sl_none__" in url:
            return self.base
        bucket = self.seq.get(url, [(self.base["status"], self.base["body"])])
        status, body = bucket[min(len(self.calls) - self.calls[::-1].index(url) - 1
                                  if False else 0, len(bucket) - 1)]
        return {"url": url, "status": status, "size": len(body), "body": body,
                "headers": {}, "title": ""}


class _FlakyFetcher:
    """计数型抖动源：第 1 次命中、第 2 次（重放）未命中 → 应判误报丢弃"""

    def __init__(self, hit_body, miss_body):
        self.n = 0
        self.hit_body = hit_body
        self.miss_body = miss_body
        self.base = {"status": 404, "size": 5, "body": "no", "headers": {}}

    def get_small(self, url, headers=None):
        self.n += 1
        if "__sl_none__" in url:
            return self.base
        body = self.hit_body if self.n == 1 else self.miss_body
        return {"url": url, "status": 200, "size": len(body), "body": body,
                "headers": {}, "title": ""}


class TestDoubleConfirmation(unittest.TestCase):
    def test_check_flaky_hit_dropped(self):
        """check 首次命中、重放未命中 → 抖动误报丢弃"""
        t = ScanTarget("https://example.com", resolve=False)
        f = _FlakyFetcher("ref: refs/heads/main", "not a git head now")
        hits = checks_mod.run_checks(f, t, level="all")
        self.assertEqual([h for h in hits if h["check"] == "git-leak"], [])

    def test_check_stable_hit_confirmed(self):
        """check 两次命中 → 采信且 evidence 标注二次确认"""

        class _Stable:
            def __init__(self):
                self.n = 0
                self.base = {"status": 404, "size": 5, "body": "no", "headers": {}}

            def get_small(self, url, headers=None):
                self.n += 1
                if "__sl_none__" in url:
                    return self.base
                if url.endswith("/.git/HEAD"):
                    body = "ref: refs/heads/main"
                    return {"url": url, "status": 200, "size": len(body),
                            "body": body, "headers": {}, "title": ""}
                return self.base

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(_Stable(), t, level="all")
        git = [h for h in hits if h["check"] == "git-leak"]
        self.assertEqual(len(git), 1)
        self.assertIn("二次确认", git[0]["evidence"])

    def test_check_replay_error_single_sample(self):
        """重放异常 → 保留单次采样，evidence 标注单次采样"""

        class _FirstHitThenError:
            def __init__(self):
                self.n = 0
                self.base = {"status": 404, "size": 5, "body": "no", "headers": {}}

            def get_small(self, url, headers=None):
                if "__sl_none__" in url:
                    return self.base
                if url.endswith("/.git/HEAD"):
                    self.n += 1
                    if self.n == 1:
                        body = "ref: refs/heads/main"
                        return {"url": url, "status": 200, "size": len(body),
                                "body": body, "headers": {}, "title": ""}
                    raise RuntimeError("replay network error")
                return self.base

        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_checks(_FirstHitThenError(), t, level="all")
        git = [h for h in hits if h["check"] == "git-leak"]
        self.assertEqual(len(git), 1)
        self.assertIn("单次采样", git[0]["evidence"])

    def test_nuclei_flaky_dropped(self):
        """nuclei 首次命中、重放未命中 → 丢弃"""
        rows = [{"id": "n-flaky", "name": "Flaky", "sev": "high", "path": "/a.txt",
                 "groups": [{"s": [200], "wany": ["secret"]}]}]
        f = _FlakyFetcher("secret data", "nothing")
        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_nuclei(f, t, rows)
        self.assertEqual(hits, [])

    def test_nuclei_stable_confirmed(self):
        """nuclei 两次命中 → 采信二次确认"""

        class _Stable2:
            def __init__(self):
                self.n = 0
                self.base = {"status": 404, "size": 5, "body": "no", "headers": {}}

            def get_small(self, url, headers=None):
                self.n += 1
                if "__sl_none__" in url:
                    return self.base
                body = "secret marker"
                return {"url": url, "status": 200, "size": len(body),
                        "body": body, "headers": {}, "title": ""}

        rows = [{"id": "n-stable", "name": "Stable", "sev": "high", "path": "/s.txt",
                 "groups": [{"s": [200], "wany": ["secret"]}]}]
        t = ScanTarget("https://example.com", resolve=False)
        hits = checks_mod.run_nuclei(_Stable2(), t, rows)
        self.assertEqual(len(hits), 1)
        self.assertIn("二次确认", hits[0]["evidence"])


# ---------------------------------------------------------------------------
# ③ 审计上传上限 /api/audit（Flask 端点级，DB 打桩离线）
# ---------------------------------------------------------------------------
def _fake_zip(entries):
    """构造 zip 字节流；entries: [(name, data, declared_size)]。

    declared_size 可大于实际 data 长度（模拟压缩炸弹：文件头声明超大体积）。
    """
    local_parts, central_parts = [], []
    offset = 0
    for fname, data, usize in entries:
        fname_b = fname.encode("utf8")
        crc = zlib.crc32(data) & 0xffffffff
        header = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0, 0x21,
                             crc, len(data), usize, len(fname_b), 0)
        local_parts.append(header + fname_b + data)
        cdr = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 0x0314, 20, 0, 0,
                          0, 0x21, crc, len(data), usize, len(fname_b), 0, 0, 0,
                          0, 0, offset)
        central_parts.append(cdr + fname_b)
        offset += len(header) + len(fname_b) + len(data)
    cd = b"".join(central_parts)
    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(entries),
                       len(entries), len(cd), offset, 0)
    return b"".join(local_parts) + cd + eocd


class _FakeAuditDB:
    def __init__(self, conf=None):
        pass


class _FakeAuditKB:
    def __init__(self, db):
        self.db = db
        self.categories = {"web-server": {"name": "Web 服务器", "icon": "", "ord": 0}}
        self.fingerprints = []
        self.by_name = {}
        self.tscan = []
        self.fingerdir = {}
        self.vuln_all = []
        self.vuln_index = {}

    def load(self):
        pass

    def category_name(self, c):
        return c

    def search_vulns(self, q, limit=40):
        return []


class _FakeAuditRegistry:
    def __init__(self, kb=None):
        kb = kb or _FakeAuditKB(None)
        self.kb = kb
        self.categories = kb.categories
        self.fingerprints = kb.fingerprints
        self.by_name = kb.by_name
        self.tscan = kb.tscan
        self.fingerdir = kb.fingerdir

    def category_name(self, c):
        return c

    def search_vulns(self, q, limit=40):
        return []


class TestAuditUploadLimits(unittest.TestCase):
    """/api/audit 上限防护（zip 炸弹 / 路径穿越 / 空文件），DB 全打桩离线跑"""

    @classmethod
    def setUpClass(cls):
        os.environ["SLENS_AUTO_UPDATE"] = "0"
        import scanner.db as _sdb
        import scanner.registry as _sreg
        cls._orig = (_sdb.Database, _sdb.KnowledgeBase, _sreg.Registry)
        _sdb.Database = _FakeAuditDB
        _sdb.KnowledgeBase = _FakeAuditKB
        _sreg.Registry = _FakeAuditRegistry
        import app as _app_mod
        _sdb.Database, _sdb.KnowledgeBase, _sreg.Registry = cls._orig
        cls.app_mod = _app_mod          # 保留模块引用，patch 模块级 _store
        cls.app = _app_mod.app
        cls.client = _app_mod.app.test_client()

    def _upload(self, filename, data):
        return self.client.post(
            "/api/audit", data={"files": (io.BytesIO(data), filename)},
            content_type="multipart/form-data")

    def test_plain_source_file_audited(self):
        """普通单文件源码审计返回发现（非 zip 直传走不到 zip 分支）"""
        resp = self._upload("sample.py", b'password = "hunter2-secret"\n')
        self.assertEqual(resp.status_code, 200)
        j = resp.get_json()
        self.assertGreater(j["files"], 0)
        self.assertGreater(j["by_severity"]["high"], 0)

    def test_normal_zip_audited(self):
        """普通 zip 审计返回发现"""
        buf = io.BytesIO()
        import zipfile as _zf
        with _zf.ZipFile(buf, "w") as z:
            z.writestr("app.py", 'import os\nos.system("ls")\n')
        resp = self._upload("src.zip", buf.getvalue())
        self.assertEqual(resp.status_code, 200)
        j = resp.get_json()
        self.assertGreater(j["files"], 0)

    def test_zip_bomb_declared_size_rejected(self):
        """zip 内单个成员声明 530MB（实际 ~0.5KB）→ 解压前按 file_size 拦截"""
        bomb = _fake_zip([("big.sql", b"x", 530 * 1024 * 1024)])
        resp = self._upload("bomb.zip", bomb)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("512MB", resp.get_json()["error"])

    def test_zip_path_traversal_rejected(self):
        """zip 内 ../ 穿越条目 → 400 路径非法"""
        evil = _fake_zip([("../evil.txt", b"x", 5)])
        resp = self._upload("evil.zip", evil)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("路径非法", resp.get_json()["error"])

    def test_no_files_400(self):
        resp = self.client.post("/api/audit", data={},
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_audit_temp_cleaned(self):
        """审计后临时目录清理干净（不残留 sitelens_audit_*）"""
        import tempfile
        buf = io.BytesIO()
        import zipfile as _zf
        with _zf.ZipFile(buf, "w") as z:
            z.writestr("a.py", "x=1\n")
        resp = self._upload("clean.zip", buf.getvalue())
        self.assertEqual(resp.status_code, 200)
        leftovers = [p for p in os.listdir(tempfile.gettempdir())
                     if p.startswith("sitelens_audit_")]
        self.assertEqual(leftovers, [])

    def test_history_negative_limit_no_500(self):
        """_safe_limit 负 limit 不再 500：limit=-5 夹回 1（回归锁住）"""
        from unittest.mock import patch
        with patch.object(self.__class__.app_mod, "_store") as store:
            store.list_scans.return_value = []
            with self.__class__.app.test_request_context(
                    "/api/history?limit=-5"):
                resp = self.__class__.app.view_functions["api_history"]()
            self.assertEqual(resp.status_code, 200)
            store.list_scans.assert_called_once_with(limit=1, tech=None)

    def test_history_zero_limit_clamped(self):
        """limit=0 夹回 1，不返回空列表也不 500"""
        from unittest.mock import patch
        with patch.object(self.__class__.app_mod, "_store") as store:
            store.list_scans.return_value = []
            with self.__class__.app.test_request_context(
                    "/api/history?limit=0"):
                resp = self.__class__.app.view_functions["api_history"]()
            self.assertEqual(resp.status_code, 200)
            store.list_scans.assert_called_once_with(limit=1, tech=None)

    def test_history_huge_limit_capped(self):
        """limit 超上限夹到 cap=200"""
        from unittest.mock import patch
        with patch.object(self.__class__.app_mod, "_store") as store:
            store.list_scans.return_value = []
            with self.__class__.app.test_request_context(
                    "/api/history?limit=99999"):
                resp = self.__class__.app.view_functions["api_history"]()
            self.assertEqual(resp.status_code, 200)
            store.list_scans.assert_called_once_with(limit=200, tech=None)


# ---------------------------------------------------------------------------
# ④ 无资产包优雅降级（match_cve_ms）
# ---------------------------------------------------------------------------
class _NullCursor:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _RaisingTx:
    def __init__(self, error):
        self.error = error

    def __enter__(self):
        raise self.error

    def __exit__(self, *a):
        return False


class _Tech:
    def __init__(self, name):
        self.name = name


class TestGracefulDegrade(unittest.TestCase):
    def test_match_cve_ms_no_table_returns_empty(self):
        """cve_ms 表不存在（无资产包部署）→ 静默返回空，不阻塞扫描"""
        from scanner.vuln import VulnMatcher
        kb = mock.Mock()
        kb.db.transaction.side_effect = Exception("relation cve_ms does not exist")
        m = VulnMatcher(kb)              # __init__ 里 kev 查询也应被兜住
        out = m.match_cve_ms([_Tech("Microsoft IIS")])
        self.assertEqual(out, [])

    def test_match_cve_ms_tech_alias_hit(self):
        """别名匹配命中 cve_ms：IIS → Internet Information Services"""
        from scanner.vuln import VulnMatcher
        rows = [{"cve": "CVE-2024-123", "component": "Internet Information Services",
                 "title": "IIS vuln", "severity": "HIGH", "impact": "RCE"}]

        class _RowsTx:
            def __init__(self, cur):
                self._cur = cur

            def __enter__(self):
                return self._cur

            def __exit__(self, *a):
                return False

        cur = mock.Mock()
        cur.fetchall.return_value = rows
        kb = mock.Mock()
        # VulnMatcher.__init__ kev: 空
        def side(dict_rows=False):
            return _RowsTx(cur)
        kb.db.transaction.side_effect = side
        m = VulnMatcher(kb)
        out = m.match_cve_ms([_Tech("Microsoft IIS")])
        self.assertTrue(out)
        self.assertEqual(out[0]["cve"], "CVE-2024-123")
        self.assertEqual(out[0]["severity_zh"], "高危")

    def test_match_cve_ms_abnormal_error_returns_collected(self):
        """中途异常（连接闪断）→ 返回已收集部分，不抛 500"""
        from scanner.vuln import VulnMatcher
        kb = mock.Mock()
        # kev 查询成功返回空
        cur = mock.Mock()
        cur.fetchall.return_value = []
        kb.db.transaction.side_effect = [type("_Tx", (), {
            "__enter__": lambda s: cur, "__exit__": lambda *a: False})(),
            Exception("connection reset")]
        m = VulnMatcher(kb)
        out = m.match_cve_ms([_Tech("nginx")])
        self.assertEqual(out, [])         # 不抛异常



if __name__ == "__main__":
    unittest.main()
