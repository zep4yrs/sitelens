"""P2 单元测试：合成 ScanRecord 夹具 → 建表/去重/规范化/候选集语义。"""

from __future__ import annotations

import unittest

from ml.dataset import (
    EXCL_LEVEL_NONE, EXCL_LEVEL_UNKNOWN, EXCL_UNREACHABLE,
    build_from_records, load_catalog,
)


def _rec(origin, sid, host, *, checks="all", techs=None, intel=None,
         verified=None, error="", scanned_at="2026-09-10 10:00:00",
         duration=1.5, url=None, score=50):
    r = {
        "ip": "127.0.0.1", "status": 200 if not error else 0,
        "security": {"score": score, "grade": "C", "items": []},
        "technologies": techs or [], "vulnerabilities": intel or [],
        "verified": verified or [], "pages": [], "extras": {},
        "response_time_ms": 12, "error": error,
    }
    return {
        "id": sid, "url": url or f"http://{host}", "host": host,
        "title": "t", "status": 200, "security_grade": "C",
        "security_score": score, "tech_count": len(techs or []),
        "vuln_count": len(intel or []), "duration": duration,
        "scanned_at": scanned_at, "options": {"checks": checks, "netsec": False,
                                              "dast": False, "deep": True,
                                              "passive": True},
        "result": r, "origin": origin, "scan_uid": f"{origin}:{sid}",
    }


class BuildFromRecordsTest(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.wordpress = {"name": "WordPress", "categories": ["cms"],
                          "confidence": 100, "version": "6.0",
                          "website": "", "evidence": ["header: x=wp"]}
        self.records = [
            # go 时代：all 档 + WordPress（触发 CMS 联动）+ check 命中 + 情报行
            _rec("history", 100, "a.test", techs=[self.wordpress],
                 intel=[{"tech": "WordPress", "cve": "cve-2020-1", "severity": "high",
                         "verdict": "possible", "src": "afrog", "cvss_score": 7.5}],
                 verified=[{"src": "check", "check": "phpinfo", "severity": "high",
                            "url": "http://a.test/phpinfo.php",
                            "request": "GET ", "response": {"status": 200, "size": 9},
                            "replay": "curl", "signals": ["词命中"], "confirmed": True}]),
            # 同一扫描再被 matrix 记录（同内容 → 跨来源去重应丢弃其一）
            _rec("matrix", 114, "a.test", techs=[self.wordpress],
                 intel=[{"tech": "WordPress", "cve": "CVE-2020-1", "severity": "high",
                         "verdict": "possible", "src": "afrog", "cvss_score": 7.5}],
                 verified=[{"src": "check", "check": "phpinfo", "severity": "high",
                            "url": "http://a.test/phpinfo.php",
                            "request": "GET ", "response": {"status": 200, "size": 9},
                            "replay": "curl", "signals": ["词命中"], "confirmed": True}],
                 scanned_at="2026-09-10 10:00:00"),
            # premigrate 旧 schema：Important 大小写 + 空 verdict
            _rec("premigrate", 5, "b.test", checks="core",
                 intel=[{"tech": "IIS", "cve": "CVE-2021-2", "severity": "Important",
                         "verdict": "", "src": "cve_ms"}]),
            # checks=none → 候选排除
            _rec("history", 101, "c.test", checks="none"),
            # 扫描失败 → 候选排除
            _rec("history", 102, "d.test", error="连接失败"),
            # options 缺 checks → 候选排除（batch 扫描只落 {"batch":true}）
            {**_rec("history", 103, "e.test"), "options": {"batch": True}},
        ]

    def test_counts_within_builder(self):
        """build_from_records 不做来源去重（那是 readers 层职责），全量建表。"""
        tables, stats = build_from_records(self.records, self.catalog)
        self.assertEqual(len(tables["scans"]), 6)
        self.assertEqual(stats["counts"]["verified"], 2)  # history:100 + matrix:114
        self.assertEqual(stats["counts"]["intel"], 3)

    def test_cross_source_dedup_at_readers(self):
        """跨来源内容去重在 readers.load_all_scans：matrix 重复 history → 丢弃。"""
        import json as _json
        import tempfile
        from pathlib import Path
        from ml import config as cfg, readers

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "state").mkdir()
            (td / "matrix").mkdir()
            hist = {"next_id": 101, "scans": [_rec("history", 100, "a.test",
                                                   techs=[self.wordpress])]}
            (td / "state" / "history.json").write_text(
                _json.dumps(hist), encoding="utf-8")
            dup = _rec("matrix", 114, "a.test", techs=[self.wordpress])
            dup.pop("scan_uid"); dup.pop("origin")
            (td / "matrix" / "v_dvwa.json").write_text(
                _json.dumps(dup), encoding="utf-8")
            paths = cfg.resolve_paths(data_root=td, out_root=td / "out",
                                      matrix_dir=td / "matrix")
            recs, stats = readers.load_all_scans(paths)
            self.assertEqual(len(recs), 1)
            self.assertEqual(stats["dedup_dropped_n"], 1)
            self.assertEqual(stats["dedup_dropped"][0]["kept"], "history:100")

    def test_event_dedup_premigrate(self):
        """premigrate 与 history 同 id = 同一扫描事件（迁移保留 id），
        即使内容因迁移规范化有差异也必须去重（重复样本纪律）。"""
        import json as _json
        import tempfile
        from pathlib import Path
        from ml import config as cfg, readers

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "state").mkdir()
            h = _rec("history", 7, "b.test", duration=2.0)
            h.pop("scan_uid"); h.pop("origin")
            (td / "state" / "history.json").write_text(
                _json.dumps({"next_id": 8, "scans": [h]}), encoding="utf-8")
            p = _rec("premigrate", 7, "b.test", duration=2.04)  # 内容略异（迁移规范化）
            p.pop("scan_uid"); p.pop("origin")
            (td / "state" / "history.json.premigrate").write_text(
                _json.dumps({"next_id": 8, "scans": [p]}), encoding="utf-8")
            paths = cfg.resolve_paths(data_root=td, out_root=td / "out")
            recs, stats = readers.load_all_scans(paths)
            self.assertEqual(len(recs), 1)
            self.assertEqual(stats["dedup_dropped"][0]["rule"], "event")
            self.assertEqual(stats["event_dedup"]["premigrate"], 1)

    def test_scan_uid_and_era(self):
        tables, _ = build_from_records(self.records, self.catalog)
        scans = tables["scans"].set_index("scan_uid")
        self.assertIn("history:100", scans.index)
        self.assertIn("premigrate:5", scans.index)
        self.assertEqual(scans.loc["premigrate:5", "era"], "py")
        self.assertEqual(scans.loc["history:100", "era"], "go")

    def test_severity_and_verdict_normalization(self):
        import pandas as pd
        tables, _ = build_from_records(self.records, self.catalog)
        intel = tables["intel"]
        row = intel[(intel["cve"] == "CVE-2020-1") &
                    (intel["scan_uid"] == "history:100")].iloc[0]
        self.assertEqual(row["severity_norm"], "high")
        row2 = intel[intel["cve"] == "CVE-2021-2"].iloc[0]
        self.assertEqual(row2["severity_norm"], "medium")   # Important → medium
        self.assertTrue(pd.isna(row2["verdict"]))            # 空串 → 显式 missing

    def test_verified_executed_semantics(self):
        tables, _ = build_from_records(self.records, self.catalog)
        v = tables["verified"].iloc[0]
        self.assertEqual(v["execution_status"], "executed")
        self.assertTrue(v["confirmed"])
        self.assertTrue(v["has_evidence_chain"])

    def test_candidate_applicability(self):
        tables, stats = build_from_records(self.records, self.catalog)
        cand = tables["candidates"]
        # history:100（all 档 + WordPress）：全部 42 条 + CMS 联动 4 条已在 42 内
        n_a = (cand["scan_uid"] == "history:100").sum()
        self.assertEqual(n_a, len(self.catalog["checks"]))
        self.assertTrue(((cand["scan_uid"] == "history:100") &
                         (cand["cms_linked"])).sum() >= 4)
        # premigrate:5（core 档，无 WordPress）：仅 Lv0
        n_b = (cand["scan_uid"] == "premigrate:5").sum()
        lv0 = sum(1 for c in self.catalog["checks"] if c["lv"] == 0)
        self.assertEqual(n_b, lv0)
        # 排除计数：none 1 / 失败 1 / 缺档位 1
        self.assertEqual(stats["candidate_exclusions"][EXCL_LEVEL_NONE], 1)
        self.assertEqual(stats["candidate_exclusions"][EXCL_UNREACHABLE], 1)
        self.assertEqual(stats["candidate_exclusions"][EXCL_LEVEL_UNKNOWN], 1)
        # 候选全部 unknown（不得标 not_executed，更不得标 negative）
        self.assertTrue((cand["execution_status"] == "unknown").all())

    def test_candidate_positive_join_key(self):
        """命中行必须能 join 到候选集（同 scan_uid + check_id），否则标签无处安放。"""
        tables, _ = build_from_records(self.records, self.catalog)
        v = tables["verified"].iloc[0]
        cand = tables["candidates"]
        hit = cand[(cand["scan_uid"] == v["scan_uid"]) &
                   (cand["check_id"] == v["check"])]
        self.assertEqual(len(hit), 1)


if __name__ == "__main__":
    unittest.main()
