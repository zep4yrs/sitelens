"""5.0 执行日志（check_runs）→ L1 可靠负样本 → gate 翻转 的端到端纪律测试。"""

from __future__ import annotations

import unittest

import pandas as pd

from ml import dataset, labels, quality


def _mk_record(scan_uid: str, host: str, with_runs: bool,
               hit_checks: tuple[str, ...] = (), fail_checks: tuple[str, ...] = ()):
    """构造一条最小 ScanRecord：check_runs 可选，命中/失败集可控。"""
    check_runs = []
    if with_runs:
        for cid in ("chk-a", "chk-b", "chk-c"):
            st = "not_executed" if cid in fail_checks else "executed"
            check_runs.append({"check": cid, "status": st,
                               "hit": cid in hit_checks,
                               **({"reason": "request failed: timeout"}
                                  if st == "not_executed" else {})})
    return {
        "scan_uid": scan_uid, "origin": "history", "id": 1, "host": host,
        "url": f"http://{host}", "scanned_at": "2026-09-01 08:00:00",
        "tech_count": 0, "vuln_count": 0, "duration": 1.0,
        "options": {"checks": "all"},
        "result": {
            "status": 200, "security": {"grade": "C", "score": 50},
            "technologies": [], "vulnerabilities": [], "verified": [],
            "pages": [], "error": "",
            **({"check_runs": check_runs} if with_runs else {}),
        },
    }


class ExecutionsTest(unittest.TestCase):
    def test_check_runs_parsed_and_candidates_upgraded(self):
        recs = [_mk_record("history:1", "h.test", with_runs=True,
                           hit_checks=("chk-a",), fail_checks=("chk-c",))]
        catalog = {"checks": [
            {"id": "chk-a", "lv": 0, "severity": "high"},
            {"id": "chk-b", "lv": 0, "severity": "medium"},
            {"id": "chk-c", "lv": 0, "severity": "low"},
        ], "cms_checks": {}}
        tables, _ = dataset.build_from_records(recs, catalog)
        ex = tables["executions"]
        self.assertEqual(len(ex), 3)
        a = ex[ex["check_id"] == "chk-a"].iloc[0]
        self.assertEqual(a["execution_status"], "executed")
        self.assertTrue(bool(a["hit"]))
        c = ex[ex["check_id"] == "chk-c"].iloc[0]
        self.assertEqual(c["execution_status"], "not_executed")
        self.assertFalse(bool(c["hit"]))
        cand = tables["candidates"].set_index("check_id")
        self.assertEqual(cand.loc["chk-a", "execution_status"], "executed")
        self.assertEqual(cand.loc["chk-c", "execution_status"], "not_executed")

    def test_l1_negatives_from_executions_only(self):
        recs = [_mk_record("history:1", "h.test", with_runs=True,
                           hit_checks=("chk-a",), fail_checks=("chk-c",))]
        catalog = {"checks": [
            {"id": "chk-a", "lv": 0, "severity": "high"},
            {"id": "chk-b", "lv": 0, "severity": "medium"},
            {"id": "chk-c", "lv": 0, "severity": "low"},
        ], "cms_checks": {}}
        tables, _ = dataset.build_from_records(recs, catalog)
        rows, pole = labels.build_l1(
            tables["verified"], tables["candidates"], tables["executions"])
        self.assertEqual(pole["negative_count"], 1)  # chk-b executed∧未命中
        neg = rows[rows["role"] == "negative"]
        self.assertEqual(neg["item_id"].tolist(), ["chk-b"])
        # chk-c 未执行：必须是 unknown，绝不进 negative
        c_row = rows[rows["item_id"] == "chk-c"].iloc[0]
        self.assertEqual(c_row["role"], "unknown")
        # 命中键不得同时是 negative
        self.assertNotIn(("history:1", "chk-a"),
                         set(zip(neg["scan_uid"], neg["item_id"])))

    def test_l1_without_executions_keeps_negative_zero(self):
        recs = [_mk_record("history:1", "h.test", with_runs=False)]
        catalog = {"checks": [{"id": "chk-a", "lv": 0, "severity": "high"}],
                   "cms_checks": {}}
        tables, _ = dataset.build_from_records(recs, catalog)
        rows, pole = labels.build_l1(tables["verified"], tables["candidates"])
        self.assertEqual(pole["negative_count"], 0)
        self.assertEqual(int((rows["role"] == "negative").sum()), 0)

    def test_gate_flips_allowed_with_negatives(self):
        recs = [_mk_record("history:1", "h.test", with_runs=True,
                           hit_checks=("chk-a",), fail_checks=("chk-c",))]
        catalog = {"checks": [
            {"id": "chk-a", "lv": 0, "severity": "high"},
            {"id": "chk-b", "lv": 0, "severity": "medium"},
            {"id": "chk-c", "lv": 0, "severity": "low"},
        ], "cms_checks": {}}
        tables, _ = dataset.build_from_records(recs, catalog)
        scans = tables["scans"]
        gate = quality.gate_report(scans, tables["intel"], tables["verified"],
                                   tables["candidates"], tables["executions"])
        self.assertEqual(gate["T1_train"]["verdict"], "ALLOWED")
        self.assertEqual(gate["T2_train_supervised"]["verdict"], "ALLOWED")
        self.assertEqual(gate["T1_train"]["negative"], 1)
        # 旧数据（无执行日志）保持 BLOCKED
        recs_old = [_mk_record("history:1", "h.test", with_runs=False)]
        tables_old, _ = dataset.build_from_records(recs_old, catalog)
        gate_old = quality.gate_report(scans, tables_old["intel"],
                                       tables_old["verified"],
                                       tables_old["candidates"],
                                       tables_old["executions"])
        self.assertEqual(gate_old["T1_train"]["verdict"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
