"""P3/P4/P5 测试：as-of 时间截断、注入回归、host 隔离、标签三分纪律。"""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from ml import features, labels, leakage, splits


def _mk_scans(n=6, host="h.test", start="2026-09-01 08:00:00", step_h=24):
    rows = []
    for i in range(n):
        rows.append({
            "scan_uid": f"history:{100+i}", "origin": "history", "scan_id": 100+i,
            "host": host if i < n - 1 else "other.test",
            "url": f"http://{host if i < n-1 else 'other.test'}",
            "ip": "1.2.3.4", "era": "go",
            "scanned_at": (pd.Timestamp(start) + pd.Timedelta(hours=step_h*i)
                           ).strftime("%Y-%m-%d %H:%M:%S"),
            "scanned_at_dt": pd.Timestamp(start) + pd.Timedelta(hours=step_h*i),
            "tech_count": 2, "page_count": 1, "security_score": 40.0 + i,
            "options_checks": "all",
        })
    return pd.DataFrame(rows)


def _mk_events(scans, kind="verified"):
    rows = []
    for i, r in scans.iterrows():
        rows.append({"scan_uid": r["scan_uid"], "host": r["host"],
                     "scanned_at_dt": r["scanned_at_dt"], "src": "check",
                     "check": f"chk{i%2}", "execution_status": "executed"})
    return pd.DataFrame(rows)


class AsOfTest(unittest.TestCase):
    def test_priors_strictly_before(self):
        scans = _mk_scans(5, host="h.test")  # 末行是 other.test（首扫）
        empty = scans.iloc[0:0]
        out = features.add_scan_priors(scans, empty, empty)
        # 同 host 逐日扫描：第 i 条先验 = i（严格早于自身的记录数）；
        # 末行 other.test 首扫 = 0
        self.assertEqual(out["prior_scan_count"].tolist(), [0, 1, 2, 3, 0])
        self.assertEqual(int(out["prior_scan_count"].iloc[0]), 0)

    def test_injection_future_events_no_change(self):
        scans = _mk_scans(5, host="h.test")
        verified = _mk_events(scans)
        intel = verified.assign(cve="CVE-1", kev=False, n_templates=0)
        base = features.add_scan_priors(scans, verified, intel)
        future = pd.Timestamp(scans["scanned_at_dt"].max()) + pd.Timedelta(hours=1)
        fv = pd.concat([verified, pd.DataFrame([{
            "scan_uid": "X", "host": "h.test", "scanned_at_dt": future,
            "src": "check", "check": "zz", "execution_status": "executed"}])],
            ignore_index=True)
        after = features.add_scan_priors(scans, fv, intel)
        for col in ("prior_scan_count", "prior_verified_count", "prior_intel_count"):
            self.assertTrue((base[col] == after[col]).all(), col)
        # 最后一条扫描的 verified 先验不因"未来"注入而变化（未来事件晚于它）
        self.assertEqual(int(base["prior_verified_count"].iloc[-1]),
                         int(after["prior_verified_count"].iloc[-1]))

    def test_leakage_injection_assertion(self):
        scans = _mk_scans(5)
        verified = _mk_events(scans)
        intel = verified.assign(cve="CVE-1")
        prior_cols = ["prior_scan_count", "prior_verified_count", "prior_intel_count"]
        rep = leakage.assert_asof_injection(scans, verified, intel, [], prior_cols)
        self.assertTrue(rep["passed"])

    def test_prior_upper_bound(self):
        scans = _mk_scans(5)
        empty = scans.iloc[0:0]
        out = features.add_scan_priors(scans, empty, empty)
        leakage.assert_prior_upper_bound(out)  # 不抛即通过

    def test_host_disjoint_assert(self):
        splits.assert_host_disjoint(["a", "b"], ["c", "d"])  # 通过
        with self.assertRaises(AssertionError):
            splits.assert_host_disjoint(["a", "b"], ["b", "c"])

    def test_split_equivalence(self):
        scans = _mk_scans(4)  # 同一 host 同一 url
        rep = splits.split_equivalence_report(scans)
        self.assertFalse(rep["independent_target_groups"])
        self.assertIn("host split", rep["conclusion"])


class LabelDisciplineTest(unittest.TestCase):
    def test_l1_unknown_not_negative(self):
        cand = pd.DataFrame([
            {"scan_uid": "history:100", "host": "h", "scanned_at_dt": pd.Timestamp("2026-09-01"),
             "check_id": "phpinfo", "execution_status": "unknown",
             "execution_basis": "x"},
            {"scan_uid": "history:100", "host": "h", "scanned_at_dt": pd.Timestamp("2026-09-01"),
             "check_id": "env-leak", "execution_status": "unknown",
             "execution_basis": "x"},
        ])
        ver = pd.DataFrame([{
            "scan_uid": "history:100", "host": "h",
            "scanned_at_dt": pd.Timestamp("2026-09-01"), "row_idx": 0,
            "src": "check", "check": "phpinfo", "impact": None,
            "execution_status": "executed", "execution_basis": "hit",
        }])
        rows, pole = labels.build_l1(ver, cand)
        self.assertEqual(pole["negative_count"], 0)
        self.assertEqual(pole["counts"]["positive"], 1)
        self.assertEqual(pole["counts"]["unknown"], 1)
        self.assertFalse((rows["role"] == "negative").any())
        # unknown 行的 execution_status 保持 unknown
        self.assertTrue((rows[rows["role"] == "unknown"]["execution_status"]
                         == "unknown").all())

    def test_l3_sanity(self):
        intel = pd.DataFrame([
            {"verdict": "confirmed"}, {"verdict": "possible"},
            {"verdict": None}, {"verdict": "excluded"},
        ])
        df, pole = labels.build_l3(intel)
        self.assertEqual(len(df), 2)
        self.assertEqual(df["label"].sum(), 1)
        self.assertEqual(pole["counts"]["excluded_missing_verdict"], 2)

    def test_l5_disabled_when_zero(self):
        ver = pd.DataFrame([{"impact": None}])
        self.assertEqual(labels.build_l5(ver)["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
