"""P6-P10 补充单测：排序指标、校准判定规则、实验注册表追溯。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ml import explain, metrics, registry
from ml.features import check_blacklist


class MetricsTest(unittest.TestCase):
    def test_precision_recall_ndcg(self):
        ranked = ["a", "b", "c", "d", "e"]
        rel = {"a", "c"}
        self.assertEqual(metrics.precision_at_k(ranked, rel, 5), 0.4)
        self.assertEqual(metrics.precision_at_k(ranked, rel, 1), 1.0)
        self.assertEqual(metrics.recall_at_k(ranked, rel, 2), 0.5)
        # nDCG@2：命中在第 1 位 → DCG=1，IDCG=1+1/log2(3)
        expected = 1.0 / (1.0 + 1.0 / np.log2(3))
        self.assertAlmostEqual(metrics.ndcg_at_k(ranked, rel, 2), expected, places=6)

    def test_insufficient_candidates_excluded(self):
        # 候选数 < K 的查询返回 None（不凑分母）
        self.assertIsNone(metrics.precision_at_k(["a"], {"a"}, 5))
        out = metrics.eval_ranking({"q1": ["a"]}, {"q1": {"a"}}, ks=(5,))
        self.assertIsNone(out["P@5"])
        self.assertEqual(out["queries_counted_P@5"], 0)

    def test_eval_ranking_mean(self):
        ranked = {"q1": ["a", "b", "c", "d", "e"], "q2": ["x", "y", "z", "w", "v"]}
        rel = {"q1": {"a"}, "q2": {"v"}}
        out = metrics.eval_ranking(ranked, rel, ks=(5,))
        self.assertAlmostEqual(out["P@5"], (0.2 + 0.2) / 2)


class CalibrationRuleTest(unittest.TestCase):
    def test_small_sample_unreliable(self):
        y = np.array([0, 1])
        p = np.array([0.1, 0.9])
        res = explain.calibrate_verdict(y, p)
        self.assertEqual(res["verdict"], "unreliable")
        self.assertIsNone(res["probability_output"])

    def test_no_discrimination_unreliable(self):
        # 200 条全 0 样本、概率全 0.01：brier 极小但无判别力 → unreliable
        y = np.zeros(200, dtype=int)
        p = np.full(200, 0.01)
        res = explain.calibrate_verdict(y, p, auc=None)
        self.assertEqual(res["verdict"], "unreliable")
        self.assertIn("判别力", res["reason"])

    def test_prediction_entry_contract(self):
        entry = explain.prediction_entry("T", 0.7, None,
                                         [{"feature": "f", "contribution": 0.1}],
                                         calibrated=False)
        self.assertIsNone(entry["probability"])
        self.assertIsNone(entry["confidence"])  # 第一阶段恒 null
        self.assertEqual(entry["score"], 0.7)

    def test_blacklist(self):
        with self.assertRaises(AssertionError):
            check_blacklist(["ok", "impact"])


class RegistryTest(unittest.TestCase):
    def test_create_and_verify_chain(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            ds = out / "dataset" / "DATASET_MANIFEST.json"
            ds.parent.mkdir(parents=True)
            ds.write_text("{}", encoding="utf-8")
            dummy = _DummyModel()
            d = registry.create_experiment(
                out, "EXP-9001", "S2-score-sanity", "ridge",
                params={"alpha": 1.0}, metrics_report={"mae": 1.0},
                model_obj=dummy, feature_cols=["a", "b"],
                upstream_manifests=[ds], repo_dir=None)
            res = registry.verify_experiment(d)
            self.assertTrue(res["ok"], res["problems"])
            self.assertEqual(res["kind"], "model")
            # 篡改模型文件 → 校验必须失败
            (d / "model.joblib").write_bytes(b"tampered")
            res2 = registry.verify_experiment(d)
            self.assertFalse(res2["ok"])


class _DummyModel:
    def predict(self, X):
        import numpy as np
        return np.zeros(len(X))


if __name__ == "__main__":
    unittest.main()
