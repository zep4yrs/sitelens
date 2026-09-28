"""P1 单元测试：manifest 往返/篡改发现、路径解析。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ml import config, manifest


class ManifestTest(unittest.TestCase):
    def test_roundtrip_and_verify_ok(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "in.json"
            f.write_text('{"a": 1}', encoding="utf-8")
            m = manifest.make_manifest(
                kind="dataset", version="ds-0.0.1",
                inputs=[manifest.file_input(f, role="source")],
                params={"x": 1}, producer="unit-test", scope={"hosts": 1},
            )
            p = manifest.write_manifest(m, td / "DATASET_MANIFEST.json")
            loaded = manifest.load_manifest(p)
            self.assertEqual(loaded["kind"], "dataset")
            self.assertEqual(loaded["version"], "ds-0.0.1")
            self.assertEqual(manifest.verify_manifest(loaded), [])

    def test_verify_detects_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f = td / "in.json"
            f.write_text('{"a": 1}', encoding="utf-8")
            m = manifest.make_manifest(
                kind="label", version="lb-0.0.1",
                inputs=[manifest.file_input(f)],
                params={}, producer="unit-test",
            )
            f.write_text('{"a": 2}', encoding="utf-8")  # 篡改
            problems = manifest.verify_manifest(m)
            self.assertEqual(len(problems), 1)
            self.assertIn("哈希不一致", problems[0])

    def test_verify_detects_missing(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ghost.json"  # 不存在
            m = manifest.make_manifest(
                kind="feature", version="ft-0.0.1",
                inputs=[{"role": "input", "path": str(f), "sha256": "x" * 64, "bytes": 1}],
                params={}, producer="unit-test",
            )
            problems = manifest.verify_manifest(m)
            self.assertEqual(len(problems), 1)
            self.assertIn("缺失", problems[0])

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            manifest.make_manifest(kind="bad", version="v", inputs=[], params={}, producer="t")


class ConfigTest(unittest.TestCase):
    def test_resolve_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "state").mkdir()
            (td / "state" / "history.json").write_text("{}", encoding="utf-8")
            paths = config.resolve_paths(data_root=td, out_root=td / "ml")
            self.assertEqual(paths.history_json, td / "state" / "history.json")
            self.assertEqual(paths.out_root, (td / "ml").resolve())

    def test_resolve_missing_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                config.resolve_paths(data_root=td)

    def test_constants(self):
        # 纪律常量：unknown 不得作为 negative（执行原则 5）
        self.assertEqual(config.EXEC_UNKNOWN, "unknown")
        self.assertNotIn(config.EXEC_UNKNOWN, {"executed", "not_executed"})


if __name__ == "__main__":
    unittest.main()
