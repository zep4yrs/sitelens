"""构建 Dataset（P2 入口）。

用法：
  python -m ml.build_dataset --data-root <主仓 data/> \
      --out-root <data/ml> --matrix-dir <tmp_matrix_out> [--version ds-5.0.0]
"""

from __future__ import annotations

import argparse
import json

from . import config, dataset


def main() -> int:
    ap = argparse.ArgumentParser(description="SiteLens 5.0 Dataset builder (P2)")
    ap.add_argument("--data-root", default=None)
    ap.add_argument("--out-root", default=None)
    ap.add_argument("--matrix-dir", default=None)
    ap.add_argument("--version", default="ds-5.0.0")
    args = ap.parse_args()

    paths = config.resolve_paths(args.data_root, args.out_root, args.matrix_dir)
    tables, stats, inputs = dataset.build_tables(paths)
    man_path = dataset.write_dataset(paths, tables, stats, inputs, version=args.version)

    print(json.dumps({
        "manifest": str(man_path),
        "counts": stats["counts"],
        "hosts": stats["hosts"],
        "era": stats["era"],
        "source": stats["source"]["per_source_raw"],
        "dedup_dropped": stats["source"]["dedup_dropped_n"],
        "candidate_exclusions": stats["candidate_exclusions"],
    }, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
