"""离线预测（Phase 12）：对导出的 ScanRecord JSON 打 sanity 分数并解释。

只消费已有结果文件，零网络请求、不接生产扫描。输出统一契约：
score（必给）/ probability（校准不可靠 → null）/ confidence（第一阶段 null）/
top_features / prediction_reason。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from . import dataset, explain, features


def _top_features(model, feat_cols: list[str], x_row: np.ndarray,
                  k: int = 5) -> list[dict]:
    """线性模型取 |coef × standardized value|；树模型取 importance×value 近似。"""
    est = model
    xs = np.asarray(x_row, dtype=float).reshape(-1)
    if hasattr(model, "named_steps"):  # sklearn Pipeline
        if "standardscaler" in model.named_steps:
            xs = model.named_steps["standardscaler"].transform(x_row)[0]
        est = model[-1]
    if hasattr(est, "coef_"):
        coefs = np.ravel(est.coef_)
        pairs = [(n, float(c) * float(v)) for n, c, v in zip(feat_cols, coefs, xs)]
    elif hasattr(est, "feature_importances_"):
        pairs = [(n, float(i) * float(v)) for n, i, v in
                 zip(feat_cols, est.feature_importances_, xs)]
    else:
        pairs = [(n, 0.0) for n in feat_cols]
    pairs.sort(key=lambda x: abs(x[1]), reverse=True)
    return [{"feature": n, "contribution": round(v, 4)} for n, v in pairs[:k]]


def predict_scan(scan_json: Path, model_dir: Path, catalog: dict) -> dict:
    import joblib

    art = joblib.load(Path(model_dir) / "model.joblib")
    model, feat_cols = art["model"], art["feature_cols"]
    rec = json.loads(Path(scan_json).read_text(encoding="utf-8"))
    rec["origin"] = "predict"  # build_from_records 需要 origin/scan_uid 标识
    rec["scan_uid"] = f"predict:{rec.get('id')}"
    tables, _ = dataset.build_from_records([rec], catalog)
    scan_feat, _ = features.build_scan_features(
        tables["scans"], tables["techs"], tables["verified"], tables["intel"])
    # schema 对齐：训练期特征列是全量词汇表，单扫描重建时缺失列补 0
    x = (scan_feat.iloc[[0]].reindex(columns=feat_cols, fill_value=0)
         .astype(float).to_numpy())
    score = float(np.clip(model.predict(x)[0], 0.0, 100.0))
    tops = _top_features(model, feat_cols, x)
    return explain.prediction_entry("S2-score-sanity-offline", score, None, tops,
                                    calibrated=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="offline sanity prediction (Phase 12)")
    ap.add_argument("--scan-json", required=True, help="导出的 ScanRecord JSON")
    ap.add_argument("--model-dir", required=True, help="experiment 目录（含 model.joblib）")
    args = ap.parse_args()
    out = predict_scan(Path(args.scan_json), Path(args.model_dir),
                       dataset.load_catalog())
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
