"""P9 Explainability / Calibration。

输出契约（开发文档 Phase 9，score/probability/confidence 严格分离）：
  score               模型原始打分（必给）
  probability         仅当校准检验可靠才给数值，否则 null
  confidence          第一阶段一律 null
  top_features        ≤5 个 (feature, contribution)
  prediction_reason   引用触发特征值的中文短句（无 emoji）

未经 calibration 的模型输出不得称为"置信度"。
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss


def top_features_linear(model, feature_cols: list[str], row: pd.Series,
                        k: int = 5) -> list[dict]:
    """线性模型逐样本贡献 = standardized_value × coef。"""
    names = feature_cols
    coefs = model.coef_
    contrib = [(n, float(c) * float(row.get(n, 0.0) or 0.0))
               for n, c in zip(names, coefs)]
    contrib.sort(key=lambda x: abs(x[1]), reverse=True)
    return [{"feature": n, "contribution": round(v, 4)} for n, v in contrib[:k]]


def top_features_tree(model, feature_cols: list[str], row: pd.Series,
                      k: int = 5) -> list[dict]:
    """树模型逐样本贡献用 importance × standardized_value 近似（诚实标注）。"""
    imp = np.asarray(model.feature_importances_)
    vals = np.array([float(row.get(n, 0.0) or 0.0) for n in feature_cols])
    std = vals.std() or 1.0
    contrib = [(n, float(i) * float((v - vals.mean()) / std))
               for n, i, v in zip(feature_cols, imp, vals)]
    contrib.sort(key=lambda x: abs(x[1]), reverse=True)
    return [{"feature": n, "contribution": round(v, 4)} for n, v in contrib[:k]]


def prediction_reason(task: str, tops: list[dict], score: float) -> str:
    parts = "、".join(f"{t['feature']}({t['contribution']:+.2f})" for t in tops[:3])
    return f"{task}：score={score:.3f}；主要依据 {parts}"


def prediction_entry(task: str, score: float, probability: float | None,
                     tops: list[dict], calibrated: bool) -> dict:
    """统一预测契约。probability 只有在 calibrated=True 时才给数值。"""
    return {
        "task": task,
        "score": round(float(score), 6),
        "probability": round(float(probability), 6) if (calibrated and probability is not None) else None,
        "confidence": None,  # 第一阶段恒 null（开发文档 Phase 9）
        "top_features": tops,
        "prediction_reason": prediction_reason(task, tops, score),
    }


def calibrate_verdict(y_true: np.ndarray, prob: np.ndarray,
                      auc: float | None = None,
                      n_bins: int = 5, mae_threshold: float = 0.15) -> dict:
    """可靠性检验（判定规则先于计算声明）：

    reliable ⇔ n≥50 且 判别力成立（AUC≥0.55，AUC 不可计算即不成立）
               且 分箱最大偏差 ≤ mae_threshold。
    校准以判别力为前提：模型若无判别力（全部预测≈0 的退化情形），
    Brier 再小也不得输出 probability。
    """
    y = np.asarray(y_true).astype(int)
    p = np.asarray(prob).astype(float)
    res: dict = {
        "n": int(len(y)),
        "brier": round(float(brier_score_loss(y, p)), 4) if len(y) else None,
        "auc": auc,
        "rule": "n>=50 且 AUC>=0.55 且 分箱最大偏差<=0.15 判 reliable；"
                "校准以判别力为前提",
    }
    reasons = []
    if len(y) < 50:
        reasons.append(f"OOF 样本 {len(y)} < 50，小样本校准曲线不可信")
    if auc is None or auc < 0.55:
        reasons.append(f"判别力不成立（AUC={auc}），退化校准无意义")
    if len(y) < 50 or auc is None or auc < 0.55:
        res.update({"verdict": "unreliable", "reason": "；".join(reasons),
                    "probability_output": None})
        return res
    bins = np.quantile(p, np.linspace(0, 1, n_bins + 1))
    bins[0], bins[-1] = 0.0, 1.0
    max_dev = 0.0
    detail = []
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        m = (p >= lo) & (p <= hi if i == n_bins - 1 else p < hi)
        if m.sum() == 0:
            continue
        obs = float(y[m].mean())
        exp = float(p[m].mean())
        max_dev = max(max_dev, abs(obs - exp))
        detail.append({"bin": [round(lo, 3), round(hi, 3)], "n": int(m.sum()),
                       "mean_pred": round(exp, 3), "pos_rate": round(obs, 3)})
    res["bins"] = detail
    res["max_bin_deviation"] = round(max_dev, 4)
    res["verdict"] = "reliable" if max_dev <= mae_threshold else "unreliable"
    res["probability_output"] = round(float(p.mean()), 6) if res["verdict"] == "reliable" else None
    return res
