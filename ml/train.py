"""P7 训练 + P8 评估 + P9 解释/校准：gate 放行任务的真实训练。

任务（由 P5 gate 决定，开发文档 §6 Phase 7）：
  S1 = L3 confirmed-verdict sanity 分类（LR / RF / GBDT，LOHO host 交叉验证）
  S2 = T3 安全评分 sanity 回归（LR(Ridge) / GBDT，LOHO + time split）
训练一律只用 train fold；OOF 预测汇总后统一评估（P8）。
概率输出必须经 P9 校准检验后才允许进预测契约，否则 probability=null。
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, GradientBoostingRegressor, RandomForestClassifier
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import (
    average_precision_score, brier_score_loss, mean_absolute_error,
    roc_auc_score,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import splits


def _loho_folds(df: pd.DataFrame):
    return splits.leave_one_host_out(df)


def train_s1_l3_sanity(intel_feat: pd.DataFrame, feat_cols: list[str],
                       seed: int = 20260914) -> dict:
    """S1：二分类（label 来自 build_l3 的 sanity 标注），LOHO OOF。"""
    df = intel_feat.dropna(subset=["label"]).reset_index(drop=True)
    X = df[feat_cols].astype(float)
    y = df["label"].astype(int)
    models = {
        "logistic_regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced",
                                                 random_state=seed)),
        "random_forest": RandomForestClassifier(n_estimators=200, max_depth=4,
                                                random_state=seed, n_jobs=-1),
        "gradient_boosting": GradientBoostingClassifier(n_estimators=150, max_depth=2,
                                                        random_state=seed),
    }
    oof = pd.DataFrame({"host": df["host"].to_numpy(), "y": y.to_numpy()})
    fitted: dict = {}
    skipped_folds = []
    for name, mdl in models.items():
        oof[name] = np.nan
        for host, train_df, test_df in _loho_folds(df):
            tr_idx = df["host"] != host
            te_idx = ~tr_idx
            if tr_idx.sum() == 0 or te_idx.sum() == 0:
                continue
            if df.loc[tr_idx, "label"].nunique() < 2:
                skipped_folds.append(
                    {"fold_test_host": host, "model": name,
                     "reason": "训练折只有一类（正例集中），不硬造判别"})
                continue  # 训练折只有一类时跳过（如实记录，不硬造）
            mdl.fit(X[tr_idx], y[tr_idx])
            oof.loc[te_idx, name] = mdl.predict_proba(X[te_idx])[:, 1]
            fitted[name] = mdl  # 保留最后折模型（完整数据版在 registry 再拟合）
        # 全量重拟合（用于产物/解释；评估仍只用 OOF）
        mdl.fit(X, y)
        fitted[name] = mdl
    valid = oof.dropna(subset=[c for c in models.keys()])
    res: dict = {"rows": int(len(df)), "positives": int(y.sum()),
                 "folds": int(df["host"].nunique()),
                 "oof_rows": int(len(valid)),
                 "oof_positives": int(valid["y"].sum()) if len(valid) else 0,
                 "skipped_folds": skipped_folds,
                 "oof_note": "OOF 行数 < 总行数：正例集中导致部分训练折单一类，"
                             "该折如实跳过（不硬造判别）" if skipped_folds else ""}
    for name in models:
        col = oof[["y", name]].dropna()
        p = col[name].to_numpy()
        yy = col["y"].to_numpy()
        auc = None
        auc_note = ""
        if len(set(yy)) > 1:
            auc = round(float(roc_auc_score(yy, p)), 4)
        else:
            auc_note = ("OOF 汇总中正例为 0（正例全部落在被跳过/留出的折），"
                        "AUC/PR-AUC 不可计算——数据不支持该评估口径")
        entry = {
            "oof_rows": int(len(col)),
            "oof_positives": int(yy.sum()),
            "roc_auc": auc,
            "pr_auc": round(float(average_precision_score(yy, p)), 4)
            if yy.sum() > 0 else None,
            "pred_pos_at_050": int((p >= 0.5).sum()),
            "note": "OOF 汇总；class_weight/阈值未调优，数值仅用于管线验证",
        }
        if auc_note:
            entry["auc_note"] = auc_note
        if name == "logistic_regression":
            entry["brier"] = round(float(brier_score_loss(yy, p)), 4)
        res[name] = entry
    res["_oof"] = oof
    res["_models"] = fitted
    res["_feature_cols"] = feat_cols
    res["_X_columns"] = list(X.columns)
    return res


def train_s2_score_sanity(scan_feat: pd.DataFrame, feat_cols: list[str],
                          seed: int = 20260914) -> dict:
    """S2：安全评分回归（LOHO + time split 双口径）。特征不含响应头评分项。"""
    df = scan_feat.dropna(subset=["security_score"]).copy().reset_index(drop=True)
    X = df[feat_cols].astype(float)
    y = df["security_score"].astype(float)
    models = {
        "ridge": make_pipeline(StandardScaler(), Ridge(alpha=1.0)),
        "gradient_boosting": GradientBoostingRegressor(n_estimators=150, max_depth=2,
                                                       random_state=seed),
    }
    oof = pd.DataFrame({"host": df["host"].to_numpy(), "y": y.to_numpy(),
                        "scanned_at_dt": df["scanned_at_dt"].to_numpy()})
    fitted = {}
    for name, mdl in models.items():
        oof[name] = np.nan
        for host, train_df, test_df in _loho_folds(df):
            tr_idx = df["host"] != host
            te_idx = ~tr_idx
            mdl.fit(X[tr_idx], y[tr_idx])
            oof.loc[te_idx, name] = mdl.predict(X[te_idx])
            fitted[name] = mdl
        mdl.fit(X, y)
        fitted[name] = mdl
    # median 基线（每折用 train 的中位数）
    med = np.full(len(df), np.nan)
    for host, train_df, test_df in _loho_folds(df):
        tr_idx = df["host"] != host
        med[te_idx.to_numpy()] = float(np.median(y[tr_idx]))
    oof["median_baseline"] = med

    # time split 80/20（第二口径）
    tr_df, te_df = splits.time_split(df, train_frac=0.8)
    time_res = {}
    if len(tr_df) and len(te_df):
        tr_idx = df.index.isin(tr_df.index)
        for name, mdl in models.items():
            mdl.fit(X[tr_idx], y[tr_idx])
            pred = np.clip(mdl.predict(X[~tr_idx]), 0.0, 100.0)  # 分数域 [0,100]
            time_res[name] = round(float(mean_absolute_error(y[~tr_idx], pred)), 3)

    res: dict = {"rows": int(len(df)), "folds": int(df["host"].nunique())}
    for name in models:
        col = oof[["y", name, "median_baseline"]].dropna(subset=["y", name])
        pred = np.clip(col[name].to_numpy(), 0.0, 100.0)
        res[name] = {
            "oof_rows": int(len(col)),
            "mae_loho": round(float(mean_absolute_error(col["y"], pred)), 3),
            "rmse_loho": round(float(np.sqrt(((col["y"] - pred) ** 2).mean())), 3),
            "mae_time_split": time_res.get(name),
        }
    colm = oof.dropna(subset=["median_baseline"])
    res["median_baseline"] = {
        "mae_loho": round(float(mean_absolute_error(colm["y"], colm["median_baseline"])), 3),
        "note": "每折 train 中位数；模型必须与之对照",
    }
    res["_oof"] = oof
    res["_models"] = fitted
    res["_feature_cols"] = feat_cols
    return res
