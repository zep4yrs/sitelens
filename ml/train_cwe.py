"""学习阶段追加实验（kb-5.0.1：v2 镜像 cwes 字段解锁 CVE↔CWE 关系学习）。

背景：4.x P5 已把 weaknesses 投影进 update-nvd v2 产出（2024-26 的 13 万条
CVE 自带 cwes），项 67 无需改动 update-nvd——本实验直接消费该字段。

EXP-1005  CVE 描述 → CWE 弱点类型分类（top-25 类，时间切分 train pub<2024 /
          test>=2024，与 EXP-1001/1002 同口径）；主弱点=每条 CVE 首个 cwe
          （NVD 宣告序）；多数类基线对照；模型持久化 + 全链 manifest。

KB 版本：kb-5.0.1 写独立子目录 dataset/kb-5.0.1/（kb-5.0.0 及其已验证实验链
原样保留，不受覆盖影响）。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import f1_score

from . import config, knowledge, manifest

DATA_VERSION = "kb-5.0.1"
TOP_N = 25
SEED = 20260914


def _year_split(df: pd.DataFrame, cut: str = "2024-01-01"):
    t = pd.to_datetime(df["pub"], errors="coerce")
    return df[t < cut], df[t >= cut]


def _save(paths: config.Paths, name: str, payload: dict,
          upstream: list[Path], params: dict) -> Path:
    out = paths.out_root / "metrics" / f"{name}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    man = manifest.make_manifest(
        kind="experiment", version=name,
        inputs=[manifest.file_input(p, role="upstream") for p in upstream]
               + [manifest.file_input(out, role="output")],
        params=params, producer="ml/train_cwe.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, paths.out_root / "metrics" / f"{name}_MANIFEST.json")
    return out


def _persist_model(paths: config.Paths, exp_name: str, art: dict,
                   upstream: list[Path], task: str, feature_note: str) -> Path:
    import joblib
    d = paths.out_root / "experiments" / exp_name
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(art, d / "model.joblib")
    man = manifest.make_manifest(
        kind="model", version=exp_name,
        inputs=[manifest.file_input(d / "model.joblib", role="output:model")]
               + [manifest.file_input(p, role=f"upstream:{p.name}") for p in upstream],
        params={"task": task, "feature_note": feature_note},
        producer="ml/train_cwe.py",
        scope={"data_version": DATA_VERSION},
    )
    manifest.write_manifest(man, d / "EXPERIMENT_MANIFEST.json")
    summary = paths.out_root / "metrics" / "summary.jsonl"
    summary.parent.mkdir(parents=True, exist_ok=True)
    with open(summary, "a", encoding="utf-8") as f:
        f.write(json.dumps({"exp_id": exp_name, "task": task,
                            "data_version": DATA_VERSION,
                            "git_rev": manifest.git_rev()}) + "\n")
    return d


def exp1005_cwe_relation(kb: dict[str, pd.DataFrame], kb_man: Path,
                         paths: config.Paths) -> dict:
    """K3：CVE 描述 → CWE 弱点类型（top-25 主弱点，时间切分）。"""
    edges = kb["kb_cve_cwe"].copy()
    # 主弱点 = 每 CVE 首个 cwe（NVD 宣告序，保留原始顺序去重）
    primary = edges.drop_duplicates("cve", keep="first")
    cve_descr = kb["kb_cve"].set_index("cve")[["descr", "pub"]]
    df = primary.merge(cve_descr, left_on="cve", right_index=True, how="inner")
    df = df.dropna(subset=["descr", "pub"])
    df["pub_dt"] = pd.to_datetime(df["pub"], errors="coerce")

    train_all, test_all = _year_split(df)
    # 类宇宙只看训练期（避免用测试期频率选类）
    classes = (train_all["cwe"].value_counts().head(TOP_N).index.tolist())
    class_set = set(classes)
    train = train_all[train_all["cwe"].isin(class_set)]
    test = test_all[test_all["cwe"].isin(class_set)]

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=120000,
                          sublinear_tf=True)
    Xtr = vec.fit_transform(train["descr"])
    Xte = vec.transform(test["descr"])
    ytr, yte = train["cwe"].to_numpy(), test["cwe"].to_numpy()

    clf = SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=30,
                        random_state=SEED)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)

    majority = train["cwe"].value_counts().index[0]
    rep = {
        "task": "K3 CVE→CWE weakness-type classification (top-25 primary)",
        "train_rows": int(len(train)), "test_rows": int(len(test)),
        "test_excluded_longtail": int(len(test_all) - len(test)),
        "coverage_note": (f"测试期主弱点 ∈ top-25 的占 "
                          f"{len(test)}/{len(test_all)}；长尾如实排除不硬凑"),
        "split": "train pub<2024-01-01 / test>=2024-01-01",
        "n_classes": len(classes),
        "classes": classes,
        "models": {
            "sgd_tfidf": {
                "accuracy": round(float((pred == yte).mean()), 4),
                "macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
            },
            "majority_baseline": {
                "accuracy": round(float((yte == majority).mean()), 4),
                "note": f"恒预测训练期多数类 {majority}",
            },
        },
        "label_provenance": {
            "source": "NVD weaknesses（4.x P5 v2 镜像自带，主弱点=宣告序首个）",
            "label_type": "supervised", "label_confidence": "medium",
            "note": "CWE 分配本身有噪声且多值；取主弱点作单标签是保守近似",
        },
    }
    art = {"vectorizer": vec, "model": clf, "classes": classes,
           "feature": "tfidf(descr) word 1-2gram"}
    return rep, art


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", default=r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data")
    ap.add_argument("--out-root", default=None)
    args = ap.parse_args()
    paths = config.resolve_paths(args.data_root, args.out_root)

    kb = knowledge.build_kb_tables(paths)
    st = knowledge.kb_stats(kb, paths)
    kb_man = knowledge.write_kb(paths, kb, st, version=DATA_VERSION,
                                subdir=DATA_VERSION)
    print(f"[kb] {DATA_VERSION}: cwe_edges={st['kb_cve_cwe']['edges']} "
          f"unique_cwe={st['kb_cve_cwe']['unique_cwe']} "
          f"cves_with_cwe={st['kb_cve_cwe']['cves_with_cwe']}")

    rep, art = exp1005_cwe_relation(kb, kb_man, paths)
    _save(paths, "EXP-1005-cwe-relation", rep, [kb_man], {"task": "K3"})
    _persist_model(paths, "EXP-1005-cwe-model", art, [kb_man], "K3",
                   art["feature"])
    print(json.dumps({k: v for k, v in rep.items()
                      if k in ("train_rows", "test_rows", "n_classes",
                               "models", "test_excluded_longtail")},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
