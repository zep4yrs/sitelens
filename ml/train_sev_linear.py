"""train_sev_linear.py —— CVE 描述 → CVSS 0-10 线性回归（TF-IDF + Adagrad SGD），训练 + 导出 + 自检一体。

用途
    为引擎阶段 1（下线 ONNX、改用线性 severity）训练并导出 Go 引擎可直接加载的
    线性回归资产，同时产出 Go 回归测试夹具。纯 numpy 实现（Python 3.13 仅 numpy，
    不依赖 sklearn/scipy），单次全流程实测约 18 秒、峰值内存约 0.83 GB。

真值来源（唯一）
    <repo>/data/nvd_cves.json.gz（gzip JSON：{count, cves:[{cve,pub,mod,score,vec,descr,prods}]}）。
    其中的 descr 已是生产路径口径——internal/intel/nvd_sync.go 的 truncateRunes(v, 280)
    截断（≤280 字符 + '…'），训练/导出/夹具一律直接用它，禁止再截断或改写。
    score 为 NVD CVSS baseScore（0-10），是回归目标。

特征与推理口径（必须与 Go 侧 internal/ml/ml.go 逐位一致）
    lowercase（Python str.lower()）
    → re.findall(r"\\b\\w\\w+\\b", text) 一元词（sklearn token_pattern 的等价实现）
    → 词频 count
    → tf_val = (1 + ln(count)) * idf[t]
    → 整行 L2 归一
    → score = x·w + b（本脚本导出 w = coef.f32、b = meta.intercept，预测后 clip 到 [0,10]）
    词表只含一元词（无 bigram）：Go 侧 Vectorize 会额外生成 bigram 特征，但 bigram
    串含空格、不可能命中一元词表，因此 Go 侧行为等价于本模型（bigram 恒被丢弃）。
    idf 用 smooth idf：idf[t] = ln((1+N)/(1+df[t])) + 1，N = 训练文档数。

切分（时间切分，固定种子，可复现）
    训练集 = pub < 2024 且 score > 0 且 descr 非空（全量，不抽样）
    holdout = pub >= 2024 且 score > 0 且 descr 非空，seed 20261030 抽 20,000 条
    夹具    = 同池剔除 holdout 后，seed 20261031 抽 120 条（与 holdout 不相交）
    词表    = 训练集 df >= 3，按总词频降序取 top 60,000（同频按词字典序，确定性）

产物（UTF-8；float32 一律小端 Little-Endian；文本 LF 换行，跨平台逐字节一致）
    sev-linear.vocab.txt      每行一个一元词，行号 = 特征 id
    sev-linear.idf.f32        n_features 个 float32 LE
    sev-linear.coef.f32       1×n_features float32 LE（行主序，行=类）
    sev-linear.meta.json      字段与 cve-tech/cwe-type 同构（ml.LoadModel 校验）
    sev-linear-fixtures.json  {"n":120,"items":[{"cve","text","score"}]}，text=截断 descr

路径（环境变量优先，默认仓库相对，不写死开发机绝对路径）
    SITLENS_NVD_DUMP       默认 <repo>/data/nvd_cves.json.gz
    SITLENS_ML_GO_ASSETS   默认 <repo>/models/go/ml_assets
    注意：ml/config.py 的 go_assets_dir() 默认是 <repo>/data/go/ml_assets（旧导出位置）；
    本脚本默认改为 <repo>/models/go/ml_assets，因为「模型进仓库本体」后运行时
    （internal/ml/locate.go、internal/engine/ml.go）实际加载的是 models/go/ml_assets
    （cve-tech / cwe-type 就在那里），导出物必须落在运行时真正读的目录。

可复现命令（仓库根目录，任意 cwd 均可，路径按 __file__ 解析）
    python ml/train_sev_linear.py
    # 换数据/换导出目录：
    SITLENS_NVD_DUMP=/data/nvd_cves.json.gz SITLENS_ML_GO_ASSETS=/tmp/ml_assets python ml/train_sev_linear.py
    # Windows PowerShell：
    $env:SITLENS_NVD_DUMP="D:\\data\\nvd_cves.json.gz"; python ml/train_sev_linear.py

自检
    导出后重新读回 float32 资产（vocab/idf/coef/meta），按 Go 口径（float32 权重升格
    float64、逐 id 累加、clip 到 [0,10]）在 20k holdout 上重算 MAE/RMSE/p95/≤±1，
    并算 120 条夹具的 MAE；MAE > 1.25 或出现 NaN/Inf 时以非零码退出（不自欺通过）。
    实测（参考机 CPU）：holdout MAE 1.177 / RMSE 1.486 / p95 2.953 / ≤±1 50.9%，
    夹具（120 条）MAE 1.135；耗时 ~18 s，峰值内存 ~0.83 GB。
"""

from __future__ import annotations

import gc
import gzip
import json
import math
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

# ---- 资产契约（与 Go 侧对齐的常量，勿随意改）----
NAME = "sev-linear"
CLASSES = ["cvss-score"]
TOKEN_PATTERN = r"(?u)\b\w\w+\b"  # 必须逐字节等于 ml.go 的 expectedTokenPattern
FORMAT = ("vocab.txt line=id; idf.f32; coef.f32 rows=classes；"
          "regression: score=x·w+intercept")
TOKEN_RE = re.compile(r"\b\w\w+\b")  # = token_pattern 的 Python 等价（str.lower 后切词）

# ---- 训练超参（A/B 已定，勿重选）----
MAX_FEATURES = 60_000
MIN_DF = 3
EPOCHS = 3
LR = 0.15
ALPHA = 1e-6          # L2（ridge）强度，作用于 w 与 b
ADAGRAD_EPS = 1e-8
TRAIN_SEED = 20261030

# ---- 切分 / 夹具 ----
HOLDOUT_N = 20_000
HOLDOUT_SEED = 20261030
FIXTURE_N = 120
FIXTURE_SEED = 20261031
MAE_GATE = 1.25

TRAIN_YEAR_MAX = "2024"  # pub[:4] < 2024 → 训练


def repo_root() -> Path:
    """仓库根目录（本文件在 <repo>/ml/ 下），与 cwd 无关。"""
    return Path(__file__).resolve().parents[1]


def nvd_dump_path() -> Path:
    raw = os.environ.get("SITLENS_NVD_DUMP")
    return Path(raw).expanduser().resolve() if raw else (repo_root() / "data" / "nvd_cves.json.gz")


def out_dir() -> Path:
    """导出目录：SITLENS_ML_GO_ASSETS > <repo>/models/go/ml_assets（见文件头说明）。"""
    raw = os.environ.get("SITLENS_ML_GO_ASSETS")
    return Path(raw).expanduser().resolve() if raw else (repo_root() / "models" / "go" / "ml_assets")


def peak_rss_mb() -> float | None:
    """峰值物理内存（仅诊断用；psutil 缺失时返回 None，不阻断训练）。

    Windows 取 peak_wset（真实峰值），其他平台退化为当前 RSS。
    """
    try:
        import psutil
    except ImportError:
        return None
    info = psutil.Process().memory_info()
    peak = getattr(info, "peak_wset", None) or info.rss
    return peak / (1024 * 1024)


def _iter_cves(path: Path):
    """流式逐条解析 dump 的 cves 数组。

    直接 json.load 整个 dump（37.2 万条、解压后 ~290MB）会把解析树留在内存里，
    峰值实测 ~2.5GB；这里按 4MiB 分块喂给 JSONDecoder.raw_decode，只保留当前条目，
    峰值降到 ~0.6GB（契约要求内存 ≲2GB）。
    """
    dec = json.JSONDecoder()
    chunk = 1 << 22  # 4 MiB
    with gzip.open(path, "rt", encoding="utf-8") as f:
        buf = f.read(chunk)
        eof = not buf
        while True:  # 定位 "cves" 后的 '['
            key = buf.find('"cves"')
            if key >= 0:
                start = buf.find("[", key)
                if start >= 0:
                    pos = start + 1
                    break
            if eof:
                raise ValueError(f"{path}: 找不到 cves 数组")
            more = f.read(chunk)
            eof = not more
            buf += more
        while True:
            n = len(buf)
            while pos < n and buf[pos] in " \t\r\n,":
                pos += 1
            if pos >= n or buf[pos] == "]":
                if eof:
                    return
                buf, pos = buf[pos:], 0  # 丢弃已消费前缀，续读
                more = f.read(chunk)
                eof = not more
                buf += more
                continue
            try:
                obj, end = dec.raw_decode(buf, pos)
            except json.JSONDecodeError:
                if eof:
                    raise
                buf, pos = buf[pos:], 0
                more = f.read(chunk)
                eof = not more
                buf += more
                continue
            pos = end
            yield obj


def load_dump(path: Path):
    """读 NVD 镜像 → (训练 texts, 训练 scores, 测试池 [(cve, text, score)])。

    过滤口径：score > 0（有 CVSS 真值）且 descr 非空（否则无特征可算）。
    descr 直接用 dump 里已截断的版本（生产口径），不再二次截断。
    """
    if not path.is_file():
        raise FileNotFoundError(f"未找到 NVD 镜像：{path}（可用 SITLENS_NVD_DUMP 指定）")
    train_texts: list[str] = []
    train_scores: list[float] = []
    pool: list[tuple[str, str, float]] = []
    for e in _iter_cves(path):
        descr = e.get("descr") or ""
        score = e.get("score")
        if not descr or score is None or not score > 0:
            continue
        year = (e.get("pub") or "")[:4]
        if year and year < TRAIN_YEAR_MAX:
            train_texts.append(descr)
            train_scores.append(float(score))
        elif year >= TRAIN_YEAR_MAX:
            pool.append((e.get("cve", ""), descr, float(score)))
    gc.collect()
    return train_texts, train_scores, pool


def tokenize(text: str) -> Counter:
    """Go 口径切词：lowercase 后取 \\w\\w+ 连续 run 的一元词，返回词频。"""
    return Counter(TOKEN_RE.findall(text.lower()))


def build_vocab(token_counts: list[Counter]) -> tuple[list[str], np.ndarray]:
    """df>=3 且按总词频取 top 60k；idf 用 smooth idf（N=训练文档数）。"""
    df: Counter = Counter()
    tf: Counter = Counter()
    for counts in token_counts:
        for tok, n in counts.items():
            df[tok] += 1
            tf[tok] += n
    cands = [(tok, d) for tok, d in df.items() if d >= MIN_DF]
    cands.sort(key=lambda kv: (-tf[kv[0]], kv[0]))  # 同频按字典序 → 确定性
    cands = cands[:MAX_FEATURES]
    vocab = [tok for tok, _ in cands]
    n_docs = len(token_counts)
    idf = np.array([math.log((1.0 + n_docs) / (1.0 + d)) + 1.0 for _, d in cands],
                   dtype=np.float64)
    return vocab, idf


def pack_rows(token_counts: list[Counter], vocab_map: dict[str, int],
              idf: np.ndarray) -> list[tuple[np.ndarray, np.ndarray]]:
    """把词频转成 L2 归一的行向量（ids 升序，与 Go 侧累加顺序一致）。"""
    rows: list[tuple[np.ndarray, np.ndarray]] = []
    empty = (np.empty(0, np.int32), np.empty(0, np.float64))
    for counts in token_counts:
        hits = [(vocab_map[tok], n) for tok, n in counts.items() if tok in vocab_map]
        if not hits:
            rows.append(empty)
            continue
        hits.sort()  # id 升序
        ids = np.fromiter((i for i, _ in hits), dtype=np.int32, count=len(hits))
        vals = np.array([(1.0 + math.log(n)) * idf[i] for i, n in hits], dtype=np.float64)
        norm = math.sqrt(float(vals @ vals))
        rows.append((ids, vals / norm) if norm > 0.0 else empty)
    return rows


def train(rows, y: np.ndarray, n_features: int) -> tuple[np.ndarray, float]:
    """Adagrad SGD（逐样本，平方损失 + L2），bias 与 w 同步更新。"""
    rng = np.random.default_rng(TRAIN_SEED)
    w = np.zeros(n_features, dtype=np.float64)
    grad_sq = np.zeros_like(w)
    b = 0.0
    b_grad_sq = 0.0
    for _ in range(EPOCHS):
        for k in rng.permutation(len(rows)):
            ids, vals = rows[k]
            if ids.size == 0:
                continue
            w_hit = w[ids]
            err = 2.0 * (b + float(w_hit @ vals) - y[k])  # d(loss)/d(pred)，loss=(pred-y)^2
            grad = err * vals + ALPHA * w_hit
            grad_sq[ids] += grad * grad
            w[ids] -= LR * grad / np.sqrt(grad_sq[ids] + ADAGRAD_EPS)
            b_grad = err + ALPHA * b
            b_grad_sq += b_grad * b_grad
            b -= LR * b_grad / math.sqrt(b_grad_sq + ADAGRAD_EPS)
    return w, b


def export(out: Path, vocab: list[str], idf: np.ndarray, w: np.ndarray, b: float) -> dict:
    """写 4 个资产文件（UTF-8；float32 小端；文本一律 LF，保证跨平台逐字节可复现）。"""
    out.mkdir(parents=True, exist_ok=True)
    n = len(vocab)
    (out / f"{NAME}.vocab.txt").write_text("\n".join(vocab) + "\n", encoding="utf-8",
                                           newline="\n")
    np.asarray(idf, dtype="<f4").tofile(out / f"{NAME}.idf.f32")
    np.asarray(w, dtype="<f4").reshape(1, n).tofile(out / f"{NAME}.coef.f32")
    meta = {
        "name": NAME,
        "classes": CLASSES,
        "n_features": int(n),
        "n_classes": len(CLASSES),
        "intercept": [float(b)],
        "sublinear_tf": True,
        "lowercase": True,
        "token_pattern": TOKEN_PATTERN,
        "l2_norm": True,
        "format": FORMAT,
    }
    (out / f"{NAME}.meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
    return meta


def write_fixtures(out: Path, items: list[tuple[str, str, float]]) -> Path:
    payload = {"n": len(items),
               "items": [{"cve": cve, "text": text, "score": float(score)}
                         for cve, text, score in items]}
    dst = out / f"{NAME}-fixtures.json"
    dst.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8", newline="\n")
    return dst


# ---------------- Go 口径自检：重新读回 float32 资产 ----------------

class GoModel:
    """按 internal/ml/ml.go 的推理口径重实现（float32 资产 → float64 累加）。"""

    def __init__(self, assets: Path) -> None:
        meta = json.loads((assets / f"{NAME}.meta.json").read_text(encoding="utf-8"))
        if meta["token_pattern"] != TOKEN_PATTERN:
            raise SystemExit(f"meta.token_pattern={meta['token_pattern']!r} 与 Go 口径不符")
        if not (meta["lowercase"] and meta["sublinear_tf"] and meta["l2_norm"]):
            raise SystemExit("meta 的 lowercase/sublinear_tf/l2_norm 必须为 true")
        vocab = (assets / f"{NAME}.vocab.txt").read_text(encoding="utf-8").split("\n")
        if vocab and vocab[-1] == "":
            vocab.pop()  # 结尾换行（Go loadVocab 同样容忍）
        self.n_features = meta["n_features"]
        if len(vocab) != self.n_features:
            raise SystemExit(f"vocab 行数 {len(vocab)} != n_features {self.n_features}")
        self.vocab = {tok: i for i, tok in enumerate(vocab)}
        if len(self.vocab) != len(vocab):
            raise SystemExit("vocab 存在重复词（Go 侧会拒绝加载）")
        self.idf = np.fromfile(assets / f"{NAME}.idf.f32", dtype="<f4").astype(np.float64)
        self.coef = np.fromfile(assets / f"{NAME}.coef.f32", dtype="<f4").astype(np.float64)
        if self.idf.size != self.n_features or self.coef.size != self.n_features:
            raise SystemExit(f"idf/coef 长度 {self.idf.size}/{self.coef.size} != {self.n_features}")
        for label, arr in (("idf", self.idf), ("coef", self.coef)):
            if not np.all(np.isfinite(arr)):
                raise SystemExit(f"{label}.f32 含 NaN/Inf")
        self.intercept = float(meta["intercept"][0])

    def predict(self, text: str) -> float:
        counts = Counter(TOKEN_RE.findall(text.lower()))
        hits = sorted((self.vocab[tok], n) for tok, n in counts.items() if tok in self.vocab)
        if not hits:
            return min(10.0, max(0.0, self.intercept))  # 零向量：只剩 intercept
        ids = np.fromiter((i for i, _ in hits), dtype=np.int64, count=len(hits))
        vals = np.array([(1.0 + math.log(n)) * self.idf[i] for i, n in hits],
                        dtype=np.float64)
        norm = math.sqrt(float(vals @ vals))
        if norm == 0.0:
            return min(10.0, max(0.0, self.intercept))
        vals /= norm
        score = self.intercept + float(vals @ self.coef[ids])
        if not math.isfinite(score):
            raise SystemExit("预测出现 NaN/Inf")
        return min(10.0, max(0.0, score))  # 训练完 clip 到 [0,10]


def metrics(errs: np.ndarray) -> dict[str, float]:
    return {
        "mae": float(errs.mean()),
        "rmse": float(np.sqrt((errs ** 2).mean())),
        "p95": float(np.percentile(errs, 95)),
        "le1": float((errs <= 1.0).mean()),
        "max": float(errs.max()),
    }


def main() -> int:
    t0 = time.time()
    dump = nvd_dump_path()
    out = out_dir()
    print(f"[sev-linear] dump={dump}")
    print(f"[sev-linear] out ={out}")

    train_texts, train_scores, pool = load_dump(dump)
    if not train_texts or not pool:
        raise SystemExit("训练集或测试池为空：检查 dump 的 pub/score/descr 字段")
    print(f"[sev-linear] train={len(train_texts)}  pool(pub>={TRAIN_YEAR_MAX})={len(pool)}  "
          f"load {time.time() - t0:.1f}s")

    t = time.time()
    train_counts = [tokenize(s) for s in train_texts]
    vocab, idf = build_vocab(train_counts)
    vocab_map = {tok: i for i, tok in enumerate(vocab)}
    print(f"[sev-linear] vocab={len(vocab)} (df>={MIN_DF}, top {MAX_FEATURES})  "
          f"tokenize+build {time.time() - t:.1f}s")

    t = time.time()
    rows = pack_rows(train_counts, vocab_map, idf)
    nnz = sum(int(ids.size) for ids, _ in rows)
    del train_counts
    gc.collect()
    print(f"[sev-linear] nnz={nnz}  avg_nonzero/row={nnz / len(rows):.1f}  "
          f"pack {time.time() - t:.1f}s")

    t = time.time()
    w, b = train(rows, np.asarray(train_scores, dtype=np.float64), len(vocab))
    print(f"[sev-linear] train {EPOCHS} epochs  lr={LR} alpha={ALPHA}  "
          f"{time.time() - t:.1f}s  b={b:.4f}")
    if not (np.all(np.isfinite(w)) and math.isfinite(b)):
        raise SystemExit("训练发散：w/b 出现 NaN/Inf")
    del rows
    gc.collect()

    meta = export(out, vocab, idf, w, b)
    print(f"[sev-linear] exported n_features={meta['n_features']} intercept={b:.6f}")

    # ---- holdout（seed 20261030，20k）----
    rng = np.random.default_rng(HOLDOUT_SEED)
    holdout_idx = np.sort(rng.choice(len(pool), size=min(HOLDOUT_N, len(pool)), replace=False))
    holdout = [pool[int(i)] for i in holdout_idx]

    # ---- 夹具（seed 20261031，120 条，剔除 holdout → 与评测集不相交）----
    keep = np.setdiff1d(np.arange(len(pool)), holdout_idx, assume_unique=True)
    rng_f = np.random.default_rng(FIXTURE_SEED)
    fx_idx = np.sort(keep[rng_f.choice(keep.size, size=min(FIXTURE_N, keep.size), replace=False)])
    fixtures = [pool[int(i)] for i in fx_idx]
    if not fixtures:
        raise SystemExit("夹具为空：测试池不足 120 条，无法产出 Go 回归夹具")
    fx_path = write_fixtures(out, fixtures)
    print(f"[sev-linear] fixtures n={len(fixtures)} -> {fx_path.name}")

    # ---- 自检：按 Go 口径重算（读回 float32 资产）----
    t = time.time()
    gm = GoModel(out)
    hold_err = np.array([abs(gm.predict(text) - score) for _, text, score in holdout])
    fx_items = json.loads(fx_path.read_text(encoding="utf-8"))["items"]
    fx_err = np.array([abs(gm.predict(it["text"]) - float(it["score"])) for it in fx_items])
    hm, fm = metrics(hold_err), metrics(fx_err)
    print(f"[sev-linear] holdout n={len(holdout)}  MAE={hm['mae']:.4f}  RMSE={hm['rmse']:.4f}  "
          f"p95={hm['p95']:.3f}  <=±1={hm['le1']:.4f}  max={hm['max']:.3f}")
    print(f"[sev-linear] fixtures n={len(fx_err)}  MAE={fm['mae']:.4f}  "
          f"(Go 口径重算 {time.time() - t:.1f}s)")

    sizes = {}
    for p in (out / f"{NAME}.vocab.txt", out / f"{NAME}.idf.f32", out / f"{NAME}.coef.f32",
              out / f"{NAME}.meta.json", fx_path):
        sizes[p.name] = p.stat().st_size
    print("[sev-linear] sizes: " + "  ".join(f"{k}={v / 1024:.1f}KB" for k, v in sizes.items())
          + f"  total={sum(sizes.values()) / 1024:.0f}KB")
    peak = peak_rss_mb()
    print(f"[sev-linear] total {time.time() - t0:.1f}s  peak_rss="
          + (f"{peak:.0f}MB" if peak else "n/a"))

    if not np.all(np.isfinite(hold_err)) or not np.all(np.isfinite(fx_err)):
        print("[sev-linear] FAIL: 自检出现 NaN/Inf", file=sys.stderr)
        return 1
    if hm["mae"] > MAE_GATE:
        print(f"[sev-linear] FAIL: holdout MAE {hm['mae']:.4f} > 闸门 {MAE_GATE}", file=sys.stderr)
        return 1
    print("[sev-linear] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
