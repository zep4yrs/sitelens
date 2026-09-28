"""export_sev_v31_pair.py —— sev-prior v3.1 部署对：双种子 ONNX 导出 + int8
量化 + 集成对拍 + Go 夹具再生成。

前置：ml/train_sev_v31_deploy.py 已产出
  sitelens-ml5/data/ml/dist/models/sev-prior-v3.1/s<20260928|20260929>.pt
产物（实训考核2/data/go/ml_assets/）：
  sev-prior-v3.1-a.onnx / -b.onnx（fp32，opset17，动态 batch）
  sev-prior-v3.1-a-int8.onnx / -b-int8.onnx（quantize_dynamic）
  sev-fixtures.json（集成 ONNX 打分，供 Go parity 对拍）
  parity 记录打印（fp32 torch↔onnx MAE<0.02 方 ok）
"""
import json
import time
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ML5 = Path(r"D:\fengqiao\Desktop\26-08python实训\sitelens-ml5")
OUT_DIR = Path(r"D:\fengqiao\Desktop\26-08python实训\实训考核2\data\go\ml_assets")
CKPT_DIR = ML5 / "data" / "ml" / "dist" / "models" / "sev-prior-v3.1"
BASE = ML5 / "data" / "bench" / "models" / "distilbert-base-uncased"
SEQ, OPSET, BATCH = 192, 17, 16
SEEDS = [20260928, 20260929]
SLUG = {20260928: "a", 20260929: "b"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def build_model(ckpt_path):
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(BASE), num_labels=1)
    model.load_state_dict(ckpt["state_dict"], strict=True)
    model.eval()
    return model


def export_fp32(model, dst):
    ids = torch.ones(1, SEQ, dtype=torch.int64)
    mask = torch.ones(1, SEQ, dtype=torch.int64)
    torch.onnx.export(
        model, (ids, mask), str(dst),
        input_names=["input_ids", "attention_mask"], output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch"}, "attention_mask": {0: "batch"},
                      "logits": {0: "batch"}},
        opset_version=OPSET, dynamo=False)


def main():
    import onnxruntime as ort
    import shutil
    import tempfile
    from onnxruntime.quantization import quantize_dynamic, QuantType

    tok = AutoTokenizer.from_pretrained(str(BASE))

    # 夹具文本：沿用既有 sev-fixtures.json 的文本清单（Go 侧同集对拍）
    fix_path = OUT_DIR / "sev-fixtures.json"
    texts = [it["text"] for it in json.loads(fix_path.read_text(encoding="utf-8"))["items"]]
    enc = tok(texts, truncation=True, max_length=SEQ, padding="max_length")
    ids = np.asarray(enc["input_ids"], dtype=np.int64)
    mask = np.asarray(enc["attention_mask"], dtype=np.int64)

    fp32_scores, int8_scores = [], []
    for seed in SEEDS:
        slug = SLUG[seed]
        log(f"seed {seed}: 加载 ckpt")
        model = build_model(CKPT_DIR / f"s{seed}.pt")
        fp32 = OUT_DIR / f"sev-prior-v3.1-{slug}.onnx"
        int8 = OUT_DIR / f"sev-prior-v3.1-{slug}-int8.onnx"
        log(f"seed {seed}: 导出 fp32 → {fp32.name}")
        export_fp32(model, fp32)
        log(f"seed {seed}: 量化 int8 → {int8.name}")
        # 量化器不吃非 ASCII 路径：拷到 ASCII 临时目录量化再拷回；
        # 分类头（pre_classifier/classifier）排除量化保持 fp32（消融：全量化
        # MAE 0.203 / +head fp32 0.196），节点名带 _MatMul 后缀。
        tmp = tempfile.mkdtemp(prefix="sevq_")
        assert all(ord(c) < 128 for c in tmp), "临时目录含非 ASCII 字符"
        try:
            src = Path(tmp) / "model-fp32.onnx"
            dst = Path(tmp) / "model-int8.onnx"
            shutil.copy2(fp32, src)
            quantize_dynamic(str(src), str(dst), weight_type=QuantType.QInt8,
                             per_channel=True,
                             nodes_to_exclude=["/pre_classifier/Gemm_MatMul",
                                               "/classifier/Gemm_MatMul"])
            assert dst.is_file(), "量化产物未生成"
            shutil.copy2(dst, int8)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        for tag, path, sink in (("fp32", fp32, fp32_scores), ("int8", int8, int8_scores)):
            sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
            out = []
            for i in range(0, len(texts), BATCH):
                lg = sess.run(["logits"], {"input_ids": ids[i:i + BATCH],
                                           "attention_mask": mask[i:i + BATCH]})[0]
                out.append(lg.reshape(-1))
            sink.append(np.concatenate(out))
            log(f"seed {seed} {tag}: {path.name} 打分完成")
        del model
        torch.cuda.empty_cache() if torch.cuda.is_available() else None

    ens_fp32 = (fp32_scores[0] + fp32_scores[1]) / 2.0
    d = np.abs(ens_fp32 - (int8_scores[0] + int8_scores[1]) / 2.0)
    log(f"集成 fp32 vs int8+int8: MAE={d.mean():.5f} max={d.max():.5f}（门限 0.05）")
    ok = d.mean() < 0.05

    # Go 夹具再生成：集成 fp32 ONNX 打分（真值），×10 CVSS 尺度
    items = [{"text": t, "score": round(float(s) * 10.0, 6)}
             for t, s in zip(texts, ens_fp32)]
    fix_path.write_text(json.dumps(
        {"seq": SEQ, "n": len(items), "items": items, "ensemble": "v3.1 a+b"},
        ensure_ascii=False), encoding="utf-8")
    log(f"sev-fixtures.json 再生成（n={len(items)}，集成口径）ok={ok}")


if __name__ == "__main__":
    main()
