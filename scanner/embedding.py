# -*- coding: utf-8 -*-
"""文本向量化：字符 3-gram 哈希 TF-IDF（离线、零依赖、确定性）。

用于漏洞情报的语义式模糊匹配：不依赖在线模型，短文本场景下与
trgm 相似度互补。维度 256，L2 归一化，余弦相似度即点积。
"""
import hashlib
import math

DIM = 256


def embed_text(text, dim=DIM):
    """文本 → 归一化稠密向量（hashing trick，字符 3-gram + 词级特征）"""
    if not text:
        return [0.0] * dim
    text = text.lower()
    grams = []
    for i in range(max(1, len(text) - 2)):
        grams.append(text[i:i + 3])
    for word in text.split():
        if 2 <= len(word) <= 24:
            grams.append("w:" + word)
    tf = {}
    for g in grams:
        tf[g] = tf.get(g, 0) + 1
    vec = [0.0] * dim
    for g, count in tf.items():
        h = int(hashlib.sha256(g.encode("utf8")).hexdigest()[:8], 16)
        idx = h % dim
        sign = 1.0 if (h >> 31) & 1 == 0 else -1.0
        vec[idx] += sign * (1.0 + math.log(count))
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]


def cosine(a, b):
    """余弦相似度（两向量均已归一化时等价于点积）"""
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))
