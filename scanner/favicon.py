# -*- coding: utf-8 -*-
"""favicon 指纹：fofa 风格 icon_hash（mmh3(base64(icon)))。

TscanPlus 指纹中的 icon_hash 条件即此算法；mmh3 用纯 Python 实现
（32 位 x86 MurmurHash3），避免额外依赖。
"""
import base64


def mmh3_32(data, seed=0):
    """MurmurHash3 x86 32 位（返回有符号整数，与 fofa 一致）"""
    data = bytearray(data)
    length = len(data)
    nblocks = length // 4
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h = seed & 0xFFFFFFFF

    def rotl(x, r):
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

    for i in range(nblocks):
        k = (data[i * 4] | (data[i * 4 + 1] << 8) |
             (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24))
        k = (k * c1) & 0xFFFFFFFF
        k = rotl(k, 15)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = rotl(h, 13)
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = rotl(k, 15)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16

    # 转有符号 32 位
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def favicon_hash(icon_bytes):
    """fofa icon_hash：base64 编码后取 mmh3"""
    b64 = base64.encodebytes(icon_bytes)
    return mmh3_32(b64)
