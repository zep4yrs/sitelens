# -*- coding: utf-8 -*-
"""离线 JWT HS256 密钥字典校验（不发起任何网络请求）。

用途：审计「你自己的」token 是否使用了弱密钥——签发方自查，
不是攻击工具。字典来自漏洞收集包（data/wordlists/full/JWT字典*.txt）。

用法：
  python tools/jwt_check.py <JWT> [字典路径]
  默认字典：data/wordlists/full/ 下第一个 JWT 字典文件
"""
import base64
import hashlib
import hmac
import sys
from pathlib import Path

DICT_DIR = Path(__file__).resolve().parents[1] / "data" / "wordlists" / "full"


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def check_token(token, words):
    """HS256：逐候选密钥验签，命中返回密钥"""
    try:
        header_b64, payload_b64, sig_b64 = token.strip().split(".")
        header = b64url_decode(header_b64)
    except ValueError:
        print("token 格式不对（应为三段式）")
        return None
    alg = __import__("json").loads(header).get("alg", "")
    if alg.upper() != "HS256":
        print("仅支持 HS256 对称签名，该 token 是", alg)
        return None
    signing_input = ("%s.%s" % (header_b64, payload_b64)).encode()
    expected = b64url_decode(sig_b64)
    for word in words:
        word = word.strip()
        if not word:
            continue
        if hmac.compare_digest(
                hmac.new(word.encode(), signing_input, hashlib.sha256).digest(),
                expected):
            return word
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    token = sys.argv[1]
    if len(sys.argv) >= 3:
        dict_path = Path(sys.argv[2])
    else:
        cands = sorted(DICT_DIR.glob("JWT*"))
        if not cands:
            print("未找到字典：请先运行 tools/import_assets.py，或手动指定字典路径")
            return
        dict_path = cands[0]
    words = dict_path.read_text(encoding="utf8", errors="ignore").splitlines()
    print("字典：%s（%d 条）" % (dict_path.name, len(words)))
    found = check_token(token, words)
    if found:
        print("⚠ 命中弱密钥：%r —— 请立即更换为 ≥256 位随机密钥" % found)
    else:
        print("✔ 未命中字典（不代表密钥安全，仅说明不在本字典内）")


if __name__ == "__main__":
    main()
