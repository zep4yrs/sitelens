# -*- coding: utf-8 -*-
"""靶场回归断言：对授权靶场跑全量扫描，断言预期检出。

用法：python tools/regression.py <靶场URL> [--expect check1,check2]
缺省断言：技术栈非空、安全报告存在。--expect 传逗号分隔的 check id
（如 phpinfo,git-leak,wp-login），命中判定：check id 或指纹名包含该关键字。
退出码：全部通过 0，否则 1。仅限授权目标使用。
"""
import sys

from scanner.engine import ScannerEngine


def main():
    url = ""
    expect = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--expect" and i + 1 < len(args):
            expect = [x.strip() for x in args[i + 1].split(",") if x.strip()]
            i += 2
            continue
        url = args[i]
        i += 1
    if not url:
        print(__doc__)
        return 2

    engine = ScannerEngine(
        options={"deep": True, "checks": "all"},
        progress=lambda d, t, m: print("[%3d%%] %s" % (d, m)))
    result = engine.scan(url)
    names = {t.name.lower() for t in result.technologies}
    check_ids = {v["check"] for v in result.verified}

    ok = True
    print("\n=== 回归断言 ===")
    print("技术栈 %d 项 / 已验证 %d 条 / 安全评分 %s(%d)" % (
        len(result.technologies), len(result.verified),
        result.security.grade, result.security.score))

    def assert_has(label, pred):
        nonlocal ok
        print(("  PASS " if pred else "  FAIL ") + label)
        ok = ok and pred

    assert_has("技术栈非空", len(result.technologies) > 0)
    assert_has("安全评分存在", bool(result.security))
    for cid in expect:
        hit = any(cid.lower() in n for n in names) or cid in check_ids
        assert_has("预期检出: " + cid, hit)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
