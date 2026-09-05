# -*- coding: utf-8 -*-
"""版本区间判定（M2）：判断组件版本是否落在受影响区间。

区间语法（与常见漏洞库兼容的精简子集）：
    ">=8.3,<8.3.7"   多条件逗号分隔，全部满足才命中
    "<=2.4.1" / ">1.0" / "=3.2" / "!=1.9"
    "*"              任意版本
版本比较：按数字段逐段比较（8.3.7 与 8.3 等价补零）。
"""


def _parse(v):
    """版本字符串 → 数字元组（忽略非数字后缀）"""
    parts = []
    for seg in v.strip().lstrip("v").split("."):
        digits = ""
        for ch in seg:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def cmp_version(a, b):
    """a<b 返回 -1，相等 0，a>b 返回 1"""
    pa, pb = _parse(a), _parse(b)
    return (pa > pb) - (pa < pb)


def version_in(version, affected):
    """version 是否命中 affected 区间串（如 ">=8.3,<8.3.7"，"*" 或空 = 不判定）"""
    if not version or not affected:
        return False
    if affected.strip() == "*":
        return True               # 显式通配 = 任意版本受影响
    if not affected.strip():
        return False              # 空区间 = 情报未标注，不做判定
    version = version.strip().lstrip("v")
    for cond in affected.split(","):
        cond = cond.strip()
        if not cond:
            continue
        if cond == "*":
            continue
        op = "="
        for candidate in (">=", "<=", "!=", ">", "<", "="):
            if cond.startswith(candidate):
                op = candidate
                cond = cond[len(candidate):]
                break
        c = cmp_version(version, cond)
        ok = {"=": c == 0, "!=": c != 0, ">=": c >= 0,
              "<=": c <= 0, ">": c > 0, "<": c < 0}[op]
        if not ok:
            return False
    return True
