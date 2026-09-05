# -*- coding: utf-8 -*-
"""Nuclei http 模板 → SiteLens check 格式导入器。

支持子集：单 GET 请求、path 仅含 {{BaseURL}} 前缀、matchers 为
status/word 类型（含 part: header）。跳过 DSL/payload/二进制/交互式。
输出：data/nuclei_checks.json（组格式与 scanner/checks.py 对应）。

用法：python tools/import_nuclei.py
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
HTTP_DIR = ROOT / "data" / "nuclei" / "http"
OUT = ROOT / "data" / "nuclei_checks.json"

sys.path.insert(0, str(ROOT))


def convert(doc):
    """单模板 → check 记录；不支持返回 None"""
    if not isinstance(doc, dict):
        return None
    info = doc.get("info") or {}
    tid, name = doc.get("id"), info.get("name")
    sev = str(info.get("severity") or "info").lower()
    http = doc.get("http")
    if not tid or not name or not isinstance(http, list):
        return None
    req = http[0]
    if str(req.get("method", "GET")).upper() != "GET":
        return None
    paths = req.get("path") or []
    path = paths[0] if paths and isinstance(paths[0], str) else None
    if not path or "{{BaseURL}}" not in path:
        return None
    suffix = path.split("{{BaseURL}}", 1)[1]
    if "{{" in suffix or not suffix:
        return None
    if "interactsh" in json.dumps(doc)[:3000]:
        return None                                   # 需要外部回调，跳过

    matchers = req.get("matchers") or []
    if not isinstance(matchers, list) or not matchers:
        return None
    cond = str(req.get("matchers-condition") or "or").lower()
    groups = []
    for m in matchers:
        if not isinstance(m, dict):
            return None
        mtype = m.get("type")
        g = {}
        if mtype == "status":
            g["s"] = [int(x) for x in m.get("status", [])]
        elif mtype == "word":
            words = [str(w).lower() for w in (m.get("words") or [])]
            if not words:
                return None
            if str(m.get("part") or "body").lower() == "header":
                g["h"] = words
            elif str(m.get("condition", "or")).lower() == "and":
                g["wall"] = words
            else:
                g["wany"] = words
        else:
            return None                               # dsl/binary/其他
        if not g or all(not v for v in g.values()):
            return None
        groups.append(g)

    if cond == "and" and len(groups) > 1:
        merged = {}
        for g in groups:
            for k, v in g.items():
                if k == "s":
                    merged.setdefault("s", v)
                else:
                    merged.setdefault(k, []).extend(v)
        groups = [merged]

    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = tags.split(",")
    tags = [str(t).strip() for t in tags if str(t).strip()]
    return {
        "id": str(tid), "name": str(name)[:120], "sev": sev,
        "tags": tags[:6], "method": "GET", "path": suffix,
        "groups": groups,
    }


def main():
    files = sorted(HTTP_DIR.rglob("*.y*ml"))
    out, skip = [], 0
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf8", errors="replace"))
        except Exception:
            skip += 1
            continue
        c = convert(doc)
        if c:
            out.append(c)
        else:
            skip += 1
    OUT.write_text(json.dumps(out, ensure_ascii=False), encoding="utf8")
    print(f"[nuclei] 导入 {len(out)} 条 / 跳过 {skip} 条 → data/nuclei_checks.json")


if __name__ == "__main__":
    main()
