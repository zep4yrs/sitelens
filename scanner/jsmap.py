# -*- coding: utf-8 -*-
"""JS 攻击面提取：bundle 内 API 端点枚举 + SourceMap 源码地图泄露检测。

源码地图（.js.map）会在公网暴露原始源码；bundle 里硬编码的接口路径
则暴露内部 API 攻击面。均为只读检测。
"""
import re
from urllib.parse import urljoin

API_RE = re.compile(r"[\"'](/(?:api|v[12]|rest|graphql|gateway|service)[/_a-zA-Z0-9\-]{2,50})[\"']")
MAP_RE = re.compile(r"sourceMappingURL=(\S+?)[\"'\s]")


def run_js_surface(fetcher, target, signals, progress=None, max_bundles=4):
    """扫描主 bundle：返回 (已验证发现, API 端点列表)"""
    progress = progress or (lambda done, total, msg: None)
    if not signals:
        return [], []
    srcs = signals.script_srcs[:max_bundles]
    findings, endpoints = [], []
    seen_eps = set()
    for i, src in enumerate(srcs):
        url = urljoin(target.url + "/", src)
        try:
            data = fetcher.fetch_bytes(url)
        except Exception:
            data = None
        if not data:
            progress(i + 1, max_bundles, src[:40])
            continue
        text = data.decode("utf8", errors="ignore")[:400000]

        # SourceMap 泄露
        m = re.search(r"sourceMappingURL=(\S+?)[\s\"']", text + ' ')
        if m:
            map_url = urljoin(url, m.group(1))
            try:
                mdata = fetcher.fetch_bytes(map_url)
            except Exception:
                mdata = None
            if mdata and mdata[:1] in (b"{", b"["):
                findings.append({
                    "check": "sourcemap-leak", "title": "SourceMap 源码地图泄露",
                    "severity": "medium", "url": map_url,
                    "evidence": "map 文件公网可访问（含原始源码引用）",
                    "advice": "生产环境移除 .map 文件或关闭 sourceMap 生成", "src": "js"})
                endpoints.append({"endpoint": map_url, "kind": "sourcemap"})

        # API 端点枚举
        for ep in API_RE.findall(text):
            if ep not in seen_eps:
                seen_eps.add(ep)
                endpoints.append({"endpoint": ep, "kind": "api"})
        progress(i + 1, max_bundles, "bundle %s" % src[:40])
    return findings, endpoints
