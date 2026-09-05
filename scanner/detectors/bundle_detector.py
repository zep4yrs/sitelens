# -*- coding: utf-8 -*-
"""JS bundle 内容特征识别：打包进产物的框架不再漏检。

现代站点把 React/Framer/Monaco 等编译进 bundle，script src 与内联脚本
都看不出真身。BundleDetector 抓取同域主 bundle（≤3 个、单个 ≤2MB），
用库签名正则匹配源码，命中即新增技术项。
"""
import re
from urllib.parse import urljoin

from .base import BaseDetector

# (技术名, 类别, 置信度, bundle 源码特征)
BUNDLE_SIGNATURES = [
    ("React", "js-framework", 90, r"react-dom[.-]production|__SECRET_INTERNALS_DO_NOT_USE|react\.element"),
    ("Vue.js", "js-framework", 90, r"__VUE_HMR_RUNTIME_|vue-runtime-helpers|createStaticVNode"),
    ("Angular", "js-framework", 90, r"ngDevMode|@angular/core"),
    ("Svelte", "js-framework", 85, r"svelte_register|__svelte"),
    ("SolidJS", "js-framework", 80, r"solid-js|getOwner\(\)\.owner"),
    ("Framer Motion", "js-library", 90, r"framer-motion|MotionConfig|animate::before"),
    ("Monaco Editor", "editor", 90, r"MonacoEnvironment|monaco-editor"),
    ("Three.js", "js-graphics", 85, r"REVISION\s*=\s*'\d{3}'|THREE\.WebGLRenderer"),
    ("ECharts", "js-graphics", 85, r"echarts|registerMap\("),
    ("Stripe", "payment", 85, r"js\.stripe\.com/v3|mstripe\."),
    ("Swiper", "js-library", 80, r"swiper-slide|Swiper\b.*container"),
    ("Day.js", "js-library", 80, r"dayjs"),
    ("Socket.IO", "js-library", 85, r"socket\.io|engine\.io"),
    ("Quill", "rich-editor", 85, r"quill"),
    ("hls.js", "video-player", 85, r"hls\.js|Hls\.isSupported"),
]


class BundleDetector(BaseDetector):
    """下载主 bundle 源码做库签名匹配（FIELD=None：自带 scan 流程）"""

    FIELD = None
    SOURCE = "Bundle"
    MAX_BUNDLES = 3
    MAX_BYTES = 2_000_000

    def __init__(self, fetcher):
        self._fetcher = fetcher
        self._signatures = [
            (name, cat, conf, re.compile(pat, re.I))
            for name, cat, conf, pat in BUNDLE_SIGNATURES
        ]
        self._seen_urls = set()          # 深爬多页时只处理一次
        self._cache_hits = None          # 同一批 bundle 的命中缓存

    def scan(self, evidence, signals=None):
        if evidence.url in self._seen_urls:
            return self._cache_hits or []
        self._seen_urls.add(evidence.url)
        self._cache_hits = []

        srcs = (signals.script_srcs if signals else []) or []
        # 优先同域 bundle（第三方统计脚本特征已由其他检测器覆盖）
        parsed = _split(evidence.final_url or evidence.url)
        origin = "%s://%s" % (parsed.scheme, parsed.hostname)
        own = [s for s in srcs if origin in s][: self.MAX_BUNDLES]
        if not own:
            own = srcs[: self.MAX_BUNDLES]

        blob_parts = []
        for src in own:
            url = urljoin(evidence.final_url or evidence.url, src)
            data = self._fetcher.fetch_bytes(url)
            if data and len(data) <= self.MAX_BYTES:
                blob_parts.append(data.decode("utf8", errors="ignore")[:500000])
        blob = "\n".join(blob_parts)
        if not blob:
            return []

        for name, cat, conf, regex in self._signatures:
            m = regex.search(blob)
            if m:
                detail = "bundle 命中 %s" % m.group(0)[:40]
                self._cache_hits.append((name, detail, None))
                _CATS[name] = cat
                _CONFS[name] = conf
        return self._cache_hits

    def detect(self, evidence, signals=None):
        return self.scan(evidence, signals)

    def cat_for(self, name):
        return _CATS.get(name)

    def conf_for(self, name):
        return _CONFS.get(name)

    def _match_fingerprint(self, rule, evidence, signals):
        return None, None


# 引擎从这两个映射取类别/置信度（签名驱动的动态指纹）
_CATS = {}
_CONFS = {}


def split_url(url):
    from urllib.parse import urlparse
    return urlparse(url)


def _split(url):
    return split_url(url)
