"""检测器继承体系。

BaseDetector 定义统一的 detect() 接口；五个子类各自消费指纹规则中的
一种证据字段，Engine 多态地遍历所有检测器，不关心具体类型。

指纹规则字段 -> 检测器 的对应关系：
    headers       -> HeaderDetector   响应头（server/x-powered-by/cf-ray...）
    cookies       -> CookieDetector   Cookie（会话/框架特征...）
    meta          -> MetaDetector     <meta> 标签（generator/验证码...）
    html / dom    -> HtmlDetector     原文正则 / css 选择器命中
    scripts / js  -> ScriptDetector   外部脚本地址 / 内联脚本内容
"""
import re
from abc import ABC, abstractmethod


VERSION_RE = re.compile(r"\d")


def version_from_match(m):
    """捕获组 1 只有形如版本号（数字开头）时才采信，避免把 (.min) 当版本"""
    if m and m.groups() and m.group(1) and VERSION_RE.match(m.group(1)):
        return m.group(1)
    return None


class BaseDetector(ABC):
    """检测器抽象基类：子类声明自己消费的证据字段并实现 scan()"""

    #: 子类消费的指纹规则字段名（如 "headers"）
    FIELD = None
    #: 人类可读的证据来源名（写入命中证据，如 "响应头"）
    SOURCE = ""

    def __init__(self, fingerprints):
        self._fingerprints = fingerprints     # 全量指纹列表（数据驱动）

    @abstractmethod
    def scan(self, evidence, signals=None):
        """扫描一次采集证据，返回命中列表 [(tech_name, rule, version|None)]"""

    def detect(self, evidence, signals=None):
        """模板方法：统一遍历指纹，子类实现 _match_fingerprint"""
        hits = []
        for fp in self._fingerprints:
            rules = fp.get("rules") or {}
            if self.FIELD not in rules:
                continue
            matched, version = self._match_fingerprint(rules[self.FIELD], evidence, signals)
            if matched:
                hits.append((fp["name"], matched, version))
        return hits

    @abstractmethod
    def _match_fingerprint(self, rule, evidence, signals):
        """对单条指纹应用本类证据，返回 (命中描述|None, 版本|None)"""


class HeaderDetector(BaseDetector):
    """响应头检测：server / x-powered-by / via / cf-ray 等"""

    FIELD = "headers"
    SOURCE = "响应头"

    def scan(self, evidence, signals=None):
        hits = []
        for fp in self._fingerprints:
            rules = (fp.get("rules") or {}).get(self.FIELD)
            if not rules:
                continue
            matched, version = self._match_fingerprint(rules, evidence, signals)
            if matched:
                hits.append((fp["name"], matched, version))
        return hits

    def _match_fingerprint(self, rule, evidence, signals):
        # rule 形如 {"server": ["nginx(?:/([\\d.]+))?"], "cf-ray": ["."]}
        for header_name, patterns in rule.items():
            value = evidence.header(header_name)
            if not value:
                continue
            for pattern in patterns:
                m = re.search(pattern, value, re.I)
                if m:
                    version = version_from_match(m)
                    return "%s=%s" % (header_name.lower(), value[:80]), version
        return None, None


class CookieDetector(BaseDetector):
    """Cookie 检测：框架会话 Cookie 是最稳定的后端指纹之一"""

    FIELD = "cookies"
    SOURCE = "Cookie"

    def _match_fingerprint(self, rule, evidence, signals):
        names = evidence.cookies.keys()
        # rule 形如 ["^csrftoken$", "^PHPSESSID"]，按正则匹配 cookie 名
        for cookie_name in names:
            for pattern in rule:
                m = re.search(pattern, cookie_name, re.I)
                if m:
                    version = version_from_match(m)
                    return "cookie %s" % cookie_name, version
        return None, None

    def scan(self, evidence, signals=None):
        return self.detect(evidence, signals)


class MetaDetector(BaseDetector):
    """<meta> 检测：generator / site verification / 主题标识"""

    FIELD = "meta"
    SOURCE = "meta"

    def _match_fingerprint(self, rule, evidence, signals):
        # rule 形如 {"generator": "WordPress ([\\d.]+)?"}
        metas = signals.metas if signals else {}
        for meta_name, pattern in rule.items():
            content = metas.get(meta_name.lower())
            if not content:
                continue
            m = re.search(pattern, content, re.I)
            if m:
                version = version_from_match(m)
                return "%s=%s" % (meta_name, content[:60]), version
        return None, None

    def scan(self, evidence, signals=None):
        return self.detect(evidence, signals)


class HtmlDetector(BaseDetector):
    """HTML 原文正则 + DOM 选择器双通道检测"""

    FIELD = "html"
    SOURCE = "HTML"

    def _match_fingerprint(self, rule, evidence, signals):
        # rule 形如 {"html": ["wp-content"], "dom": ["#wpadminbar"]} 的子集
        body = evidence.body or ""
        for pattern in rule.get("html", []):
            m = re.search(pattern, body, re.I)
            if m:
                version = version_from_match(m)
                return "正则 %s" % pattern[:40], version
        if signals:
            for selector in rule.get("dom", []):
                if selector in signals.dom_hits:
                    return "DOM %s" % selector, None
        return None, None

    def scan(self, evidence, signals=None):
        return self.detect(evidence, signals)


class ScriptDetector(BaseDetector):
    """脚本检测：外部脚本地址 + 内联脚本内容（分析/支付/框架的最强信号）"""

    FIELD = "scripts"
    SOURCE = "脚本"

    def _match_fingerprint(self, rule, evidence, signals):
        srcs = signals.script_srcs if signals else []
        inlines = signals.inline_scripts if signals else []
        for pattern in rule.get("src", []):
            for src in srcs:
                m = re.search(pattern, src, re.I)
                if m:
                    version = version_from_match(m)
                    return "src %s" % src[:80], version
        for pattern in rule.get("content", []):
            for text in inlines:
                m = re.search(pattern, text, re.I)
                if m:
                    version = version_from_match(m)
                    return "内联JS %s" % pattern[:40], version
        return None, None

    def scan(self, evidence, signals=None):
        return self.detect(evidence, signals)
