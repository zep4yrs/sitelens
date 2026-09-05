"""证据解析：用 BeautifulSoup 把 HTML 拆成结构化信号。

EvidenceExtractor 负责「采集之后、检测之前」的一步：
把原始 HTML 提炼成 meta / 脚本地址 / 内联脚本 / DOM 选择器命中 等信号，
检测器只面向信号工作，不直接碰原始 HTML（职责分离）。
"""
from bs4 import BeautifulSoup


class HtmlSignals:
    """一次解析得到的 HTML 信号集合"""

    def __init__(self):
        self.metas = {}               # name/property/http-equiv -> content
        self.script_srcs = []         # 外部脚本地址
        self.inline_scripts = []      # 内联脚本内容（截断存储）
        self.stylesheets = []         # 样式表地址
        self.links = []               # 其他 link（字体/预加载/图标）
        self.classes = set()          # 全页 class 名集合（识别 Tailwind/Bootstrap 等）
        self.ids = set()              # 全页 id 集合
        self.dom_hits = {}            # css 选择器 -> 命中数（预置常用选择器）
        self.link_hrefs = []          # <a href>（爬虫用）
        self.has_html = False
        self.favicon_hash = None      # fofa 风格 icon_hash（引擎按需回填）

    def to_dict(self):
        return {
            "metas": self.metas,
            "script_srcs": self.script_srcs,
            "stylesheets": self.stylesheets,
            "inline_scripts": len(self.inline_scripts),
            "class_count": len(self.classes),
            "link_count": len(self.link_hrefs),
        }


# DOM 检测器要探测的 css 选择器池（技术特征 → 选择器）
DOM_PROBES = [
    "#wpadminbar", "#wp-footer", "[class*='wp-block']",            # WordPress
    "#__next", "[data-reactroot]", "[data-react-helmet]",          # Next.js / React
    "#__nuxt", "[data-v-]", "[data-vue]",                          # Nuxt / Vue
    "[data-radix-popper-content-wrapper]", "[data-state]",         # Radix UI
    "[data-framer-name]", "[data-framer-appear-id]",               # Framer Motion/Framer
    ".elementor", "#elementor",                                    # Elementor
    ".woocommerce", ".woocommerce-result-count",                   # WooCommerce
    ".gh-canvas", "#ghost-portal",                                 # Ghost
    ".gutenberg", ".wp-block-buttons",                             # Gutenberg
    ".monaco-editor", ".monaco-mouse-cursor-text",                 # Monaco Editor
    ".bootstrap-datetimepicker", ".btn-primary",                   # Bootstrap
    "[data-bs-toggle]",                                            # Bootstrap 5
    ".ql-editor", ".ProseMirror", ".tox",                          # Quill/ProseMirror/TinyMCE
    "framer-wrapper",                                              # Framer Sites
    "[data-sentry-component]",                                     # Sentry
    "#gatsby-focus-wrapper", "[data-gatsby-image-wrapper]",        # Gatsby
    ".astro-wrapper", "astro-island",                              # Astro
    "#__footer", ".shopify-section",                               # Shopify
    "[x-data]", "[x-cloak]",                                       # Alpine.js
    "[wire\\:id]",                                                 # Livewire
    "[data-turbo]", "[data-turbolinks]",                           # Turbo/Turbolinks
    ".leaflet-container", ".mapboxgl-map", "#gmimap0", ".gm-style",# 地图
    ".plyr", ".video-js", ".jw-player", "#youtube-player",         # 播放器
    ".hcaptcha", ".g-recaptcha", ".cf-turnstile",                  # 验证码
    ".revealing-footer", "[data-sal]",                             # 动效库
]


def extract_signals(evidence):
    """从 PageEvidence.body 提炼 HtmlSignals"""
    signals = HtmlSignals()
    body = evidence.body
    if not body:
        return signals
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return signals
    signals.has_html = True

    title = soup.find("title")
    if title:
        evidence.set_title(title.get_text(strip=True)[:200])

    # 1) meta 信号
    for meta in soup.find_all("meta"):
        key = meta.get("name") or meta.get("property") or meta.get("http-equiv")
        content = (meta.get("content") or "").strip()
        if key and content:
            signals.metas[key.lower()] = content

    # 2) 外部脚本 / 内联脚本
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            signals.script_srcs.append(src)
        elif script.string and len(script.string.strip()) > 0:
            signals.inline_scripts.append(script.string.strip()[:4000])

    # 3) link（样式表、字体、图标）
    for link in soup.find_all("link"):
        href = link.get("href") or ""
        rel = " ".join(link.get("rel") or [])
        if not href:
            continue
        if "stylesheet" in rel:
            signals.stylesheets.append(href)
        else:
            signals.links.append({"rel": rel, "href": href, "as": link.get("as", "")})

    # 4) class / id 集合
    for tag in soup.find_all(True):
        for cls in (tag.get("class") or []):
            signals.classes.add(cls)
        if tag.get("id"):
            signals.ids.add(tag["id"])

    # 5) DOM 选择器探测（限定选择器池，避免任意选择器开销）
    for selector in DOM_PROBES:
        try:
            hits = soup.select(selector)
            if hits:
                signals.dom_hits[selector] = len(hits)
        except Exception:
            continue

    # 6) 站内链接（爬虫用）
    base = evidence.final_url or evidence.url
    for a in soup.find_all("a", href=True):
        signals.link_hrefs.append((a["href"], base))

    return signals
