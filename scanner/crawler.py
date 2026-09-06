"""同域浅爬取：从入口页跟随站内链接，合并证据提高检出率。

很多技术（统计脚本、客服组件）只在部分子页面出现，仅扫首页会漏检。
SiteCrawler 用 BFS 限制「同域 + 最多 max_pages 页 + 最大深度 1 跳」，
把每个页面的证据合并后交给检测器。
"""
from collections import deque
from urllib.parse import urljoin, urlparse

from .evidence import extract_signals
from .target import TargetError


class SiteCrawler:
    """浅爬取器（组合 Fetcher，体现组件拼装）"""

    def __init__(self, fetcher, target, max_pages=4, progress=None, robots=None):
        self._fetcher = fetcher
        self._target = target          # ScanTarget：范围边界
        self._max_pages = max_pages
        self._progress = progress or (lambda done, total, msg: None)
        self._robots = robots          # RobotFileParser 或 None

    def crawl(self, first_evidence, first_signals):
        """从首页开始浅爬，返回 [(PageEvidence, HtmlSignals), ...]（含首页）"""
        results = [(first_evidence, first_signals)]
        queue = deque(self._same_site_links(first_signals.link_hrefs))
        seen = {first_evidence.final_url, first_evidence.url}

        while queue and len(results) < self._max_pages:
            raw_url = queue.popleft()
            url = urljoin(raw_url[1], raw_url[0]).split("#")[0]
            if url in seen or not self._target.same_site(url):
                continue
            seen.add(url)
            if self._robots is not None and not self._robots.can_fetch("*", url):
                continue               # robots.txt 禁止抓取
            # 只跟内容页，跳过明显的大文件
            if urlparse(url).path.lower().endswith((".jpg", ".png", ".zip", ".pdf", ".mp4", ".webp", ".svg", ".css", ".js")):
                continue
            try:
                ev = self._fetcher.fetch(url)
            except TargetError:
                continue
            if ev.status != 200 or not ev.body:
                continue
            sig = extract_signals(ev)
            results.append((ev, sig))
            self._progress(len(results), self._max_pages, url)
        return results

    def _same_site_links(self, link_pairs):
        picked = []
        for href, base in link_pairs:
            absu = urljoin(base, href)
            p = urlparse(absu)
            if p.scheme in ("http", "https") and (p.hostname or "") == self._target.host:
                picked.append((absu, base))
        return picked[:40]
