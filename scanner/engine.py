# -*- coding: utf-8 -*-
"""扫描引擎：把 校验 → 采集 → 解析 → 爬取 → 检测 → 漏洞关联 → 模块 串成流水线。

ScannerEngine 是「组合」关系的核心体现：
    Fetcher        组合 RateLimiter
    SiteCrawler    组合 Fetcher
    ScannerEngine  组合 Fetcher + Crawler + 检测器列表 + Registry + VulnMatcher
检测阶段多态：engine 只调用 detector.detect(evidence, signals)，
不区分是 HeaderDetector 还是 TscanDetector。

options 可选开关（默认全关，授权测试用）：
    deep            同域浅爬取（默认开）
    active_fp       FingerDir 主动路径指纹
    dir_scan        目录探测          dir_bypass  403 绕过重试
    subdomain       子域名枚举        service_probe  端口服务识别
"""
import time
from urllib.parse import urljoin

from . import checks as checks_mod
from . import netsec as netsec_mod
from . import dast as dast_mod
from . import jsmap as jsmap_mod
from . import modules
from .crawler import SiteCrawler
from .detectors import BundleDetector, TscanDetector, build_detectors
from .evidence import extract_signals
from .favicon import favicon_hash
from .fetcher import Fetcher
from .models import ScanResult, Technology
from .registry import Registry
from .security import assess_security
from .target import ScanTarget, TargetError
from .vuln import VulnMatcher


class ScannerEngine:
    """一次完整扫描的编排器"""

    def __init__(self, registry=None, fetcher=None, rate_interval=0.4, progress=None,
                 options=None, resolve=True):
        self.registry = registry or Registry()
        opts0 = options or {}
        self.fetcher = fetcher or Fetcher(
            rate_interval=rate_interval, browser_ua=bool(opts0.get("browser_ua", False)),
            cookie=str(opts0.get("auth_cookie") or ""))
        self._detectors = build_detectors(self.registry.fingerprints,
                                          self.registry.tscan or None,
                                          fetcher=self.fetcher)
        self._bundle = next((d for d in self._detectors
                             if isinstance(d, BundleDetector)), None)
        self._tscan = next((d for d in self._detectors
                            if isinstance(d, TscanDetector)), None)
        self._vulns = VulnMatcher(self.registry.kb)
        self._resolve = resolve                 # 单测可关掉 DNS 解析
        self.options = dict({
            "deep": True, "active_fp": False, "dir_scan": False, "dir_bypass": False,
            "subdomain": False, "service_probe": False, "browser_ua": False,
            "weak_audit": False, "webshell": False, "checks": "none",
            "auth_cookie": "", "netsec": False, "dast": False,
        }, **(options or {}))
        self._progress = progress or (lambda done, total, msg: None)
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def scan(self, url):
        """执行扫描，返回 ScanResult（异常统一抛 TargetError，消息可直接展示）"""
        start = time.time()
        target = ScanTarget(url, resolve=self._resolve)  # 1) 校验（含 SSRF 防护）
        result = ScanResult(target.url, host=target.host)
        self._progress(5, 100, "校验目标：%s" % target)

        evidence = self.fetcher.fetch(target.url)      # 2) 采集首页
        if evidence.status >= 400:
            result.error = "目标返回 HTTP %d" % evidence.status
            result.finish(start)
            return result
        self._progress(25, 100, "已采集首页（%d）" % evidence.status)

        signals = extract_signals(evidence)            # 3) 解析信号
        self._maybe_favicon(target, evidence, signals)
        result.set_page_info(evidence.status, evidence.response_time,
                             evidence.ip, evidence.title)
        result.add_page(evidence.final_url, evidence.status)

        pages = [(evidence, signals)]
        if self.options.get("deep"):                   # 4) 同域浅爬取（遵循 robots.txt）
            crawler = SiteCrawler(self.fetcher, target, max_pages=4,
                                  progress=self._progress,
                                  robots=self._load_robots(target))
            pages = crawler.crawl(evidence, signals)
            for ev, _ in pages[1:]:
                result.add_page(ev.url, ev.status)

        self._progress(55, 100, "运行 %d 个检测器…" % len(self._detectors))
        for ev, sig in pages:                          # 5) 多态检测
            if self._cancelled:
                break
            self._run_detectors(ev, sig, result)

        self._progress(75, 100, "评估安全响应头…")
        result.set_security(assess_security(evidence))  # 6) 安全评分

        extras = {}
        if self.options.get("checks", "none") != "none":   # 6.5) 验证型 check
            cms_ids = set()
            for t in result.technologies:                  # CMS 联动调度
                cms_ids.update(checks_mod.CMS_TECH_CHECKS.get(t.name, ()))
            if cms_ids:
                self._progress(79, 100, "CMS 联动专项：%s" %
                               ",".join(sorted(cms_ids)))
            result.set_verified(checks_mod.run_checks(
                self.fetcher, target,
                level=self.options["checks"], progress=self._progress,
                include_ids=cms_ids,
                cancel_check=lambda: self._cancelled))
            if self.options["checks"] == "all" and not self._cancelled:
                self._progress(84, 100, "运行 Nuclei 社区模板子集…")
                nuclei_hits = checks_mod.run_nuclei(
                    self.fetcher, target,
                    checks_mod.select_nuclei(
                        cap=80,
                        tech_tags={t.name for t in result.technologies},
                        query_text=(result.title or "") + " "
                                   + " ".join(t.name for t in result.technologies)),
                    progress=self._progress,
                    cancel_check=lambda: self._cancelled)
                result.set_verified(result.verified + nuclei_hits)

        if self.options.get("netsec") and not self._cancelled:
            self._progress(85, 100, "TLS / DNS 安全检测…")
            extras["netsec"] = netsec_mod.run_netsec(target.host)

        if self.options.get("dast") and not self._cancelled:
            self._progress(86, 100, "JS 攻击面提取…")
            try:
                js_find, js_eps = jsmap_mod.run_js_surface(
                    self.fetcher, target, signals, progress=self._progress)
                extras.setdefault("js", []).extend(js_eps)
                for h in js_find:
                    h["src"] = "js"
                result.set_verified(result.verified + js_find)
            except Exception:
                pass
            self._progress(87, 100, "参数级 DAST 探测…")
            links = [l for _, sig in pages for l in sig.link_hrefs]
            dast_hits = dast_mod.run_dast(self.fetcher, target, links,
                                          progress=self._progress)
            for h in dast_hits:
                h["src"] = "dast"
            result.set_verified(result.verified + dast_hits)
        if not self._cancelled:                        # 7) 漏洞情报关联
            self._progress(85, 100, "关联漏洞情报…")
            result.set_vulnerabilities(
                self._vulns.match(result.technologies)
                + self._vulns.match_cve_ms(result.technologies))

        self._run_modules(target, result, start)        # 8) 可选模块

        merged = dict(result.extras)
        for k, v in extras.items():
            merged.setdefault(k, v)
        if merged:
            result.set_extras(merged)

        result.finish(start)
        self._progress(100, 100, "完成，识别 %d 项技术，%d 条漏洞情报"
                       % (len(result.technologies), len(result.vulnerabilities)))
        return result

    def _load_robots(self, target):
        """拉取 robots.txt 解析为 RobotFileParser；不可得则返回 None（不限制）"""
        import urllib.robotparser
        try:
            resp = self.fetcher.get_small(target.url + "/robots.txt")
        except Exception:
            return None
        if resp.get("status") != 200 or not resp.get("body"):
            return None
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(resp["body"].splitlines())
        return rp

    def _maybe_favicon(self, target, evidence, signals):
        """TscanPlus 指纹需要 icon_hash 时抓取 favicon 并计算 fofa 哈希"""
        if not (self._tscan is not None and getattr(self._tscan, "needs_icon", False)):
            return
        icon_url = None
        for link in signals.links:
            if "icon" in (link.get("rel") or ""):
                icon_url = urljoin(evidence.final_url, link.get("href") or "")
                break
        candidates = [icon_url] if icon_url else []
        candidates.append(urljoin(evidence.final_url, "/favicon.ico"))
        for u in candidates:
            if self._cancelled:
                return
            data = self.fetcher.fetch_bytes(u)
            if data:
                signals.favicon_hash = favicon_hash(data)
                return

    def _run_detectors(self, evidence, signals, result):
        """把各检测器的命中合并进结果（同名技术共享置信度成长）"""
        tech_index = {}
        for detector in self._detectors:
            if self._cancelled:
                return
            for tech_name, detail, version in detector.detect(evidence, signals):
                fp = self._find_fingerprint(tech_name)
                tech = tech_index.get(tech_name.lower())
                if tech is None:
                    cats = fp.get("cats", []) if fp else []
                    conf = fp.get("conf", 80) if fp else 80
                    if not cats and self._bundle and self._bundle.cat_for(tech_name):
                        cats = [self._bundle.cat_for(tech_name)]
                        conf = self._bundle.conf_for(tech_name) or conf
                    if not cats and self.registry.tscan:
                        cats = [t["cat"] for t in self.registry.tscan
                                if t["name"] == tech_name][:1]
                    tech = Technology(
                        name=tech_name,
                        categories=cats,
                        confidence=conf,
                        version=version,
                        website=fp.get("website", "") if fp else "",
                        evidence=[],
                    )
                    tech_index[tech.name.lower()] = tech
                # add_technology 会去重合并，必须记到返回的规范实例上
                tech = result.add_technology(tech)
                tech.add_evidence(detector.SOURCE, detail)
                tech.set_version(version)

    def _run_modules(self, target, result, start):
        """按 options 运行可选模块（全部默认关闭）；各模块支持取消检查点"""
        opts = self.options
        extras = {}
        cancel = lambda: self._cancelled          # noqa: E731
        try:
            if opts.get("active_fp") and self.registry.fingerdir and not self._cancelled:
                self._progress(88, 100, "主动路径指纹…")
                extras["active_fp"] = modules.active_fingerprint(
                    self.fetcher, target, self.registry.fingerdir,
                    progress=self._progress, cancel_check=cancel)
            if opts.get("dir_scan") and not self._cancelled:
                self._progress(90, 100, "目录探测…")
                extras["dir_scan"] = modules.dir_scan(
                    self.fetcher, target, progress=self._progress,
                    bypass_403=bool(opts.get("dir_bypass")), cancel_check=cancel)
            if opts.get("subdomain") and not self._cancelled:
                self._progress(93, 100, "子域名枚举…")
                extras["subdomain"] = modules.subdomain_enum(
                    target.host, progress=self._progress, cancel_check=cancel)
            if opts.get("service_probe") and not self._cancelled:
                self._progress(96, 100, "端口服务识别…")
                extras["service"] = modules.service_probe(
                    target.host, self.registry.kb.db, progress=self._progress,
                    cancel_check=cancel)
            if opts.get("webshell") and not self._cancelled:
                self._progress(97, 100, "WebShell 路径探测…")
                extras["webshell"] = modules.webshell_probe(
                    self.fetcher, target, progress=self._progress, cancel_check=cancel)
            if opts.get("weak_audit") and not self._cancelled:
                self._progress(98, 100, "弱口令审计…")
                extras["weak_audit"] = modules.weak_audit(
                    self.fetcher, target, progress=self._progress)
        except TargetError:
            pass
        if extras:
            result.set_extras(extras)

    def _find_fingerprint(self, name):
        return self.registry.by_name.get(name)
