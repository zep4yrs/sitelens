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
import re
import time
from urllib.parse import urljoin

from . import checks as checks_mod
from . import passive as passive_mod
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
from .version_cmp import version_in
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
        self._ranges = getattr(self._vulns, "_ranges", {}) or {}
        self._resolve = resolve                 # 单测可关掉 DNS 解析
        self.options = dict({
            "deep": True, "active_fp": False, "dir_scan": False, "dir_bypass": False,
            "subdomain": False, "service_probe": False, "browser_ua": False,
            "weak_audit": False, "webshell": False, "checks": "none",
            "auth_cookie": "", "netsec": False, "dast": False, "passive": False,
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
                        cap=300,
                        tech_tags={t.name for t in result.technologies},
                        query_text=(result.title or "") + " "
                                   + " ".join(t.name for t in result.technologies)),
                    progress=self._progress,
                    cancel_check=lambda: self._cancelled)
                result.set_verified(result.verified + nuclei_hits)

        if self.options.get("netsec") and not self._cancelled:
            self._progress(85, 100, "TLS / DNS 安全检测…")
            extras["netsec"] = netsec_mod.run_netsec(target.host)

        if self.options.get("passive") and not self._cancelled:
            self._progress(84, 100, "被动安全检测（Cookie 属性 / CSRF token）…")
            p_hits = []
            for ev, _ in pages:
                p_hits.extend(passive_mod.run_passive(
                    ev, ev.final_url or target.url))
            for h in p_hits:
                h.setdefault("src", "passive")
            result.set_verified(result.verified + p_hits)

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
            techs = self._apply_extracted_versions(result)
            result.set_vulnerabilities(
                self._vulns.match(techs)
                + self._vulns.match_cve_ms(techs))

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

    def _apply_extracted_versions(self, result):
        """验证线 → 情报线焊接：把 check/nuclei 抽取的版本号回填到对应技术。

        规则：verified 项带 extracted_version 时，匹配出抽取来源 URL 中
        提及技术名（check id/标题路径）的已识别技术；版本回填后按
        affected_ranges / vuln_kb.affected 重算三级判定。仅当该技术此前
        未识别出版本时回填（指纹识别的版本优先）。
        返回可能已更新的技术列表。
        """
        techs = list(result.technologies)
        by_name = {t.name.lower(): t for t in techs}
        for h in result.verified:
            ver = h.get("extracted_version")
            if not ver:
                continue
            tech = self._match_tech_for_hit(h, by_name)
            if tech is None or tech.version:
                continue
            tech.set_version(ver)
            h["verdict_applied"] = "%s 版本回填 %s" % (tech.name, ver)
            # 三级判定：抽取值直接喂 version_cmp（affected_ranges 命中 = confirmed）
            verdict, r = self._range_verdict(tech.name, ver)
            if verdict:
                h["verdict"] = "confirmed"
                h["verdict_detail"] = "%s %s 命中受影响区间 %s（%s）" % (
                    tech.name, ver, r.get("affected", ""),
                    r.get("cve") or r.get("title") or "intel-range")
        return techs

    # check id 中常见的产物名缩写/别名 → 规范名（词边界匹配用）
    # 11ty (Eleventy)：check/正文可能只出现 "11ty" 或 "eleventy" 之一
    TECH_ABBREVS = {"wp": "wordpress", "11ty": "11ty (eleventy)",
                    "eleventy": "11ty (eleventy)"}

    def _match_tech_for_hit(self, hit, by_name):
        """从 check id / 标题 / URL 中找出提及的已识别技术名。

        词边界匹配（避免 "go" 误命中 "golang" 之类子串）。
        技术名与正文统一按非字母数字切分为 token 后比对，统一规则为
        「全部词出现」：多词名（"apache tomcat"）、含标点/别名单名
        （"next.js" → next+js、"11ty (eleventy)" → 11ty+eleventy）
        同样适用——否则这类名字在纯字母数字 token 集里永远命中不上，
        版本抽取永不回填。
        缩写（wp → WordPress）仅对单词名生效，且要求全部 token 命中
        或缩写命中，避免 "next.js" 被 "next" 或 "js" 单独误命中。
        多个命中取名字最长者。
        """
        text = " ".join(str(hit.get(k) or "") for k in
                        ("check", "title", "url")).lower()
        tokens = set(re.split(r"[^a-z0-9]+", text))
        best = None
        for name_l, tech in by_name.items():
            if not name_l:
                continue
            # 技术名同样 token 化：多词、含标点单名（next.js）统一为
            # 「全部词出现」判定——这类名字在纯字母数字 token 集里
            # 原文永远命中不上；11ty (eleventy) 这类括号别名以词集
            # 相交判定（11ty 或 eleventy 任一出现即可，见 ALIAS 组）。
            words = [w for w in re.split(r"[^a-z0-9]+", name_l) if w]
            if len(words) > 1:
                ok = all(w in tokens for w in words) or any(
                    self.TECH_ABBREVS.get(t) == name_l for t in tokens)
            else:
                ok = name_l in tokens or any(
                    self.TECH_ABBREVS.get(t) == name_l for t in tokens)
            if ok and (best is None or len(name_l) > len(best[0])):
                best = (name_l, tech)
        return best[1] if best else None

    def _range_verdict(self, name, version):
        """版本 + affected_ranges.json → confirmed/None（version_cmp 三级判定的独立入口）"""
        ranges = self._ranges.get((name or "").lower(), [])
        for r in ranges:
            if version_in(version, r.get("affected", "")):
                return "confirmed", r
        return None, None

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
