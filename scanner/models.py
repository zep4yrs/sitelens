"""实体层：用普通类 + 私有属性 + property 完成数据封装。

对应考核点「封装」：所有实体属性私有化（双下划线），
对外只暴露只读 property 与少量受控方法，防止外部绕过校验改数据。
"""
import time
from urllib.parse import urlparse


class Technology:
    """一项被识别出的技术（如 WordPress / Nginx / jQuery）"""

    def __init__(self, name, categories, confidence, version=None, website="", evidence=None):
        self.__name = name
        self.__categories = list(categories)          # 类别 id 列表，如 ["cms", "blog"]
        self.__confidence = int(confidence)           # 置信度 0-100
        self.__version = version                      # 识别出的版本号（可能为 None）
        self.__website = website                      # 官网
        self.__evidence = list(evidence or [])        # 命中证据描述列表

    @property
    def name(self):
        return self.__name

    @property
    def categories(self):
        return list(self.__categories)

    @property
    def confidence(self):
        return self.__confidence

    @property
    def version(self):
        return self.__version

    @property
    def website(self):
        return self.__website

    @property
    def evidence(self):
        return list(self.__evidence)

    def add_evidence(self, source, detail):
        """补充一条命中证据；每多一个独立来源，置信度 +5（上限 100）"""
        self.__evidence.append("%s: %s" % (source, detail))
        self.__confidence = min(100, self.__confidence + 5)

    def set_version(self, version):
        """版本号只允许设置一次（取第一个识别出的）"""
        if version and not self.__version:
            self.__version = version

    def __str__(self):
        v = " " + self.__version if self.__version else ""
        return "%s%s (%d%%)" % (self.__name, v, self.__confidence)


class PageEvidence:
    """一次 HTTP 采集得到的全部「证据」，供各检测器各取所需。

    证据来源分五类，与五个检测器一一对应：
    headers / cookies / meta / html(含 dom) / scripts(含内联脚本)
    """

    def __init__(self, url, status=0, headers=None, cookies=None, body="",
                 response_time=0.0, ip="", title="", final_url=""):
        self.__url = url
        self.__final_url = final_url or url
        self.__status = status
        self.__headers = dict(headers or {})
        self.__cookies = dict(cookies or {})
        self.__body = body or ""
        self.__response_time = response_time          # 秒
        self.__ip = ip
        self.__title = title
        self.__collected_at = time.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def url(self):
        return self.__url

    @property
    def final_url(self):
        return self.__final_url

    @property
    def host(self):
        return urlparse(self.__final_url).hostname or ""

    @property
    def status(self):
        return self.__status

    @property
    def headers(self):
        """响应头（原始大小写）"""
        return dict(self.__headers)

    def header(self, name, default=""):
        """大小写不敏感地取响应头"""
        for k, v in self.__headers.items():
            if k.lower() == name.lower():
                return v
        return default

    @property
    def cookies(self):
        return dict(self.__cookies)

    @property
    def body(self):
        return self.__body

    @property
    def response_time(self):
        return self.__response_time

    @property
    def ip(self):
        return self.__ip

    @property
    def title(self):
        return self.__title

    @property
    def collected_at(self):
        return self.__collected_at

    def set_title(self, title):
        """解析阶段回填页面标题（唯一允许修改的字段）"""
        if title and not self.__title:
            self.__title = title


class ScanResult:
    """一次扫描的完整结果：技术列表 + 页面信息 + 安全评分"""

    def __init__(self, url, host=""):
        self.__url = url
        self.__host = host
        self.__technologies = []                      # Technology 列表
        self.__pages = []                             # 爬取过的页面信息
        self.__security = None                        # SecurityReport
        self.__status = 0
        self.__response_time = 0.0
        self.__ip = ""
        self.__title = ""
        self.__scanned_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.__duration = 0.0
        self.__error = ""
        self.__vulnerabilities = []                   # 漏洞情报关联
        self.__verified = []                          # 已验证漏洞（check 命中）
        self.__extras = {}                            # 可选模块结果（目录/子域/服务）

    @property
    def url(self):
        return self.__url

    @property
    def host(self):
        return self.__host

    @property
    def technologies(self):
        return list(self.__technologies)

    @property
    def pages(self):
        return list(self.__pages)

    @property
    def security(self):
        return self.__security

    @property
    def status(self):
        return self.__status

    @property
    def response_time(self):
        return self.__response_time

    @property
    def ip(self):
        return self.__ip

    @property
    def title(self):
        return self.__title

    @property
    def scanned_at(self):
        return self.__scanned_at

    @property
    def duration(self):
        return self.__duration

    @property
    def error(self):
        return self.__error

    @error.setter
    def error(self, msg):
        self.__error = msg

    def set_vulnerabilities(self, vulns):
        self.__vulnerabilities = list(vulns or [])

    def set_verified(self, verified):
        self.__verified = list(verified or [])

    @property
    def verified(self):
        return list(self.__verified)

    @property
    def vulnerabilities(self):
        return list(self.__vulnerabilities)

    def set_extras(self, extras):
        self.__extras = dict(extras or {})

    @property
    def extras(self):
        return dict(self.__extras)

    def set_page_info(self, status, response_time, ip, title):
        self.__status = status
        self.__response_time = response_time
        self.__ip = ip
        self.__title = title

    def set_security(self, report):
        self.__security = report

    def add_technology(self, tech):
        """合并去重：同名技术只保留一条，证据与版本并入已有记录"""
        for existing in self.__technologies:
            if existing.name.lower() == tech.name.lower():
                for ev in tech.evidence:
                    existing.add_evidence(*ev.split(": ", 1) if ": " in ev else (ev, ""))
                existing.set_version(tech.version)
                return existing
        self.__technologies.append(tech)
        return tech

    def add_page(self, url, status):
        self.__pages.append({"url": url, "status": status})

    def finish(self, start_ts):
        self.__duration = round(time.time() - start_ts, 2)

    def to_dict(self):
        """序列化为 dict（API / 存储共用）"""
        return {
            "url": self.__url,
            "host": self.__host,
            "title": self.__title,
            "status": self.__status,
            "ip": self.__ip,
            "response_time_ms": int(self.__response_time * 1000),
            "scanned_at": self.__scanned_at,
            "duration": self.__duration,
            "error": self.__error,
            "security": self.__security.to_dict() if self.__security else None,
            "technologies": [
                {
                    "name": t.name,
                    "categories": t.categories,
                    "confidence": t.confidence,
                    "version": t.version,
                    "website": t.website,
                    "evidence": t.evidence,
                }
                for t in self.__technologies
            ],
            "vulnerabilities": self.__vulnerabilities,
            "verified": self.__verified,
            "extras": self.__extras,
            "pages": self.__pages,
        }
