"""扫描目标：URL 解析与安全校验（SSRF 防护）。

SiteLens 允许用户提交任意 URL，服务端会代为发起请求——这正是 SSRF
（服务端请求伪造）攻击的入口。TargetValidator 强制：
1. 仅允许 http / https 协议；
2. 域名解析后拒绝环回、私有、链路本地与保留地址；
3. 拒绝 localhost、*.local、无效端口等常见绕过写法。
"""
import ipaddress
import socket
from urllib.parse import urlparse


class TargetError(ValueError):
    """目标 URL 不合法或不允许扫描"""


class TargetValidator:
    """URL 安全校验器（纯静态方法，无状态）"""

    PRIVATE_NETS = [
        ipaddress.ip_network("127.0.0.0/8"),        # 环回
        ipaddress.ip_network("10.0.0.0/8"),         # A 类私有
        ipaddress.ip_network("172.16.0.0/12"),      # B 类私有
        ipaddress.ip_network("192.168.0.0/16"),     # C 类私有
        ipaddress.ip_network("169.254.0.0/16"),     # 链路本地
        ipaddress.ip_network("0.0.0.0/8"),          # 未指定
        ipaddress.ip_network("100.64.0.0/10"),      # 运营商级 NAT
        ipaddress.ip_network("::1/128"),            # IPv6 环回
        ipaddress.ip_network("fc00::/7"),           # IPv6 唯一本地
        ipaddress.ip_network("fe80::/10"),          # IPv6 链路本地
    ]

    BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "metadata.google.internal"}

    @classmethod
    def validate(cls, url, resolve=True):
        """校验并规范化 URL，返回 (scheme, host, port)。

        resolve=True 时做 DNS 解析校验（引擎主路径）；
        resolve=False 供单元测试等无网络场景跳过解析。
        不合法时抛 TargetError，消息可直接展示给用户。
        """
        if not url or not url.strip():
            raise TargetError("请输入网址")
        url = url.strip()
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url          # 容错：省略协议时默认 https

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise TargetError("仅支持 http/https 协议")

        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            raise TargetError("URL 缺少主机名")
        if host in cls.BLOCKED_HOSTS or host.endswith(".local") or host.endswith(".internal"):
            raise TargetError("不允许扫描内网或保留主机名")

        port = parsed.port                   # 非法端口会在此抛 ValueError
        if port is not None and not (0 < port < 65536):
            raise TargetError("端口号不合法")

        if resolve:
            cls.__ensure_public_host(host)
        return scheme, host, port

    @classmethod
    def __ensure_public_host(cls, host):
        """域名解析后逐个 IP 校验，防止 DNS 指向内网（DNS Rebinding 的第一步）"""
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            raise TargetError("域名解析失败：%s" % host)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                raise TargetError("目标解析到保留/内网地址（%s），已拒绝" % ip)
        if not infos:
            raise TargetError("域名解析失败：%s" % host)


class ScanTarget:
    """一次扫描的目标（封装校验结果，供引擎与爬虫使用）"""

    def __init__(self, url, resolve=True):
        scheme, host, port = TargetValidator.validate(url, resolve=resolve)
        self.__url = "%s://%s%s" % (scheme, host, "" if port in (None, 80, 443) else ":%d" % port)
        self.__scheme = scheme
        self.__host = host
        self.__port = port

    @property
    def url(self):
        return self.__url

    @property
    def scheme(self):
        return self.__scheme

    @property
    def host(self):
        return self.__host

    @property
    def port(self):
        return self.__port

    def same_site(self, other_url):
        """判断 other_url 是否与本目标同域（爬虫范围限制）"""
        other = urlparse(other_url)
        other_host = (other.hostname or "").lower()
        other_scheme = (other.scheme or "").lower()
        return other_host == self.__host and other_scheme in ("http", "https")

    def __str__(self):
        return self.__url
