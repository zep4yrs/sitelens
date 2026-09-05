# -*- coding: utf-8 -*-
"""网络层安全检测（M6）：TLS 证书/协议 + DNS 邮件安全（SPF/DMARC/MX）。

TLS 用标准库 ssl 完成；DNS 查询用系统 nslookup（Windows/Linux 通用），
不引入额外依赖。全部为无攻击性的合规检测。
"""
import socket
import ssl
import subprocess
from datetime import datetime, timezone


def check_tls(host, port=443):
    """证书与协议检测，返回发现列表（无发现 = 空列表）"""
    hits = []
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                version = ss.version()
    except (OSError, ssl.SSLError):
        return []

    if cert:
        try:
            not_after = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (not_after - datetime.now(timezone.utc)).days
            if days < 0:
                hits.append({"check": "tls-expired", "title": "证书已过期",
                             "severity": "high", "url": host,
                             "evidence": "notAfter=%s" % cert["notAfter"],
                             "advice": "立即更换证书"})
            elif days < 30:
                hits.append({"check": "tls-expiring", "title": "证书即将过期",
                             "severity": "medium", "url": host,
                             "evidence": "剩余 %d 天" % days,
                             "advice": "安排证书续期"})
            issuer = str(cert.get("issuer", ""))
            subject = str(cert.get("subject", ""))
            if issuer and issuer == subject:
                hits.append({"check": "tls-self-signed", "title": "自签名证书",
                             "severity": "medium", "url": host,
                             "evidence": issuer[:80], "advice": "改用 CA 签发证书"})
        except (KeyError, ValueError):
            pass

    if version and version not in ("TLSv1.2", "TLSv1.3"):
        hits.append({"check": "tls-old", "title": "协商到旧版 TLS（%s）" % version,
                     "severity": "medium", "url": "%s:%d" % (host, port),
                     "evidence": version, "advice": "服务端禁用 TLS1.1 及以下"})
    return hits


# 常见多标签公共后缀（够用于教学场景；完整版应接 Public Suffix List）
_MULTI_SUFFIX = ("com.cn", "net.cn", "org.cn", "gov.cn", "co.uk", "com.hk",
                 "com.tw", "com.au", "co.jp", "ne.jp", "com.sg")


def org_domain(host):
    """扫描主机 → 主域（邮件安全记录挂在主域与 _dmarc.<主域> 上）"""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIX:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host.lower()


def check_dns_mail(domain):
    """邮件安全：以主域评估 SPF/DMARC/MX，返回发现列表（含已查到的记录证据）"""
    hits = []
    org = org_domain(domain)
    spf_spots = [org] + ([domain] if domain != org else [])
    spf_records = []
    for spot in dict.fromkeys(spf_spots):          # 去重保序：主域优先
        for r in _txt(spot):
            if r.lower().startswith("v=spf1"):
                spf_records.append((spot, r))
    dmarc_records = [r for r in _txt("_dmarc." + org)
                     if r.lower().startswith("v=dmarc1")]
    apex_mx = _mx(org)
    host_mx = _mx(domain) if domain != org else []

    if not spf_records:
        hits.append({"check": "no-spf", "title": "缺少 SPF 记录（发件域易被伪造）",
                     "severity": "medium", "url": org, "evidence": "",
                     "advice": "在主域添加 v=spf1 TXT 记录限定合法发件源"})
    if not dmarc_records:
        hits.append({"check": "no-dmarc", "title": "缺少 DMARC 记录",
                     "severity": "medium", "url": "_dmarc." + org, "evidence": "",
                     "advice": "添加 _dmarc TXT 记录（p=quarantine 或 reject）"})
    elif any("p=none" in r.lower() for r in dmarc_records):
        hits.append({"check": "dmarc-none", "title": "DMARC 策略为 p=none（仅监控，不拦截伪造邮件）",
                     "severity": "low", "url": "_dmarc." + org,
                     "evidence": dmarc_records[0][:80],
                     "advice": "观察期结束后将策略升级为 p=quarantine 或 p=reject"})
    if not apex_mx and not host_mx:
        hits.append({"check": "no-mx", "title": "主域未配置 MX（该域不收邮件时属正常）",
                     "severity": "low", "url": org, "evidence": "",
                     "advice": "若需要收邮件再配置 MX；不收邮件可忽略"})
    return hits


def run_netsec(host, progress=None):
    """TLS + DNS 邮件安全合集（全面识别等级调用）"""
    progress = progress or (lambda done, total, msg: None)
    progress(1, 3, "TLS 检测")
    hits = check_tls(host)
    progress(2, 3, "DNS 邮件安全")
    hits += check_dns_mail(host)
    progress(3, 3, "完成")
    return hits


def _txt(domain):
    """TXT 记录解析（Windows 中文 nslookup：值在 'text =' 的续行引号内）"""
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain],
                              capture_output=True, timeout=10)
        out = proc.stdout.decode("gbk", errors="ignore").replace("\r", "")
    except Exception:
        return []
    records = []
    for seg in out.split("text =")[1:]:          # 每段 = 一条 TXT 记录的值
        val = []
        for l in seg.splitlines():
            t = l.strip().strip('"')
            if not t:
                if val:
                    break
                continue
            if t.startswith("服务器") or t.startswith("Non-authoritative"):
                break
            val.append(t)
        if val:
            records.append("".join(val))
    return records


def _mx(domain):
    try:
        proc = subprocess.run(["nslookup", "-type=MX", domain],
                              capture_output=True, timeout=10)
        out = proc.stdout.decode("gbk", errors="ignore")
    except Exception:
        return []
    return [l.strip() for l in out.splitlines() if "mail exchanger" in l or "MX preference" in l]

