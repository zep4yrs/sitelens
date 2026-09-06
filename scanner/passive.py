# -*- coding: utf-8 -*-
"""被动安全检测（M7）：基于已有采集证据的纯只读检查，不发任何额外请求。

两个模块（参考 Wapiti 被动模块思路）：
- check_cookie_attrs   Cookie 属性检查：HttpOnly / SameSite / Secure 缺失告警
- check_csrf_tokens    表单 CSRF token 存在性检查：登录/注册等表单缺 token 提示

数据来源为引擎已抓取的 PageEvidence（响应头 + Cookie + 页面表单），
因此零额外请求量，随「全面识别」等级默认运行。
全部为配置审查类发现，severity 均为 low/medium，不与情报混淆。
"""
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

# Cookie 属性提取：兼顾多 Set-Cookie 合并头（逗号+空格+name= 形态切分）
_SET_COOKIE_SPLIT = re.compile(r",(?=[^;,]+?=)")
_ATTR_TRUE = re.compile(r"(?:^|;)\s*(httponly|secure)\s*(?=;|$)", re.I)
_ATTR_VAL = re.compile(r"(?:^|[;,])\s*(samesite)\s*=\s*([a-z]+)", re.I)


def _extract_cookies(evidence):
    """从 PageEvidence 收集 (name, attrs, known) 列表。

    优先取响应头 Set-Cookie（attrs 可判定，known=True），
    补充会话 Cookie 名（attrs 未知，known=False，仅做 Secure 交叉提示）。
    """
    cookies = []
    seen = set()
    raw = evidence.header("Set-Cookie") or evidence.header("set-cookie")
    if raw:
        for part in _SET_COOKIE_SPLIT.split(raw):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            if not name or name in seen:
                continue
            seen.add(name)
            attrs = set()
            if _ATTR_TRUE.search(part):
                for m in _ATTR_TRUE.finditer(part):
                    attrs.add(m.group(1).lower())
            for m in _ATTR_VAL.finditer(part):
                attrs.add("samesite=" + m.group(2).lower())
            cookies.append((name, attrs, True))
    for name in (evidence.cookies or {}):
        if name not in seen:
            seen.add(name)
            cookies.append((name, set(), False))   # 会话 Cookie：属性未知
    return cookies


def check_cookie_attrs(evidence, base_url=""):
    """Cookie 属性检查（只读）。返回发现列表，无发现 = 空列表。"""
    hits = []
    base = base_url or evidence.final_url or evidence.url
    secure_transport = urlparse(base).scheme == "https"
    for name, attrs, known in _extract_cookies(evidence):
        notes = []
        if known and "httponly" not in attrs:
            notes.append("未设 HttpOnly（XSS 可窃取）")
        if known and "samesite" not in {a.split("=", 1)[0] for a in attrs}:
            notes.append("未设 SameSite（CSRF 面扩大）")
        if secure_transport and "secure" not in attrs:
            # 会话 Cookie 属性未知时只提示 Secure 交叉项，避免误报 HttpOnly/SameSite
            notes.append("未设 Secure（HTTPS 下明文回传）")
        if not notes:
            continue
        hits.append({
            "check": "cookie-attr",
            "title": "Cookie 缺少安全属性（%s）" % name,
            "severity": "medium" if (known and "httponly" not in attrs) else "low",
            "url": base,
            "evidence": "%s：%s" % (name, "；".join(notes)),
            "advice": "Set-Cookie 补齐 HttpOnly、Secure、SameSite=Lax/Strict",
            "src": "passive",
        })
    return hits


# 含密码/敏感输入的表单才检查 CSRF token（登录/注册/改密/管理员表单）
_SENSITIVE_INPUT = ("password", "passwd", "pwd", "email", "phone",
                    "card", "captcha", "username", "user", "account")
_TOKEN_HINT = ("csrf", "csrftoken", "_token", "authenticity_token",
               "xsrf", "xsrf-token", "xsrf_token", "anticsrf", "nonce")


def _looks_like_token(name):
    n = (name or "").lower()
    return any(h in n for h in _TOKEN_HINT)


def check_csrf_tokens(evidence, base_url=""):
    """表单 CSRF token 存在性检查（只读，静态判断不发请求）。

    规则：只检查含密码/身份类输入的敏感表单（登录/注册/改密）；
    表单任一隐藏输入名含 csrf/_token/nonce 类关键词即视为已防护。
    返回发现列表，无发现 = 空列表。
    """
    body = evidence.body or ""
    if not body or "<form" not in body.lower():
        return []
    base = base_url or evidence.final_url or evidence.url
    hits = []
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return []
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        names = [(i.get("name") or "").lower() for i in inputs]
        sensitive = any(any(k in n for k in _SENSITIVE_INPUT) for n in names)
        if not sensitive:
            continue
        if any(_looks_like_token(n) for n in names):
            continue
        action = (form.get("action") or "").strip()
        form_url = urljoin(base, action) if action else base
        hits.append({
            "check": "form-no-csrf",
            "title": "敏感表单未见 CSRF token",
            "severity": "low",
            "url": form_url,
            "evidence": "表单（含 password/身份输入）的隐藏域中未发现 "
                        "csrf/_token/nonce 类字段（token 可能经 JS 注入，需人工确认）",
            "advice": "为表单增加一次性 CSRF token 并在服务端校验；"
                      "或确认 token 由前端 JS 注入的防御方案",
            "src": "passive",
        })
    return hits


def run_passive(evidence, base_url=""):
    """被动检测合集：输入一次采集证据，返回发现列表（零额外请求）"""
    return check_cookie_attrs(evidence, base_url) \
        + check_csrf_tokens(evidence, base_url)
