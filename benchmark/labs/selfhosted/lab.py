#!/usr/bin/env python3
# SiteLens 自建合成靶场（benchmark acceptance，Docker 不可用时的本地受控靶场）。
# 每个端点实现一个真实可复现的漏洞行为；安全端点用于误报（FPR）对照。
# 仅本机验收使用，不进入产品代码。
import html
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

INDEX = """<html><head><title>SelfHosted Lab</title></head><body>
<h1>SelfHosted Lab</h1>
<ul>
<li><a href="/vulnerabilities/sqli/?id=1">SQLi</a></li>
<li><a href="/vulnerabilities/xss_r/?name=test">XSS</a></li>
<li><a href="/vulnerabilities/fi/?page=include.php">LFI</a></li>
<li><a href="/vulnerabilities/csrf/">CSRF</a></li>
<li><a href="/login.php">Login (safe)</a></li>
</ul></body></html>"""

SAFE_LOGIN = """<html><head><title>Login</title></head><body>
<h1>Sign in</h1>
<form method="post" action="/login.php">
<input type="hidden" name="csrf_token" value="tok-9f2c">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button type="submit">Login</button>
</form></body></html>"""

CSRF_PAGE = """<html><head><title>Change password</title></head><body>
<h1>Change password</h1>
<form method="post" action="/vulnerabilities/csrf/">
<input name="password_new" placeholder="new password">
<input name="password_conf" placeholder="confirm password">
<button type="submit">Change</button>
</form></body></html>"""

UPLOAD_PAGE = """<html><head><title>Upload</title></head><body>
<h1>Upload avatar</h1>
<form method="post" action="/vulnerabilities/upload/" enctype="multipart/form-data">
<input type="file" name="upload">
<button type="submit">Upload</button>
</form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.57 (Debian)"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra_headers=None):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _param(self, q, name):
        return q.get(name, [""])[0]

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query, keep_blank_values=True)

        if path in ("/", "/index.php"):
            return self._send(200, INDEX)
        if path in ("/login.php", "/WebGoat/start.mvc"):
            return self._send(200, SAFE_LOGIN)
        if path == "/vulnerabilities/csrf/":
            return self._send(200, CSRF_PAGE)
        if path == "/vulnerabilities/upload/" or path == "/Pass-01/index.php":
            return self._send(200, UPLOAD_PAGE)
        if path == "/vulnerabilities/fi/":
            page = self._param(q, "page")
            if ".." in page or "/etc/passwd" in page:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
            return self._send(200, "<html><body>include.php content</body></html>")
        if path == "/vulnerabilities/xss_r/" or path == "/level1.php":
            name = self._param(q, "name")
            # 反射型 XSS：payload 原样回显（未编码）。
            return self._send(200, "<html><head><title>Reflected XSS</title></head><body><h2>Hello %s</h2></body></html>" % name)
        if path in ("/vulnerabilities/sqli/", "/vul/sqli/sqli_str.php",
                    "/Less-1/", "/Less-1/index.php", "/bWAPP/sqli_1.php"):
            ident = self._param(q, "id") or self._param(q, "name") or self._param(q, "title")
            if "'" in ident or '"' in ident:
                # 报错注入面：把用户输入拼进 SQL 后的真实报错样式。
                return self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%s' at line 1" % html.escape(ident))
            if re.search(r"1\s*'\s*=\s*'2|1\s*=\s*2|and\s+1\s*=\s*2", ident, re.I):
                return self._send(200, "<html><body>No records found.</body></html>")
            if re.search(r"1\s*'\s*=\s*'1|1\s*=\s*1|and\s+1\s*=\s*1", ident, re.I):
                return self._send(200, "<html><body>ID: 1<br>First name: admin<br>Surname: admin</body></html>")
            return self._send(200, "<html><body>ID: 1<br>First name: admin<br>Surname: admin</body></html>")
        return self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        if parsed.path == "/vulnerabilities/csrf/":
            # 无 anti-CSRF token 的密码修改端点：总能成功。
            return self._send(200, "Password changed.")
        if parsed.path == "/login.php":
            return self._send(200, SAFE_LOGIN.replace("<h1>Sign in</h1>", "<h1>Sign in</h1><p>Invalid credentials.</p>"))
        if parsed.path in ("/vulnerabilities/upload/", "/Pass-01/index.php"):
            return self._send(200, "upload ok")
        return self._send(404, "not found")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("selfhosted lab on http://127.0.0.1:%d" % PORT, flush=True)
    srv.serve_forever()
