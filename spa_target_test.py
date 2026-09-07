# -*- coding: utf-8 -*-
"""SPA 测试页：JS 延迟注入登录表单（无头渲染 e2e 靶子）。
POST /login 校验 admin/admin123，命中返回欢迎页。"""
import http.server

SPA = b"""<html><body><div id="app">loading</div><script>
setTimeout(function(){
  document.getElementById("app").innerHTML =
    '<form action="/login" method="post"><input name="user"><input type="password" name="pass"></form>';
}, 300);
</script></body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(SPA)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        ok = "user=admin" in body and "pass=admin123" in body
        self.send_response(200 if ok else 403)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"welcome dashboard" if ok else b"denied")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", 5055), H).serve_forever()
