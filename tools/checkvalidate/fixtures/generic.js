// 通用站点靶场：任何路径都返回 200 + 通用 HTML（模拟 SPA 软 404）。
// 用途：误报门禁——全量内置 check 跑完应 0 命中。
// 用法：node generic.js [port]（默认 18081）
const http = require("http");
const port = Number(process.argv[2] || 18081);
const page = `<!doctype html>
<html><head><title>Example Site</title></head>
<body><h1>Welcome</h1><p>This is a generic page returned for every path.</p>
<ul><li>Home</li><li>About</li><li>Contact</li></ul></body></html>`;

const server = http.createServer((req, res) => {
  if (req.url === "/robots.txt") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("User-agent: *\nAllow: /\n");
    return;
  }
  if (req.url === "/favicon.ico") {
    res.writeHead(200, { "Content-Type": "image/x-icon" });
    res.end("");
    return;
  }
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Server": "nginx",
    "X-Powered-By": "Express",
  });
  res.end(page);
});
server.listen(port, "127.0.0.1", () => console.log("generic fixture on " + port));
