// 故意暴露靶场：为部分路径返回「真实暴露」内容，其余路径 200 通用页。
// 用途：漏报门禁——期望命中对应 check（git/env/actuator/凭据/备份/日志等）。
// 内容按各 check 的判据构造（强特征），用于验证端到端链路：
// 软 404 基线、二次确认、同路径聚类、回显剔除。
// 用法：node vulnerable.js [port]（默认 18082）
const http = require("http");
const port = Number(process.argv[2] || 18082);

const routes = {
  "/.git/HEAD": "ref: refs/heads/main\n",
  "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
  "/.env": "DB_HOST=127.0.0.1\nDB_PASSWORD=supersecret\nAPI_KEY=abcd1234\n",
  "/.env.local": "SECRET_KEY=local-secret\nDB_PASSWORD=local-pass\n",
  "/phpinfo.php": "<html><body><?php phpinfo(); ?></body></html>",
  "/php.ini": "[PHP]\nshort_open_tag = On\nsafe_mode = Off\nexpose_php = On\n",
  "/info.php": "<html><body><h1>PHP Version 8.2.10</h1><h2>PHP Extension</h2></body></html>",
  "/actuator": '{"_links":{"self":{"href":"/actuator"}}}',
  "/actuator/heapdump": "JAVA PROFILE 1.0.2\n",
  "/actuator/health": '{"status":"UP"}',
  "/actuator/env/": '{"propertySources":[{"name":"systemProperties"}]}',
  "/swagger-ui/index.html": "<html><body>Swagger UI Version: 5.0.0 ?v=5</body></html>",
  "/v2/api-docs": '{"swagger":"2.0"}',
  "/backup.sql": "INSERT INTO users VALUES (1,'admin');\n",
  "/backup.zip": "PK\x03\x04fakezip",
  "/.aws/credentials": "[default]\naws_access_key_id = AKIAFAKE\naws_secret_access_key = fake\n",
  "/.kube/config": "clusters:\n- name: test\n  cluster:\n    server: https://k8s.local\n",
  "/terraform.tfstate": '{"version":4,"terraform_version":"1.5.0"}',
  "/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
  "/config.php.bak": "<?php define('DB_PASSWORD','fake'); ?>",
  "/server-status": "<html><title>Apache Status</title>Apache Server Status</html>",
  "/manager/html": "<html><title>Tomcat Web Application Manager</title></html>",
  "/docker-compose.yml": "services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: fake\n      MYSQL_DATABASE: app\n# local composer cache\n# Mount source-code\n",
  "/Dockerfile": "FROM nginx:alpine\n",
  "/_cluster/health": '{"cluster_name":"test","status":"green"}',
  "/api/v1/namespaces": '{"kind":"NamespaceList","items":[]}',
  "/version": '{"gitVersion":"v1.28.0"}',
  "/status": "<html><title>VerneMQ Status</title><h1>Issues</h1><h2>Cluster Overview</h2><h3>Node Status</h3></html>",
};

const generic = `<!doctype html><html><head><title>Example Site</title></head>
<body><h1>Welcome</h1><p>generic page</p></body></html>`;

const server = http.createServer((req, res) => {
  const path = req.url.split("?")[0];
  if (Object.prototype.hasOwnProperty.call(routes, path)) {
    const code = path === "/manager/html" ? 401 : 200;
    res.writeHead(code, { "Content-Type": "text/plain; charset=utf-8" });
    res.end(routes[path]);
    return;
  }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(generic);
});
server.listen(port, "127.0.0.1", () => console.log("vulnerable fixture on " + port));
