/* SiteLens 共用外壳：左侧栏注入 + 设计令牌 + 公共函数
   每页在 <body> 起始处同步引入本文件，页面自身只写内容区 HTML 与页内脚本。 */
(function () {
  "use strict";

  /* ---------------- 霞鹜文楷字体（CDN 分包按需加载，断网回退系统字体栈） ---------------- */
  var fontLink = document.createElement("link");
  fontLink.rel = "stylesheet";
  fontLink.href = "https://cdn.jsdelivr.net/npm/lxgw-wenkai-webfont@1.7.0/style.css";
  document.head.appendChild(fontLink);

  /* ---------------- 设计令牌与公共组件样式（text-well 实测值） ---------------- */
  var CSS = [
    ":root{--background:#fafafa;--foreground:#1a1a1a;--primary:#3e3f3f;--primary-fg:#ffffff;",
    "--secondary:#f1f5f9;--muted:#f8fafc;--muted-fg:#64748b;--accent:#f1f5f9;",
    "--border:#e2e8f0;--input:#ffffff;--ring:#3e3f3f;--card:#ffffff;--radius:.35rem;",
    "--ok:#16a34a;--warn:#d97706;--danger:#dc2626;--info:#2563eb;",
    "--shadow-2xs:0 2px 0 0 rgba(51,51,51,.07);",
    "--shadow-sm:0 2px 0 0 rgba(51,51,51,.15),0 1px 2px -1px rgba(51,51,51,.15);",
    "--shadow-md:0 2px 0 0 rgba(51,51,51,.15),0 2px 4px -1px rgba(51,51,51,.15);",
    "--side-w:216px;",
    '--font-sans:"LXGW WenKai","Noto Sans SC","Source Han Sans SC",-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;',
    '--font-mono:ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",Menlo,"Cascadia Code","LXGW WenKai Mono","LXGW WenKai",monospace;}',
    ".dark{--background:#0f172a;--foreground:#f8fafc;--primary:#3b82f6;--primary-fg:#ffffff;",
    "--secondary:#334155;--muted:#334155;--muted-fg:#94a3b8;--accent:#475569;",
    "--border:#334155;--input:#1e293b;--ring:#3b82f6;--card:#1e293b;}",

    "*,*::before,*::after{box-sizing:border-box;}",
    "html{scroll-behavior:smooth;}",
    "body{margin:0;margin-left:var(--side-w);background:var(--background);color:var(--foreground);",
    "font-family:var(--font-sans);font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased;}",
    "a{color:inherit;text-decoration:none;}",
    "::selection{background:var(--ring);color:#fff;}",
    ".mono{font-family:var(--font-mono);}",
    "@media(max-width:900px){:root{--side-w:60px}body{margin-left:60px}",
    ".wb-side .brand span.txt,.wb-side .side-nav a span{display:none}",
    ".wb-side .side-nav a{justify-content:center;padding:10px 0}",
    ".wb-side .side-foot{display:none}}",

    /* ---------------- 左侧栏 ---------------- */
    ".wb-side{position:fixed;left:0;top:0;bottom:0;width:var(--side-w);z-index:60;",
    "display:flex;flex-direction:column;padding:14px 10px;border-right:1px solid var(--border);",
    "background:color-mix(in srgb,var(--card) 82%,transparent);backdrop-filter:blur(8px);}",
    ".side-head{display:flex;align-items:center;justify-content:space-between;padding:2px 6px 12px;}",
    ".brand{display:flex;align-items:baseline;gap:3px;font-family:var(--font-mono);",
    "font-weight:700;font-size:19px;letter-spacing:.02em;}",
    ".brand .dot{width:6px;height:6px;border-radius:50%;background:var(--ok);",
    "animation:sl-breathing 2.4s ease-in-out infinite;}",
    ".theme-btn{width:30px;height:30px;display:grid;place-items:center;border:1px solid var(--border);",
    "border-radius:var(--radius);background:var(--card);cursor:pointer;color:var(--foreground);",
    "font-size:14px;transition:box-shadow .15s;}",
    ".theme-btn:hover{box-shadow:var(--shadow-sm);}",
    ".side-nav{display:flex;flex-direction:column;gap:2px;margin-top:6px;}",
    ".side-nav a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--radius);",
    "font-size:13.5px;color:var(--muted-fg);transition:color .2s,background .2s;}",
    ".side-nav a svg{width:17px;height:17px;flex:none;}",
    ".side-nav a:hover{color:var(--foreground);background:var(--accent);}",
    ".side-nav a.active{color:var(--foreground);background:var(--accent);font-weight:500;}",
    ".side-foot{margin-top:auto;padding:10px 6px 2px;border-top:1px solid var(--border);",
    "font-size:11px;color:var(--muted-fg);}",

    /* ---------------- 页面容器 ---------------- */
    ".page{max-width:1060px;margin:0 auto;padding:30px 30px 60px;}",
    ".page h1{font-family:var(--font-mono);font-size:24px;font-weight:700;margin:0 0 6px;letter-spacing:.01em;}",
    ".page .sub{color:var(--muted-fg);font-size:13.5px;margin:0 0 22px;max-width:72em;line-height:1.8;}",

    /* ---------------- 按钮 ---------------- */
    ".btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 18px;",
    "font-size:14px;font-weight:500;border:none;border-radius:var(--radius);cursor:pointer;",
    "background:var(--primary);color:var(--primary-fg);box-shadow:var(--shadow-sm);",
    "transition:transform .12s,box-shadow .12s,background .2s;font-family:inherit;}",
    ".btn:hover{box-shadow:var(--shadow-md);}",
    ".btn:active{transform:translateY(2px);box-shadow:none;}",
    ".btn:disabled{opacity:.5;cursor:not-allowed;}",
    ".btn.ghost{background:var(--card);color:var(--foreground);border:1px solid var(--border);box-shadow:var(--shadow-2xs);}",
    ".btn.ghost:hover{background:var(--accent);}",
    ".btn.small{padding:6px 12px;font-size:13px;}",
    ".btn.danger{background:var(--danger);}",

    /* ---------------- 输入 ---------------- */
    ".url-input,.tb{width:100%;height:46px;padding:0 14px;font-family:var(--font-mono);font-size:14.5px;",
    "color:var(--foreground);background:var(--input);border:1px solid var(--border);",
    "border-radius:var(--radius);outline:none;transition:border .2s,box-shadow .2s;}",
    ".tb{height:38px;font-size:13.5px;}",
    ".url-input:focus,.tb:focus,.sel:focus{border-color:var(--ring);",
    "box-shadow:0 0 0 3px color-mix(in srgb,var(--ring) 18%,transparent);}",
    ".url-input::placeholder,.tb::placeholder,textarea::placeholder{color:var(--muted-fg);}",
    ".sel{height:38px;padding:0 8px;font-family:var(--font-sans);font-size:13.5px;color:var(--foreground);",
    "background:var(--input);border:1px solid var(--border);border-radius:var(--radius);outline:none;cursor:pointer;}",
    ".toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:0 0 14px;}",
    "textarea.batch-box{width:100%;min-height:220px;padding:12px 14px;font-family:var(--font-mono);",
    "font-size:13.5px;color:var(--foreground);background:var(--input);border:1px solid var(--border);",
    "border-radius:var(--radius);outline:none;resize:vertical;line-height:1.9;}",

    /* ---------------- 卡片 / 摘要格 ---------------- */
    ".card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px;",
    "box-shadow:var(--shadow-2xs);}",
    ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:0 0 18px;}",
    ".cell{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);",
    "padding:10px 14px;display:flex;flex-direction:column;gap:2px;}",
    ".cell span{font-size:11.5px;color:var(--muted-fg);}",
    ".cell b{font-family:var(--font-mono);font-size:16px;font-weight:600;word-break:break-all;}",

    /* ---------------- 徽章 ---------------- */
    ".badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;",
    "font-family:var(--font-mono);font-size:12px;border:1px solid var(--border);background:var(--muted);",
    "white-space:nowrap;}",
    ".badge.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent);",
    "background:color-mix(in srgb,var(--ok) 8%,transparent);}",
    ".badge.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 35%,transparent);",
    "background:color-mix(in srgb,var(--warn) 8%,transparent);}",
    ".badge.danger{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 35%,transparent);",
    "background:color-mix(in srgb,var(--danger) 8%,transparent);}",
    ".badge.info{color:var(--info);border-color:color-mix(in srgb,var(--info) 35%,transparent);",
    "background:color-mix(in srgb,var(--info) 8%,transparent);}",

    /* ---------------- 表格 ---------------- */
    ".tbl-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px;background:var(--card);}",
    "table.list{width:100%;border-collapse:collapse;font-size:13.5px;}",
    "table.list th{font-family:var(--font-mono);font-size:12px;font-weight:600;color:var(--muted-fg);",
    "text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);white-space:nowrap;}",
    "table.list td{padding:10px 14px;border-bottom:1px solid color-mix(in srgb,var(--border) 55%,transparent);",
    "vertical-align:top;}",
    "table.list tr:last-child td{border-bottom:none;}",
    "table.list tbody tr:hover{background:color-mix(in srgb,var(--accent) 55%,transparent);}",
    ".host{font-family:var(--font-mono);cursor:pointer;}",
    ".host:hover{text-decoration:underline;}",

    /* ---------------- 进度 / 骨架 / 空态 ---------------- */
    ".progressbar{height:8px;border-radius:999px;background:var(--secondary);overflow:hidden;margin:10px 0 14px;}",
    ".progressbar i{display:block;height:100%;width:0;border-radius:999px;background:var(--primary);",
    "transition:width .5s ease;}",
    ".skeleton{position:relative;overflow:hidden;background:var(--secondary);border-radius:6px;}",
    ".skeleton::after{content:'';position:absolute;inset:0;",
    "background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--card) 80%,transparent),transparent);",
    "animation:sl-shimmer 1.4s infinite;}",
    ".empty{display:flex;flex-direction:column;align-items:center;gap:10px;padding:70px 20px;",
    "color:var(--muted-fg);font-size:14px;text-align:center;}",
    ".empty .big{font-size:34px;opacity:.5;}",

    /* ---------------- 分区标题 ---------------- */
    ".sec-title{display:flex;align-items:baseline;gap:8px;margin:26px 0 12px;",
    "font-family:var(--font-mono);font-size:16px;font-weight:700;}",
    ".sec-title .count{font-size:12px;font-weight:400;color:var(--muted-fg);font-family:var(--font-sans);}",
    ".sec-title .right{margin-left:auto;display:flex;gap:8px;}",

    /* ---------------- 页签 ---------------- */
    ".tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin:0 0 20px;}",
    ".tab{padding:9px 16px;font-size:14px;color:var(--muted-fg);background:none;border:none;",
    "border-bottom:2px solid transparent;cursor:pointer;font-family:inherit;margin-bottom:-1px;}",
    ".tab:hover{color:var(--foreground);}",
    ".tab.active{color:var(--foreground);font-weight:600;border-bottom-color:var(--primary);}",
    ".tabpanel{display:none;min-height:55vh;}",
    ".tabpanel.active{display:block;}",

    /* ---------------- 杂项 ---------------- */
    ".chip{padding:5px 12px;font-size:12.5px;font-family:var(--font-mono);color:var(--muted-fg);",
    "background:var(--card);border:1px solid var(--border);border-radius:999px;cursor:pointer;",
    "transition:all .15s;}",
    ".chip:hover{color:var(--foreground);background:var(--accent);box-shadow:var(--shadow-2xs);}",
    ".muted{color:var(--muted-fg);}",
    ".hint{font-size:12.5px;color:var(--muted-fg);margin:8px 0 0;}",
    ".extras-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 18px;",
    "font-size:12.5px;line-height:2;word-break:break-all;}",
    ".toast{position:fixed;right:22px;bottom:22px;z-index:99;padding:10px 18px;font-size:13.5px;",
    "background:var(--primary);color:var(--primary-fg);border-radius:var(--radius);",
    "box-shadow:var(--shadow-md);opacity:0;transform:translateY(8px);transition:all .25s;pointer-events:none;}",
    ".toast.show{opacity:1;transform:none;}",
    ".toast.ok{background:var(--ok);}.toast.err{background:var(--danger);}",
    ".fade-up{animation:sl-fadeUp .5s ease both;}",
    "@keyframes sl-breathing{0%,100%{opacity:.35;transform:scale(.85)}50%{opacity:1;transform:scale(1.15)}}",
    "@keyframes sl-shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}",
    "@keyframes sl-fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}"
  ].join("");

  var style = document.createElement("style");
  style.textContent = CSS;
  document.head.appendChild(style);

  /* ---------------- 左侧栏 HTML ---------------- */
  var ICONS = {
    scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/></svg>',
    netsec: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-3 8-10V5l-8-3-8 3v7c0 7 8 10 8 10z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>',
    audit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="m10 13-2 2 2 2"/><path d="m14 11 2 2-2 2"/></svg>',
    brute: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    batch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 8 5-8 5-8-5z"/><path d="m4 12 8 5 8-5"/><path d="m4 17 8 5 8-5"/></svg>',
    history: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
    intel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
    verified: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>'
  };
  var NAV = [
    ["scan", "/app", "扫描"],
    ["netsec", "/app#netsec", "网络检测"],
    ["audit", "/audit", "源码审计"],
    ["brute", "/app#loginbrute", "登录爆破"],
    ["batch", "/batch", "批量"],
    ["history", "/history", "历史"],
    ["intel", "/intel", "情报库"],
    ["verified", "/history#verified", "已验证"],
    ["settings", "/settings", "设置"]
  ];
  function navKey() {
    var p = location.pathname, h = location.hash || "";
    if (p.indexOf("/app") === 0) {
      if (h === "#netsec") return "netsec";
      if (h === "#loginbrute") return "brute";
      return "scan";
    }
    if (p.indexOf("/history") === 0) return h === "#verified" ? "verified" : "history";
    if (p.indexOf("/audit") === 0) return "audit";
    if (p.indexOf("/batch") === 0) return "batch";
    if (p.indexOf("/intel") === 0) return "intel";
    if (p.indexOf("/settings") === 0) return "settings";
    return "";
  }
  function slUpdateNav() {
    var key = navKey();
    document.querySelectorAll(".side-nav a").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-key") === key);
    });
  }
  window.slUpdateNav = slUpdateNav;
  var nav = NAV.map(function (n) {
    return '<a href="' + n[1] + '" data-key="' + n[0] + '">' + ICONS[n[0]] + "<span>" + n[2] + "</span></a>";
  }).join("");
  var aside = document.createElement("aside");
  aside.className = "wb-side";
  aside.innerHTML =
    '<div class="side-head">' +
    '<a class="brand" href="/"><span class="txt">sitelens</span><span class="dot"></span></a>' +
    '<button class="theme-btn" onclick="toggleTheme()" title="切换明暗主题">◐</button></div>' +
    '<nav class="side-nav">' + nav + "</nav>" +
    '<div class="side-foot">仅限授权目标<br><span id="sl-ver">SiteLens</span></div>';
  document.body.insertBefore(aside, document.body.firstChild);
  slUpdateNav();
  window.addEventListener("hashchange", slUpdateNav);

  /* ---------------- 主题 ---------------- */
  window.toggleTheme = function () {
    var dark = document.documentElement.classList.toggle("dark");
    try { localStorage.setItem("sitelens-theme", dark ? "dark" : "light"); } catch (e) {}
  };

  /* ---------------- 公共函数 ---------------- */
  window.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  };

  function tok() {
    var t = "";
    try { t = localStorage.getItem("sitelens-token") || ""; } catch (e) {}
    return t ? { "X-Token": t } : {};
  }
  function asJson(r) {
    return r.json().then(function (j) {
      if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
      return j;
    });
  }
  window.api = {
    get: function (u) { return fetch(u, { headers: tok() }).then(asJson); },
    post: function (u, d) {
      return fetch(u, {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, tok()),
        body: JSON.stringify(d || {})
      }).then(asJson);
    }
  };

  var toastTimer = null;
  window.toast = function (msg, cls) {
    var el = document.getElementById("sl-toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "sl-toast";
      el.className = "toast";
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.className = "toast show " + (cls || "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.className = "toast " + (cls || ""); }, 2600);
  };

  /* 严重度 → 徽章 */
  window.sevBadge = function (sev, zh) {    var s = String(sev || "").toLowerCase();
    var cls = (s === "high" || s === "critical") ? "danger" : (s === "medium" ? "warn" : "ok");
    var label = zh || (s === "critical" ? "严重" : s === "high" ? "高危" :
      s === "medium" ? "中危" : s === "low" ? "低危" : (sev || "-"));
    return '<span class="badge ' + cls + '">' + esc(label) + "</span>";
  };

  /* 可选模块（extras）条目 → 单行文本；兼容 url/path 等不同字段名，绝不输出 body/headers */
  window.extrasLine = function (key, it) {
    it = it || {};
    if (key === "netsec")
      return "• [" + esc(it.severity) + "] " + esc(it.title) + " → " + esc(it.url || "");
    if (key === "dir_scan" || key === "webshell" || key === "js") {
      var u = String(it.url || it.path || it.endpoint || "");
      var p = u.replace(/^https?:\/\/[^\/]+/i, "");
      var st = it.status ? " → " + esc(it.status) : "";
      var sz = it.size ? " (" + esc(it.size) + "B)" : "";
      var ti = it.title && it.title !== "403 Forbidden" ? " " + esc(it.title) : "";
      return "• " + esc(p || u) + st + sz + ti;
    }
    if (key === "subdomain")
      return "• " + esc(it.subdomain) + " → " + esc(it.ip || "");
    if (key === "service")
      return "• :" + esc(it.port) + " " + esc(it.service || "") + " " + esc(it.product || "");
    if (key === "active_fp")
      return "• " + esc(it.product || "") + " (" + esc(it.path || it.url || "") + ", " + esc(it.status || "") + ")";
    var c = Object.assign({}, it);
    delete c.body;
    delete c.headers;
    return "• " + esc(c.title || c.url || c.product || JSON.stringify(c));
  };

  /* 外部参考链接：仅 http/https 协议渲染为 <a>，其余原样文本（防 javascript: 注入） */
  window.safeLink = function (url, text) {
    var u = String(url || "");
    if (!/^https?:\/\//i.test(u)) return esc(text || u);
    return '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' +
      esc(text || u) + "</a>";
  };

  /* 侧栏页脚显示服务端版本号（失败保持 SiteLens 文案） */
  api.get("/api/version").then(function (v) {
    var el = document.getElementById("sl-ver");
    if (el && v && v.version) el.textContent = "SiteLens v" + v.version;
  }).catch(function () {});
})();
