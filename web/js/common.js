/* SiteLens 共用外壳：左侧栏注入 + 设计令牌 + 公共函数 + 偏好引擎
   每页在 <body> 起始处同步引入本文件，页面自身只写内容区 HTML 与页内脚本。

   Turbo（SPA 化，2026-09-16）：侧栏切换不再整页重载——turbo.js 拦截页内链接，
   后台取新页只换 <body>。本文件随新 body **重新执行**，故分两层：
     · 一次性区（__slCommonLoaded 守卫）：head 注入、window/document 级监听、
       清理注册表——绝不叠加；
     · 每渲染区：偏好应用、侧栏壳重建（服务器 HTML 本身无侧栏）、版本号。
   换页前 turbo:before-render 统一冲刷 slPoll 等跨页资源（slOnCleanup 注册）。 */
(function () {
  "use strict";

  /* ---------------- 霞鹜文楷字体（CDN 分包按需加载，断网回退系统字体栈） ---------------- */
  function injectHeadLinks() {
    var fontLink = document.createElement("link");
    fontLink.rel = "stylesheet";
    fontLink.href = "https://cdn.jsdelivr.net/npm/lxgw-wenkai-webfont@1.7.0/style.css";
    document.head.appendChild(fontLink);

    /* ---------------- 页签图标（内联 SVG，免去 favicon 404 噪音） ---------------- */
    var iconLink = document.createElement("link");
    iconLink.rel = "icon";
    iconLink.href = "data:image/svg+xml," + encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
      '<circle cx="16" cy="16" r="12" fill="none" stroke="#0f766e" stroke-width="4"/>' +
      '<circle cx="16" cy="16" r="4" fill="#0f766e"/></svg>');
    document.head.appendChild(iconLink);

    /* ---------------- 设计令牌与公共组件样式（text-well 实测值） ---------------- */
    /* 设计令牌与公共组件样式改为独立文件 web/css/app.css（4.0 样式重构 A）：
       单一来源、可缓存、页面不再各自维护样式；经 /css/ 路由由引擎 embed 服务。 */
    var cssLink = document.createElement("link");
    cssLink.rel = "stylesheet";
    cssLink.href = "/css/app.css";
    document.head.appendChild(cssLink);
  }

  /* ---------------- 偏好存取（localStorage 单键 JSON，向后兼容旧 sitelens-theme） ---------------- */
  var FS_PX = { sm: "13.5px", md: "15px", lg: "16.5px", xl: "18px" };

  function loadPrefs() {
    var p = {};
    try { p = JSON.parse(localStorage.getItem("sitelens-prefs") || "{}") || {}; } catch (e) { p = {}; }
    if (!p.theme) {
      try { p.theme = localStorage.getItem("sitelens-theme") || "light"; } catch (e) { p.theme = "light"; }
    }
    if (!p.accent) p.accent = "";
    if (!p.fontScale) p.fontScale = "md";
    if (!p.lang) p.lang = "zh-CN";
    return p;
  }
  function savePrefs(p) {
    try { localStorage.setItem("sitelens-prefs", JSON.stringify(p)); } catch (e) {}
  }

  var PREFS = loadPrefs();

  /* ---------------- i18n：zh-CN 为缺省（键值即中文），其余语言按需补字典 ---------------- */
  var I18N = {
    "en-US": {
      nav_scan: "Scan", nav_netsec: "Net Scan", nav_audit: "Code Audit",
      nav_brute: "Login Brute", nav_batch: "Batch", nav_history: "History",
      nav_intel: "Intel", nav_verified: "Verified", nav_settings: "Settings",
      theme_toggle: "Toggle light/dark theme"
    }
  };
  function t(key) {
    if (PREFS.lang && I18N[PREFS.lang] && I18N[PREFS.lang][key]) return I18N[PREFS.lang][key];
    return null;
  }
  window.slT = t;
  window.slI18N = I18N;

  /* ---------------- 偏好应用：主题（light/dark/auto）+ 主题色 + 字号 ---------------- */
  function applyTheme() {
    var dark = PREFS.theme === "dark" ||
      (PREFS.theme === "auto" &&
        window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
  }
  function applyAccent() {
    var rootStyle = document.documentElement.style;
    if (PREFS.accent && /^#[0-9a-fA-F]{6}$/.test(PREFS.accent)) {
      rootStyle.setProperty("--primary", PREFS.accent);
      rootStyle.setProperty("--ring", PREFS.accent);
    } else {
      rootStyle.removeProperty("--primary");
      rootStyle.removeProperty("--ring");
    }
  }
  function applyFontScale() {
    if (FS_PX[PREFS.fontScale] && PREFS.fontScale !== "md") {
      document.documentElement.setAttribute("data-fs", PREFS.fontScale);
    } else {
      document.documentElement.removeAttribute("data-fs");
    }
  }
  applyTheme();
  applyAccent();
  applyFontScale();

  /* ================= 一次性区（本文件随 Turbo 换页重放，这里只许发生一次） ================= */
  if (!window.__slCommonLoaded) {
    window.__slCommonLoaded = true;

    injectHeadLinks();

    // 跟随系统：系统明暗变化实时反映（仅 auto 模式）。经 trampoline 调到最新闭包。
    if (window.matchMedia) {
      try {
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
          if (window.__slOnSchemeChange) window.__slOnSchemeChange();
        });
      } catch (_) { /* 旧浏览器无 addEventListener */ }
    }
    window.__slOnSchemeChange = applyTheme;

    // 侧栏高亮随 hash 变化（/app#netsec 等页内页签）
    window.addEventListener("hashchange", function () {
      if (window.slUpdateNav) window.slUpdateNav();
      if (window.slUpdateSide) window.slUpdateSide();
    });
    // 侧栏模式点击：工作台内即时切面板（Turbo 会拦 hash 点击且不发 hashchange）
    document.addEventListener("click", function (e) {
      var t = e.target;
      var a = t && t.closest ? t.closest(".wb-side .side-nav a") : null;
      if (!a || location.pathname !== "/app") return;
      var key = a.getAttribute("data-key");
      if (key && typeof window.switchTab === "function") {
        e.preventDefault();
        window.switchTab(key);
        if (window.slUpdateSide) window.slUpdateSide();
      }
    });

    /* 跨页清理注册表：页面级定时器/监听在此登记，换页前统一冲刷 */
    window.slCleanups = [];
    window.slOnCleanup = function (fn) { window.slCleanups.push(fn); };
    window.slFlushCleanups = function () {
      var fns = window.slCleanups;
      window.slCleanups = [];
      fns.forEach(function (f) { try { f(); } catch (e) {} });
    };
    // Turbo 换页前冲刷上一页的轮询/监听（Turbo 由各页 head 静态引入）
    var hookTurbo = function () {
      if (window.Turbo) {
        document.addEventListener("turbo:before-render", function () { window.slFlushCleanups(); });
      }
    };
    if (window.Turbo || document.readyState === "loading") {
      hookTurbo();
      if (!window.Turbo) {
        document.addEventListener("DOMContentLoaded", function () {
          if (!window.__slTurboHooked) { window.__slTurboHooked = true; hookTurbo(); }
        });
      }
    } else {
      hookTurbo();
    }
  }
  window.__slOnSchemeChange = applyTheme; // 每次执行刷新 trampoline 到当前闭包

  window.slPrefs = {
    get: function () { return JSON.parse(JSON.stringify(PREFS)); },
    set: function (patch) {
      for (var k in patch) {
        if (Object.prototype.hasOwnProperty.call(patch, k)) PREFS[k] = patch[k];
      }
      savePrefs(PREFS);
      applyTheme();
      applyAccent();
      applyFontScale();
    },
    reset: function () {
      PREFS = { theme: "light", accent: "", fontScale: "md", lang: "zh-CN" };
      savePrefs(PREFS);
      applyTheme();
      applyAccent();
      applyFontScale();
    }
  };

  /* ---------------- 左侧栏 HTML ---------------- */
  var ICONS = {
    scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/></svg>',
    audit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="m10 13-2 2 2 2"/><path d="m14 11 2 2-2 2"/></svg>',
    batch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 8 5-8 5-8-5z"/><path d="m4 12 8 5 8-5"/><path d="m4 17 8 5 8-5"/></svg>',
    history: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
    intel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
    chain: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="12" r="2.5"/><circle cx="5" cy="18" r="2.5"/><path d="M7.3 7.2 16.7 11M7.3 16.8 16.7 13"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0 .33-1.82l.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>'
  };
  // 顶栏导航（视觉升级 2026-09-16）：只放**被动/管理页**；主动功能
  // （综合扫描/网络层检测/登录爆破/源码审计/批量扫描）是工作台左栏的模式行，
  // 不占顶栏。品牌 logo 点击即回工作台。
  var NAV = [
    ["settings", "/settings", "设置", "nav_settings"],
    ["intel", "/intel", "情报库", "nav_intel"],
    ["history", "/history", "历史", "nav_history"],
    ["chain", "/chain", "攻击链", "nav_chain"]
  ];
  function navKey() {
    var p = location.pathname;
    // 已验证 是历史页内页签 → 侧栏高亮所属页面「历史」
    if (p.indexOf("/history") === 0) return "history";
    if (p.indexOf("/chain") === 0) return "chain";
    if (p.indexOf("/intel") === 0) return "intel";
    if (p.indexOf("/settings") === 0) return "settings";
    return ""; // 工作台及其模式页：顶栏不高亮（左栏模式行自行高亮）
  }
  function slUpdateNav() {
    var key = navKey();
    document.querySelectorAll(".top-nav a").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-key") === key);
    });
  }
  window.slUpdateNav = slUpdateNav;

  /* ---------------- 公共函数 ---------------- */
  window.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"'`]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" }[c];
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
  function request(method, u, d) {
    return fetch(u, {
      method: method,
      headers: Object.assign({ "Content-Type": "application/json" }, tok()),
      body: d === undefined ? undefined : JSON.stringify(d)
    }).then(asJson);
  }
  window.api = {
    get: function (u) { return fetch(u, { headers: tok() }).then(asJson); },
    post: function (u, d) { return request("POST", u, d || {}); },
    put: function (u, d) { return request("PUT", u, d || {}); },
    del: function (u, d) { return request("DELETE", u, d); }
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
  /* A9：可见性感知轮询——窗口隐藏/最小化时间隔 ×4（Electron 后台节流之外
     再省 CPU/网络）；恢复可见立即回到正常间隔。fn 同 setInterval 语义。
     Turbo：句柄自动登记进清理注册表，换页前停止并解除 visibilitychange。 */
  window.slPoll = function (fn, ms) {
    var timer = null;
    var tick = function () { if (!document.hidden) fn(); };
    var onVis = function () {
      clearInterval(timer);
      timer = setInterval(tick, document.hidden ? ms * 4 : ms);
    };
    timer = setInterval(tick, ms);
    document.addEventListener("visibilitychange", onVis);
    var handle = {
      stop: function () {
        clearInterval(timer);
        document.removeEventListener("visibilitychange", onVis);
      }
    };
    if (window.slOnCleanup) window.slOnCleanup(handle.stop);
    return handle;
  };

  /* 自绘下拉组件（cdd）：app.html 与 chain.html 复用 */
  window.initCDD = function (rootId, onPick) {
    var root = document.getElementById(rootId);
    var pop = root.querySelector(".cdd-pop");
    root.querySelector(".cdd-btn").addEventListener("click", function (e) {
      e.stopPropagation();
      var willOpen = !root.classList.contains("open");
      document.querySelectorAll(".cdd.open").forEach(function (r) { r.classList.remove("open"); });
      if (willOpen) root.classList.add("open");
    });
    pop.addEventListener("click", function (e) { e.stopPropagation(); });
    pop.querySelectorAll(".cdd-opt").forEach(function (opt) {
      opt.addEventListener("click", function () {
        pop.querySelectorAll(".cdd-opt").forEach(function (o) { o.classList.remove("active"); });
        opt.classList.add("active");
        root.setAttribute("data-value", opt.getAttribute("data-v"));
        root.querySelector(".cdd-label").innerHTML =
          "<b>" + esc(opt.querySelector("b").textContent) + "</b>" +
          '<span class="cdd-desc">' + esc(opt.querySelector("span").textContent) + "</span>";
        root.classList.remove("open");
        if (onPick) onPick(opt.getAttribute("data-v"));
      });
    });
    return { get value() { return root.getAttribute("data-value"); } };
  };

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

  /* ================= 每渲染区：壳重建 =================
     工作台（.tw-app）：不设独立顶栏——被动页导航/亮暗/版本渲染进画布工具条的
     .tw-topslot 槽位，与左栏模式行同高，构成参照物式的「一条顶带」。
     其余页面：独立 .wb-top 顶栏。 */
  /* 主动功能侧栏（全页面常驻）：工作台=模式切换，被动页=返航入口 */
  var MODE_SIDE = [
    ["scan", "/app#scan", "综合扫描", '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/></svg>'],
    ["netsec", "/app#netsec", "网络层检测", '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'],
    ["loginbrute", "/app#loginbrute", "登录爆破", '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>'],
    ["audit", "/app#audit", "源码审计", '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="m10 13-2 2 2 2"/><path d="m14 11 2 2-2 2"/></svg>'],
    ["batch", "/app#batch", "批量扫描", '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 8 5-8 5-8-5z"/><path d="m4 12 8 5 8-5"/><path d="m4 17 8 5 8-5"/></svg>'],
  ];
  function sideActive() {
    var p = location.pathname, h = (location.hash || "").slice(1);
    if (p.indexOf("/audit") === 0) return "audit";
    if (p.indexOf("/batch") === 0) return "batch";
    if (p !== "/app" && p.indexOf("/app") !== 0) return "";
    return ["scan", "netsec", "loginbrute", "audit", "batch"].indexOf(h) >= 0 ? h : "scan";
  }
  function updateSideActive() {
    var key = sideActive();
    document.querySelectorAll(".wb-side .side-nav a").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-key") === key);
    });
  }
  window.slUpdateSide = updateSideActive;

  function topNavHTML() {
    var nav = NAV.map(function (n) {
      var label = t(n[3]) || n[2];
      return '<a href="' + n[1] + '" data-key="' + n[0] + '" title="' + label + '">' +
        ICONS[n[0]] + "<span>" + label + "</span></a>";
    }).join("");
    return '<nav class="top-nav">' + nav + "</nav>";
  }
  function topRightHTML() {
    return '<div class="top-right">' +
      '<button class="theme-btn" onclick="toggleTheme()" title="' + (t("theme_toggle") || "切换明暗主题") + '">◐</button>' +
      '<span class="ver" id="sl-ver">SiteLens</span></div>';
  }
  function fillVersion() {
    api.get("/api/version").then(function (v) {
      var el = document.getElementById("sl-ver");
      if (el && v && v.version) el.textContent = "v" + v.version;
    }).catch(function () {});
  }
  function buildShell() {
    var workbench = document.querySelector(".tw-app");
    var stale = document.querySelector(".wb-top");
    if (workbench) {
      // 工作台：导航渲染进工具条槽位（单顶带），独立顶栏不留
      if (stale && stale.parentNode) stale.parentNode.removeChild(stale);
      var staleSide = workbench.querySelector(":scope > .wb-side");
      if (staleSide && staleSide.parentNode) staleSide.parentNode.removeChild(staleSide);
      var side = document.createElement("aside");
      side.className = "wb-side";
      side.innerHTML =
        '<div class="side-head"><a class="brand" href="/app" title="工作台"><span class="txt">sitelens</span><span class="dot"></span></a></div>' +
        '<nav class="side-nav">' + MODE_SIDE.map(function (m) {
          return '<a href="' + m[1] + '" data-key="' + m[0] + '" title="' + m[2] + '">' + m[3] + "<span>" + m[2] + "</span></a>";
        }).join("") + "</nav>";
      workbench.insertBefore(side, workbench.firstChild);
      updateSideActive();
      var slot = document.getElementById("tw-topslot");
      if (slot) {
        slot.innerHTML = topNavHTML() + topRightHTML();
        slUpdateNav();
        fillVersion();
      }
      return;
    }
    if (stale && stale.parentNode) stale.parentNode.removeChild(stale);
    var header = document.createElement("header");
    header.className = "wb-top";
    header.innerHTML =
      '<a class="brand" href="/"><span class="txt">sitelens</span><span class="dot"></span></a>' +
      topNavHTML() +
      topRightHTML();
    document.body.insertBefore(header, document.body.firstChild);
    slUpdateNav();
    /* 顶栏显示服务端版本号（失败保持 SiteLens 文案） */
    fillVersion();
  }
  /* 首次执行位于 body 起始：.tw-app / 槽位尚未解析，等 DOM 就绪再定壳形态；
     Turbo 换页时脚本体在换页后重放，readyState 已过 loading，立即执行 */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", buildShell);
  } else {
    buildShell();
  }

  /* ---------------- 主题 ---------------- */
  // 侧栏快捷按钮：在浅/深之间显式切换（auto 模式下点按即固定）
  window.toggleTheme = function () {
    var dark = document.documentElement.classList.contains("dark");
    window.slPrefs.set({ theme: dark ? "light" : "dark" });
  };
})();
