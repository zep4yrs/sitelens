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

  /* 全局共享状态（弹层栈 / 一次性监听标记 / IME 组合态）。
     FE-04 起多处引用 SL.xxx；必须在此定义，否则后续 api/initCDD 等
     定义全部不会执行（外壳不渲染、导航消失）。 */
  var SL = window.SL = window.SL || { dialogs: [], globalReady: false, imeComposing: false };

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
      try { p.theme = localStorage.getItem("sitelens-theme") || "auto"; } catch (e) { p.theme = "auto"; }
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

  /* ---------------- i18n：zh-CN 为缺省 ----------------
     字典与 t()/apply() 的单一来源是 web/js/i18n.js（UMD，含 zh-CN 字典与
     data-i18n 扫描替换）；本文件按需加载它并暴露 window.slI18n。这里只留
     最小回退字典，保证字典脚本未就绪时导航文案不闪空。window.slI18N 为旧名兼容。 */
  var I18N_FALLBACK = {
    "en-US": {
      nav_scan: "Scan", nav_netsec: "Net Scan", nav_audit: "Code Audit",
      nav_brute: "Login Brute", nav_batch: "Batch", nav_history: "History",
      nav_intel: "Intel", nav_verified: "Verified", nav_settings: "Settings",
      theme_toggle: "Toggle light/dark theme"
    }
  };
  function t(key) {
    if (window.slI18n && typeof window.slI18n.t === "function") {
      var v = window.slI18n.t(key);
      if (v) return v;
    }
    if (PREFS.lang && I18N_FALLBACK[PREFS.lang] && I18N_FALLBACK[PREFS.lang][key]) {
      return I18N_FALLBACK[PREFS.lang][key];
    }
    return null;
  }
  window.slT = t;
  window.slI18N = window.slI18N || I18N_FALLBACK;

  /* 按需加载 i18n 字典（所有页面共用；加载成功后重渲染外壳以应用语言） */
  function loadI18n() {
    // a11y：语言偏好先落到 <html lang>，不等字典脚本（屏幕阅读器按 lang 选发音规则）
    try {
      if (document.documentElement && /^(zh-CN|en-US)$/.test(PREFS.lang || "")) {
        document.documentElement.setAttribute("lang", PREFS.lang);
      }
    } catch (e) {}
    if (window.slI18n) {
      try { window.slI18n.setLang(PREFS.lang); window.slI18n.apply(document); } catch (e) {}
      return;
    }
    var s = document.createElement("script");
    s.src = "/js/i18n.js";
    s.async = false;
    s.onload = function () {
      try {
        if (window.slI18n) {
          window.slI18n.setLang(PREFS.lang);
          window.slI18N = window.slI18n; // 旧名兼容
          window.slI18n.apply(document);
          buildShell(); // 导航/模式行由 t() 生成，重渲染一次拿新语言
        }
      } catch (e) {}
      try { document.dispatchEvent(new CustomEvent("sl:i18n-ready")); } catch (e) {}
    };
    s.onerror = function () { /* 字典缺失不影响功能，保持中文回退 */ };
    document.head.appendChild(s);
  }

  /* ---------------- 偏好应用：主题（light/dark/auto）+ 主题色 + 字号 ---------------- */
  function applyTheme() {
    var dark = PREFS.theme === "dark" ||
      (PREFS.theme === "auto" &&
        window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
    // 明暗切换按钮的按下态（屏幕阅读器可感知当前主题）
    var themeBtn = document.querySelector(".theme-btn");
    if (themeBtn) themeBtn.setAttribute("aria-pressed", dark ? "true" : "false");
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
    // i18n 字典（web/js/i18n.js）按需加载；无障碍全局快捷键/弹层接线只注册一次
    loadI18n();
    slInitGlobalA11y();

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
      if (window.slUpdateModes) window.slUpdateModes();
      // FE-09：hash 直达/前进后退到审计模式时触发 Monaco 懒加载
      if (window.slAuditActivate && (location.hash || "").slice(1) === "audit") {
        window.slAuditActivate();
      }
    });
    // 模式行点击分派：工作台=即时 switchTab；被动页=Turbo 去对应模式。
    // 注意不能以「switchTab 函数存在」判定在工作台——Turbo 切页后 window 上的
    // 旧函数仍残留，会被误判导致只改 hash 不导航；以路径+面板存在为准。
    document.addEventListener("click", function (e) {
      var b = e.target && e.target.closest ? e.target.closest(".tw-modes .tab") : null;
      if (!b) return;
      var name = b.getAttribute("data-tab");
      e.preventDefault();
      var onWorkbench = location.pathname === "/app" &&
        document.querySelector(".tw-panel") && typeof window.switchTab === "function";
      if (onWorkbench) {
        window.switchTab(name);
        if (window.slUpdateModes) window.slUpdateModes();
        // FE-09：首次进入审计模式才加载 Monaco（懒加载瘦身；其它页无此函数）
        if (name === "audit" && window.slAuditActivate) window.slAuditActivate();
      } else if (window.Turbo) {
        window.Turbo.visit("/app#" + name);
      }
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
        if (window.slUpdateModes) window.slUpdateModes();
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
      // 语言变更即时应用（设置页通常 reload，这里兜住不重载的调用方）
      if (window.slI18n && patch && Object.prototype.hasOwnProperty.call(patch, "lang")) {
        try { window.slI18n.setLang(PREFS.lang); window.slI18n.apply(document); } catch (e) {}
      }
    },
    reset: function () {
      PREFS = { theme: "auto", accent: "", fontScale: "md", lang: "zh-CN" };
      savePrefs(PREFS);
      applyTheme();
      applyAccent();
      applyFontScale();
      if (window.slI18n) {
        try { window.slI18n.setLang(PREFS.lang); window.slI18n.apply(document); } catch (e) {}
      }
    }
  };

  /* ================= 无障碍增强（FE-04，5.2.x） =================
     1) 全局快捷键：Ctrl+Enter 开始扫描 / Esc 取消扫描或关弹层 / Ctrl+E 导出 JSON；
        CJK 输入法组合输入期间一律不触发（compositionstart/end + isComposing 守卫）。
     2) 弹层管理器：role=dialog + aria-modal + 焦点陷阱（Tab 循环）+ Esc 关闭 +
        焦点归还；约定用 data-sl-dialog-open / data-sl-dialog-close 接线，避免改 app.js。
     3) 每渲染增强：跳过导航链接、main 地标、窄屏侧栏抽屉开关、页签 aria-selected、
        进度条 aria-valuenow 同步、分割条键盘调整、非原生 role=button 控件可聚焦。
     状态挂 window.__slA11y：common.js 随 Turbo 换页重放，文档级监听只注册一次，
     但 DOM 引用必须跨渲染存活/清理。 */
  var SL = window.__slA11y || (window.__slA11y = { dialogs: [], imeComposing: false });

  function slFocusables(root) {
    var sel = 'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),' +
      'select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
    return Array.prototype.slice.call(root.querySelectorAll(sel)).filter(function (el) {
      return !el.hasAttribute("hidden") && el.getClientRects().length > 0;
    });
  }

  function slEnhanceDialog(el) {
    if (!el) return null;
    if (el.__slDialogReady) return el;
    el.__slDialogReady = true;
    if (!el.hasAttribute("role")) el.setAttribute("role", "dialog");
    if (!el.hasAttribute("aria-modal")) el.setAttribute("aria-modal", "true");
    if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
    // 点遮罩关闭（只在点到 backdrop 自身时；点内容不关）
    el.addEventListener("mousedown", function (e) {
      if (e.target === el) slCloseDialog(el);
    });
    // 焦点陷阱：Tab/Shift+Tab 在弹层内循环
    el.addEventListener("keydown", function (e) {
      if (e.key !== "Tab") return;
      var f = slFocusables(el);
      if (!f.length) { e.preventDefault(); el.focus(); return; }
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === el)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });
    return el;
  }

  function slOpenDialog(el, opener) {
    if (!el) return false;
    slEnhanceDialog(el);
    if (SL.dialogs.indexOf(el) >= 0) return true;
    SL.dialogs.push(el);
    el.__slPrevFocus = opener || document.activeElement;
    el.hidden = false;
    el.classList.add("open");
    document.documentElement.classList.add("sl-modal-open");
    var f = slFocusables(el);
    (f[0] || el).focus();
    return true;
  }

  function slCloseDialog(el) {
    if (!el) return false;
    var i = SL.dialogs.indexOf(el);
    if (i < 0) return false;
    SL.dialogs.splice(i, 1);
    el.hidden = true;
    el.classList.remove("open");
    if (!SL.dialogs.length) document.documentElement.classList.remove("sl-modal-open");
    var prev = el.__slPrevFocus;
    el.__slPrevFocus = null;
    if (prev && typeof prev.focus === "function") { try { prev.focus(); } catch (e) {} }
    return true;
  }

  function slTopDialog() {
    return SL.dialogs.length ? SL.dialogs[SL.dialogs.length - 1] : null;
  }

  window.slDialog = {
    open: slOpenDialog,
    close: slCloseDialog,
    enhance: slEnhanceDialog,
    top: slTopDialog,
    isOpen: function () { return SL.dialogs.length > 0; }
  };

  /* Esc 关闭顺序：弹层 → 自绘下拉 → 窄屏侧栏抽屉（都没有才轮到取消扫描）。 */
  function slCloseOverlays() {
    var dlg = slTopDialog();
    if (dlg) { slCloseDialog(dlg); return true; }
    var openCdd = document.querySelector(".cdd.open");
    if (openCdd) {
      openCdd.classList.remove("open");
      var cbtn = openCdd.querySelector(".cdd-btn");
      if (cbtn) { cbtn.setAttribute("aria-expanded", "false"); cbtn.focus(); }
      return true;
    }
    var app = document.querySelector(".tw-app.side-open");
    if (app) {
      app.classList.remove("side-open");
      var tgl = document.querySelector(".sl-side-toggle");
      if (tgl) { tgl.setAttribute("aria-expanded", "false"); tgl.focus(); }
      return true;
    }
    return false;
  }

  /* 文档级监听（只注册一次）：快捷键 + 弹层接线 + 非原生控件键盘激活。 */
  function slInitGlobalA11y() {
    if (SL.globalReady) return;
    SL.globalReady = true;

    // CJK IME 守卫：组合输入期间快捷键不解释（中文/日文/韩文输入法）
    document.addEventListener("compositionstart", function () { SL.imeComposing = true; }, true);
    document.addEventListener("compositionend", function () { SL.imeComposing = false; }, true);

    document.addEventListener("keydown", function (e) {
      if (SL.imeComposing || e.isComposing || e.keyCode === 229) return;
      var key = String(e.key || "").toLowerCase();

      if (key === "escape") {
        if (slCloseOverlays()) { e.preventDefault(); return; }
        // 取消进行中的扫描：#cancel-btn 只在扫描期渲染（app.js renderLivePanel）
        if (document.getElementById("cancel-btn") && typeof window.cancelScan === "function") {
          e.preventDefault();
          window.cancelScan();
        }
        return;
      }

      if (!(e.ctrlKey || e.metaKey)) return;
      if (slTopDialog()) return; // 弹层内不触发全局快捷键

      if (key === "enter") {
        if (typeof window.startScan !== "function" || !document.getElementById("url")) return;
        var go = document.getElementById("go");
        if (go && go.disabled) return; // 扫描进行中不重复提交
        e.preventDefault();
        window.startScan();
        return;
      }
      if (key === "e") {
        if (typeof window.exportAs !== "function") return;
        // 无结果时 exportAs 是静默 no-op；不劫持浏览器默认快捷键
        if (!document.querySelector('#result [onclick*="exportAs"]')) return;
        e.preventDefault();
        window.exportAs("json");
      }
    }, false);

    // 弹层开/关接线（data-* 约定；不改 app.js）
    document.addEventListener("click", function (e) {
      var t2 = e.target;
      if (!t2 || !t2.closest) return;
      var opener = t2.closest("[data-sl-dialog-open]");
      if (opener) {
        var id = opener.getAttribute("data-sl-dialog-open");
        var dlg = id ? document.getElementById(id) : null;
        if (dlg) { e.preventDefault(); slOpenDialog(dlg, opener); }
        return;
      }
      var closer = t2.closest("[data-sl-dialog-close]");
      if (closer) {
        var host = closer.closest('[role="dialog"]');
        if (host) { e.preventDefault(); slCloseDialog(host); }
      }
    }, false);

    // 非原生可聚焦控件（role=button 的 div 等）用 Enter/Space 激活
    document.addEventListener("keydown", function (e) {
      if (SL.imeComposing || e.isComposing || e.keyCode === 229) return;
      var key = String(e.key || "");
      if (key !== "Enter" && key !== " " && key !== "Spacebar") return;
      var el = e.target && e.target.closest ? e.target.closest("[data-sl-activate]") : null;
      if (!el) return;
      e.preventDefault();
      el.click();
    }, false);
  }

  /* 进度条 aria-valuenow 同步：app.js 只改 <i style="width">，这里观察属性变化补 ARIA。 */
  function slWatchProgress(el) {
    if (!el || el.__slProgress) return;
    el.__slProgress = true;
    if (!el.hasAttribute("role")) el.setAttribute("role", "progressbar");
    el.setAttribute("aria-valuemin", "0");
    el.setAttribute("aria-valuemax", "100");
    if (!el.hasAttribute("aria-label")) el.setAttribute("aria-label", t("a11y_progress") || "进度");
    var bar = el.querySelector("i");
    function sync() {
      var w = bar ? parseFloat(bar.style.width || "0") : 0;
      if (!isFinite(w)) w = 0;
      el.setAttribute("aria-valuenow", String(Math.max(0, Math.min(100, Math.round(w)))));
    }
    sync();
    if (bar && window.MutationObserver) {
      new MutationObserver(sync).observe(bar, { attributes: true, attributeFilter: ["style"] });
    }
  }

  /* 分割条键盘调整（鼠标拖拽由 app.js 处理；这里补键盘可达，写同一个偏好键）。 */
  function slInitSplit() {
    var split = document.getElementById("tw-split");
    var left = document.getElementById("tw-left");
    if (!split || !left || split.__slKeys) return;
    split.__slKeys = true;
    if (!split.hasAttribute("role")) split.setAttribute("role", "separator");
    split.setAttribute("aria-orientation", "vertical");
    split.setAttribute("tabindex", "0");
    if (!split.hasAttribute("aria-label")) split.setAttribute("aria-label", t("a11y_resize") || "调整左栏宽度");
    split.setAttribute("aria-valuemin", "240");
    split.setAttribute("aria-valuemax", "520");
    function sync() {
      var w = Math.round(left.getBoundingClientRect().width);
      if (w > 0) split.setAttribute("aria-valuenow", String(w));
    }
    sync();
    split.addEventListener("keydown", function (e) {
      var d = e.key === "ArrowLeft" ? -16 : e.key === "ArrowRight" ? 16 : 0;
      if (!d) return;
      e.preventDefault();
      var w = Math.max(240, Math.min(520, Math.round(left.getBoundingClientRect().width) + d));
      left.style.width = w + "px";
      try { localStorage.setItem("tw-left-w", String(w)); } catch (err) {}
      sync();
    });
    window.addEventListener("resize", sync);
  }

  /* 模式行 aria-selected / aria-current 同步（app.js switchTab 只切 class）。 */
  function slUpdateModes() {
    var active = sideActive();
    document.querySelectorAll(".tw-modes .tab").forEach(function (b) {
      var on = b.getAttribute("data-tab") === active;
      b.setAttribute("aria-selected", on ? "true" : "false");
      if (on) b.setAttribute("aria-current", "true"); else b.removeAttribute("aria-current");
    });
  }
  window.slUpdateModes = slUpdateModes;

  /* 每渲染增强：跨页/跨 Turbo 换页都执行，必须幂等。 */
  function slInitShellA11y() {
    // 换页后清掉已不在文档里的弹层引用（避免 Esc 关闭幽灵弹层）
    SL.dialogs = SL.dialogs.filter(function (el) { return el && document.contains(el); });
    if (!SL.dialogs.length) document.documentElement.classList.remove("sl-modal-open");

    var app = document.querySelector(".tw-app");
    if (!app) return;

    // 1) 跳过导航链接 + main 地标（工作台没有 <main>，画布即主内容）
    var main = document.querySelector("main");
    if (!main) {
      var canvas = document.querySelector(".tw-canvas");
      if (canvas) { canvas.setAttribute("role", "main"); main = canvas; }
    }
    if (main) {
      if (!main.id) main.id = "sl-main";
      if (!main.hasAttribute("tabindex")) main.setAttribute("tabindex", "-1");
      if (!document.querySelector(".sl-skip")) {
        var skip = document.createElement("a");
        skip.className = "sl-skip";
        skip.href = "#" + main.id;
        skip.setAttribute("data-i18n", "skip_to_main");
        skip.textContent = t("skip_to_main") || "跳到主要内容";
        document.body.insertBefore(skip, document.body.firstChild);
      }
    }

    // 2) 左栏语义 + 窄屏抽屉开关
    var left = app.querySelector(".tw-left");
    if (left) {
      if (!left.id) left.id = "tw-left";
      if (!left.hasAttribute("aria-label")) {
        left.setAttribute("aria-label", t("a11y_side_panel") || "扫描配置面板");
      }
    }
    var toolbar = app.querySelector(".tw-toolbar");
    if (toolbar && left && !toolbar.querySelector(".sl-side-toggle")) {
      var toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "btn ghost small sl-side-toggle";
      toggle.setAttribute("aria-controls", left.id);
      toggle.setAttribute("aria-expanded", app.classList.contains("side-open") ? "true" : "false");
      toggle.setAttribute("data-i18n", "side_toggle");
      toggle.textContent = t("side_toggle") || "配置";
      toggle.addEventListener("click", function () {
        var open = app.classList.toggle("side-open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      toolbar.insertBefore(toggle, toolbar.firstChild);
    }

    // 3) 页签语义：模式行 aria-selected + 面板 role=tabpanel/aria-labelledby
    slUpdateModes();
    document.querySelectorAll(".tabpanel").forEach(function (p) {
      if (!p.hasAttribute("role")) p.setAttribute("role", "tabpanel");
      if (p.hasAttribute("aria-labelledby")) return;
      var name = (p.id || "").replace(/^tab-/, "");
      var tabBtn = document.querySelector('.tw-modes .tab[data-tab="' + name + '"]') ||
        document.querySelector('.tabs .tab[data-tab="' + name + '"]');
      if (tabBtn) {
        if (!tabBtn.id) tabBtn.id = "tab-btn-" + name;
        p.setAttribute("aria-labelledby", tabBtn.id);
        tabBtn.setAttribute("aria-controls", p.id);
      }
    });
    // 被动页的普通 .tabs（如历史页）补最小 tablist/tab 语义
    document.querySelectorAll(".tabs").forEach(function (list) {
      if (list.classList.contains("tw-modes")) return;
      if (!list.hasAttribute("role") && list.querySelector(".tab")) list.setAttribute("role", "tablist");
      list.querySelectorAll(".tab").forEach(function (b) {
        if (!b.hasAttribute("role")) b.setAttribute("role", "tab");
      });
    });

    // 4) 状态行 / 进度条 / 分割条
    ["st-msg", "st-state"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el && !el.hasAttribute("aria-live")) el.setAttribute("aria-live", "polite");
    });
    ["pw", "lb-pw", "batch-pw"].forEach(function (id) { slWatchProgress(document.getElementById(id)); });
    slInitSplit();

    // 5) role=button 的非原生控件补 tabindex（如拖拽上传区）
    document.querySelectorAll('[role="button"]').forEach(function (el) {
      if (!el.hasAttribute("tabindex") && !/^(BUTTON|A)$/.test(el.tagName)) el.setAttribute("tabindex", "0");
    });

    // 5.1) 表单控件兜底标签：范围外页面（settings/history/intel/feedback）的静态
    //      标签待 5.3 补齐，这里先用 placeholder / 相邻 label 文本补 aria-label，
    //      避免屏幕阅读器把无标签输入框读成空白。已有标签（label/aria-label/title）
    //      的控件绝不覆盖。
    document.querySelectorAll("input,textarea,select").forEach(function (el) {
      var type = (el.getAttribute("type") || "").toLowerCase();
      if (type === "hidden" || type === "submit" || type === "button" || type === "reset" || type === "image") return;
      if (el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") || el.getAttribute("title")) return;
      if (el.labels && el.labels.length) return;
      var ph = (el.getAttribute("placeholder") || "").trim();
      if (ph) { el.setAttribute("aria-label", ph); return; }
      var row = el.closest ? el.closest(".row") : null;
      var lab = row ? row.querySelector("label") : null;
      var txt = lab ? (lab.textContent || "").trim() : "";
      if (txt) el.setAttribute("aria-label", txt);
    });

    // 6) 静态弹层增强 + i18n 应用（幂等）
    document.querySelectorAll('[role="dialog"][aria-modal="true"]').forEach(function (el) { slEnhanceDialog(el); });
    if (window.slI18n) {
      try { window.slI18n.setLang(PREFS.lang); window.slI18n.apply(document); } catch (e) {}
    }
  }
  window.slInitShellA11y = slInitShellA11y;

  /* ---------------- 左侧栏 HTML ---------------- */
  var ICONS = {
    scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/></svg>',
    audit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="m10 13-2 2 2 2"/><path d="m14 11 2 2-2 2"/></svg>',
    batch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 8 5-8 5-8-5z"/><path d="m4 12 8 5 8-5"/><path d="m4 17 8 5 8-5"/></svg>',
    history: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
    intel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
    chain: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="12" r="2.5"/><circle cx="5" cy="18" r="2.5"/><path d="M7.3 7.2 16.7 11M7.3 16.8 16.7 13"/></svg>',
    feedback: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0 .33-1.82l.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>'
  };
  // 顶栏导航（视觉升级 2026-09-16）：只放**被动/管理页**；主动功能
  // （综合扫描/网络层检测/登录爆破/源码审计/批量扫描）是工作台左栏的模式行，
  // 不占顶栏。品牌 logo 点击即回工作台。
  var NAV = [
    ["settings", "/settings", "设置", "nav_settings"],
    ["feedback", "/feedback", "反馈", "nav_feedback"],
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
    if (p.indexOf("/feedback") === 0) return "feedback";
    return ""; // 工作台及其模式页：顶栏不高亮（左栏模式行自行高亮）
  }
  function slUpdateNav() {
    var key = navKey();
    document.querySelectorAll(".top-nav a").forEach(function (a) {
      var on = a.getAttribute("data-key") === key;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
  }
  window.slUpdateNav = slUpdateNav;

  /* ---------------- 公共函数 ---------------- */
  window.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"'`]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" }[c];
    });
  };
  /* JS 字符串上下文转义（D-15）：往内联事件处理器里传数据时必须用它。
     esc() 只保证 HTML 属性不被闭合——浏览器会**先做实体解码再把属性值交给
     JS 解析**，所以 onclick="f(' + esc(v) + ')" 里形如 x&#39;);alert(1)// 的
     值解码后仍是 x');alert(1)//，直接逃逸出 JS 字符串（D-03 的真实成因）。
     本函数产出「HTML 转义后的 JSON 字符串字面量」：解码后是合法 JS 字符串，
     任何引号/反斜杠/换行都已在 JSON 层转义，无法闭合字符串。
     用法：'onclick="f(' + escJs(v) + ')"'  → f("v")。 */
  window.escJs = function (s) {
    return window.esc(JSON.stringify(String(s == null ? "" : s)));
  };

  function tok() {
    var t = "";
    try { t = localStorage.getItem("sitelens-token") || ""; } catch (e) {}
    return t ? { "X-Token": t } : {};
  }
  /* ---------------- API Token 的本机存储（D-04） ----------------
     读侧是上面的 tok()（每次请求现读 localStorage）；写侧此前**全仓不存在**，
     于是设置页保存 api_token 后引擎立刻要求 X-Token，而前端手里没有 token →
     每个 /api/* 都 401，连设置页自身都打不开（只能手改 config.yml 才能恢复）。
     现在唯一写入口就是这里，设置页保存成功后调用。 */
  window.slStoreToken = function (t) {
    var v = String(t == null ? "" : t).trim();
    try {
      if (v) localStorage.setItem("sitelens-token", v);
      else localStorage.removeItem("sitelens-token");
    } catch (e) { /* 隐私模式/配额异常：静默降级（请求会 401，页面有提示） */ }
    return v;
  };
  window.slReadToken = function () {
    try { return localStorage.getItem("sitelens-token") || ""; } catch (e) { return ""; }
  };
  /* ---------------- 统一请求头（CSRF 自定义头 + 可选 X-Token） ----------------
     F5 的 internal/server/origin_guard.go 对危险端点（PUT /api/settings、
     POST /api/history/clear、/api/batch/schedules*、/api/admin/*）要求
     "显式来源证据"：自定义头或 JSON Content-Type 二选一；requireCSRFHeaderStrict
     打开后必须带 X-Requested-With: sitelens。
     跨站 JS 无法在不触发 CORS 预检的前提下携带自定义头（表单更不可能），
     所以这是 CSRF 防护的最后一块。所有请求都从这里取头：
       - api.get/post/put/del（本文件 request/api）
       - slDownload（下载/导出）
       - 裸 fetch（audit.js 的 FormData 上传、chain.html 的图查询）用 apiTok() */
  var CSRF_HEADER_NAME = "X-Requested-With";
  var CSRF_HEADER_VALUE = "sitelens";
  window.slHeaders = function (extra) {
    var h = {};
    h[CSRF_HEADER_NAME] = CSRF_HEADER_VALUE;
    var t = tok();
    for (var k in t) { if (Object.prototype.hasOwnProperty.call(t, k)) h[k] = t[k]; }
    if (extra) {
      for (var e in extra) { if (Object.prototype.hasOwnProperty.call(extra, e)) h[e] = extra[e]; }
    }
    return h;
  };
  /* ---------------- URL fragment token 引导（A-01/D-02） ----------------
     桌面壳把引擎的 web.api_token 经 URL fragment 交给前端（fragment 不发给
     服务端、不进访问日志）。这里识别 → 写入本机存储 → **立刻从地址栏抹掉**，
     避免 token 留在可截图/可复制的 URL 里；非法格式（长度/字符集不符）同样
     抹掉但不写入。纯函数 + 依赖注入，便于 node 单测（token.test.mjs）。
     必须在任何 API 请求之前执行——本文件在页面所有业务脚本之前加载。 */
  function bootstrapTokenFromFragment(loc, store, replace) {
    loc = loc || {};
    var hash = String(loc.hash || "");
    if (hash.charAt(0) !== "#") return false;
    var raw = hash.slice(1);
    // 只接管壳注入的 fragment（token=/si= 开头）；页面自身 hash 路由（如 #about）不碰。
    if (raw.indexOf("token=") !== 0 && raw.indexOf("si=") !== 0) return false;
    var clean = String(loc.pathname || "/") + String(loc.search || "");
    if (replace) replace(clean); // 壳注入的 fragment 一律抹掉（含非法内容，避免留在地址栏）
    var tok = "", si = "";
    var segs = raw.split("&");
    for (var i = 0; i < segs.length; i++) {
      var eq = segs[i].indexOf("=");
      if (eq < 0) continue;
      var k = segs[i].slice(0, eq), v = segs[i].slice(eq + 1);
      if (k === "token") tok = v;
      else if (k === "si") si = v;
    }
    // si= 是壳静态信息（GetInfo 的一次性注入，见 bridge.js）：原样交给 bridge.js 解码。
    // 同时持久化到 localStorage——壳只在首屏 URL 里带 fragment，/settings 等页面是
    // 新文档、fragment 不会跟过去，bridge.js 每页从 storage 读回。
    if (si) {
      try { window.__slShellInfoB64 = si; } catch (e) {}
      try { localStorage.setItem("sl_shell_si", si); } catch (e) {}
    }
    if (/^[0-9a-fA-F]{64}$/.test(tok)) {
      if (store) store(tok.toLowerCase());
      return true;
    }
    return false; // 非法 token：只清理 fragment，不写 token
  }
  window.slBootstrapToken = bootstrapTokenFromFragment;
  try {
    bootstrapTokenFromFragment(location, window.slStoreToken, function (u) {
      try { history.replaceState(null, "", u); } catch (e) {}
    });
  } catch (e) { /* 极旧环境无 history：忽略（token 仍已写入） */ }
  /* ---------------- API 与错误分级（BUG-034）----------------
     三类失败必须可区分，且必须带上下文：
       1) 网络失败（引擎未启动 / 已退出 / 端口不通）→ 浏览器原生 "Failed to fetch"
       2) HTTP 错误（非 2xx）→ 服务端的 {error: "..."}
       3) 响应非 JSON（网关/代理替换了响应）→ "Unexpected token '<'"
     此前三者都只抛一句没有上下文的英文，界面还常被 .catch(function(){}) 静默
     吞掉——用户只看到"Failed to fetch"一行红字，界面毫无反应。 */
  function apiError(url, kind, detail) {
    var head = {
      network: "无法连接引擎服务（引擎可能未启动、已退出，或端口被占用）",
      http: "引擎返回错误",
      parse: "引擎响应格式异常（可能被网关/代理替换）"
    }[kind] || "请求失败";
    return new Error(head + " @ " + url + (detail ? "：" + detail : ""));
  }
  function asJson(r, url) {
    return r.text().then(function (txt) {
      var j = null;
      try { j = JSON.parse(txt); } catch (e) { j = null; }
      if (!r.ok) {
        throw apiError(url, "http", (j && j.error) || ("HTTP " + r.status));
      }
      if (j === null) {
        throw apiError(url, "parse", txt.slice(0, 120));
      }
      clearEngineDown(); // 引擎恢复可达 → 撤掉"无响应"界面态
      return j;
    }, function () {
      // fetch 本身失败：连接被拒 / 引擎未监听 / 页面跨源被拦
      throw apiError(url, "network", "");
    });
  }
  function request(method, u, d) {
    return fetch(u, {
      method: method,
      headers: window.slHeaders({ "Content-Type": "application/json" }),
      body: d === undefined ? undefined : JSON.stringify(d)
    }).then(function (r) { return asJson(r, u); });
  }
  window.api = {
    get: function (u) { return fetch(u, { headers: window.slHeaders() }).then(function (r) { return asJson(r, u); }); },
    post: function (u, d) { return request("POST", u, d || {}); },
    put: function (u, d) { return request("PUT", u, d || {}); },
    del: function (u, d) { return request("DELETE", u, d); }
  };
  // 供无法走 api 封装的裸 fetch（如 FormData 上传）取统一请求头：
  // 返回 X-Requested-With: sitelens（CSRF 显式头）+ 可选 X-Token。
  window.apiTok = window.slHeaders;

  /* 引擎不可达时的界面态：明确告诉用户"引擎没响应"，而不是一片空白。
     语义：这是阻塞式错误对话框（role=dialog + aria-modal），不做 Esc 关闭
     （关闭会把故障藏起来）；焦点落到「重新加载」按钮，Tab 限制在对话框内。 */
  function showEngineDown(msg) {
    if (!document.body || document.getElementById("sl-engine-down")) return;
    var d = document.createElement("div");
    d.id = "sl-engine-down";
    d.setAttribute("role", "dialog");
    d.setAttribute("aria-modal", "true");
    d.setAttribute("aria-labelledby", "sl-engine-down-title");
    d.setAttribute("aria-describedby", "sl-engine-down-desc");
    d.setAttribute("tabindex", "-1");
    d.style.cssText = "position:fixed;inset:0;z-index:9999;background:rgba(16,16,20,.94);" +
      "color:#e8e8ee;display:flex;align-items:center;justify-content:center;padding:24px;" +
      "font:14px/1.75 system-ui,-apple-system,'Segoe UI',sans-serif";
    var box = document.createElement("div");
    box.style.cssText = "max-width:560px;padding:26px 30px;border-radius:14px;background:#25252e;" +
      "border:1px solid #3a3a46";
    box.innerHTML =
      "<h3 id='sl-engine-down-title' style='margin:0 0 10px;font-size:16px'>引擎服务无响应</h3>" +
      "<p id='sl-engine-down-desc' style='margin:0 0 10px;color:#c9c9d4'>" + esc(msg) + "</p>" +
      "<p style='margin:0 0 16px;color:#8f8f9c;font-size:13px'>可能原因：引擎进程已退出 / " +
      "端口被占用 / 数据目录不可写。命令行形态请确认 <code>sitelens serve</code> 仍在运行。</p>" +
      "<button id='sl-engine-reload' type='button' style='padding:7px 16px;border-radius:8px;" +
      "border:1px solid #55555f;background:#33333d;color:#eee;cursor:pointer'>重新加载</button>";
    d.appendChild(box);
    document.body.appendChild(d);
    var btn = document.getElementById("sl-engine-reload");
    if (btn) {
      btn.onclick = function () { location.reload(); };
      try { btn.focus(); } catch (e) {}
    }
    // 焦点陷阱：Tab/Shift+Tab 不跑出错误对话框
    d.addEventListener("keydown", function (e) {
      if (e.key !== "Tab") return;
      var f = slFocusables(d);
      if (!f.length) { e.preventDefault(); d.focus(); return; }
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  }
  function clearEngineDown() {
    var el = document.getElementById("sl-engine-down");
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  /* 全局错误出口：toast 提示 + 引擎不可达时给出界面态。
     quiet=true 用于「失败可接受」的场景（如取消按钮、版本号角标），
     但引擎不可达一律给界面态——那是用户真正需要知道的故障。 */
  window.slReportError = function (err, opts) {
    var quiet = opts && opts.quiet;
    var msg = (err && err.message) ? err.message : String(err || "未知错误");
    if (/无法连接引擎服务/.test(msg)) {
      showEngineDown(msg);
      if (!quiet && window.toast) window.toast("引擎服务无响应：" + msg, "err");
      return;
    }
    if (!quiet && window.toast) window.toast(msg, "err");
  };
  // 未捕获的 Promise 异常一律上报，不再无声失败。
  window.addEventListener("unhandledrejection", function (ev) {
    window.slReportError(ev.reason);
  });

  /* 带 X-Token 的下载：location.href 导航无法携带自定义头，token 模式下
     /api/* 导航必 401，故统一 fetch→Blob→a.download。preferOpen 为真且
     响应无 attachment 头（如 HTML 报告预览）时改为新开标签。
     请求头统一走 slHeaders()（含 CSRF 自定义头，见上方注释）。 */
  window.slDownload = function (url, fallbackName, preferOpen) {
    return fetch(url, { headers: window.slHeaders() }).then(function (r) {
      if (!r.ok) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          throw new Error(j.error || "HTTP " + r.status);
        });
      }
      var cd = r.headers.get("Content-Disposition") || "";
      var m = cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)/i);
      var name = (m && m[1]) || fallbackName || "download";
      return r.blob().then(function (b) {
        var u = URL.createObjectURL(b);
        if (preferOpen && !cd) {
          var w = window.open(u, "_blank");
          if (!w) location.href = u;
          return;
        }
        var a = document.createElement("a");
        a.href = u;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(u); }, 10000);
      });
    });
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

  /* 自绘下拉组件（cdd）：app.html 与 chain.html 复用。
     ARIA：触发按钮 aria-haspopup=listbox + aria-expanded，弹层 role=listbox、
     选项 role=option + aria-selected；Esc 关闭并把焦点还给按钮。
     注意：app.js/chain.html 只用返回值的 .value，额外方法向后兼容。 */
  window.initCDD = function (rootId, onPick) {
    var root = document.getElementById(rootId);
    if (!root) return { get value() { return null; } };
    var btn = root.querySelector(".cdd-btn");
    var pop = root.querySelector(".cdd-pop");
    if (!btn || !pop) return { get value() { return root.getAttribute("data-value"); } };
    var opts = pop.querySelectorAll(".cdd-opt");

    btn.setAttribute("aria-haspopup", "listbox");
    btn.setAttribute("aria-expanded", "false");
    pop.setAttribute("role", "listbox");
    opts.forEach(function (o) { o.setAttribute("role", "option"); });

    function sync() {
      var open = root.classList.contains("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      opts.forEach(function (o) {
        o.setAttribute("aria-selected", o.classList.contains("active") ? "true" : "false");
      });
    }
    function close(refocus) {
      root.classList.remove("open");
      sync();
      if (refocus) btn.focus();
    }
    sync();

    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      var willOpen = !root.classList.contains("open");
      document.querySelectorAll(".cdd.open").forEach(function (r) {
        r.classList.remove("open");
        var b = r.querySelector(".cdd-btn");
        if (b) b.setAttribute("aria-expanded", "false");
      });
      if (willOpen) root.classList.add("open");
      sync();
    });
    pop.addEventListener("click", function (e) { e.stopPropagation(); });
    opts.forEach(function (opt) {
      opt.addEventListener("click", function () {
        opts.forEach(function (o) { o.classList.remove("active"); });
        opt.classList.add("active");
        root.setAttribute("data-value", opt.getAttribute("data-v"));
        root.querySelector(".cdd-label").innerHTML =
          "<b>" + esc(opt.querySelector("b").textContent) + "</b>" +
          '<span class="cdd-desc">' + esc(opt.querySelector("span").textContent) + "</span>";
        root.classList.remove("open");
        sync();
        if (onPick) onPick(opt.getAttribute("data-v"));
      });
    });
    // 键盘：Esc 关闭并归还焦点；上下键在选项间移动
    root.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        if (root.classList.contains("open")) {
          e.stopPropagation();
          e.preventDefault();
          close(true);
        }
        return;
      }
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      if (!root.classList.contains("open")) return;
      e.preventDefault();
      var list = Array.prototype.slice.call(opts).filter(function (o) { return !o.disabled; });
      if (!list.length) return;
      var i = list.indexOf(document.activeElement);
      var next = e.key === "ArrowDown" ? (i + 1) % list.length : (i <= 0 ? list.length - 1 : i - 1);
      list[next].focus();
    });
    return {
      get value() { return root.getAttribute("data-value"); },
      close: function () { close(false); }
    };
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
      var on = a.getAttribute("data-key") === key;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
  }
  window.slUpdateSide = updateSideActive;

  /* 模式行（主动五功能）单一来源：工作台与被动页渲染同一份 markup。
     ARIA：tablist/tab + aria-selected（active 由 buildShell/switchTab 维护），
     可访问名来自 <span> 文案；图标对辅助技术隐藏（aria-hidden）。 */
  function svgA11y(svg) {
    return String(svg || "").replace(/^<svg\b/, '<svg aria-hidden="true" focusable="false"');
  }
  function modeRowHTML() {
    return '<div class="tw-modes tabs" role="tablist" aria-label="' +
      (t("a11y_mode_tabs") || "功能模式") + '" data-i18n-aria-label="a11y_mode_tabs">' +
      MODE_SIDE.map(function (m) {
        var label = t("mode_" + m[0]) || m[2];
        return '<button type="button" class="tab" role="tab" data-tab="' + m[0] + '"' +
          ' aria-selected="false" title="' + label + '" data-i18n-title="mode_' + m[0] + '">' +
          svgA11y(m[3]) + '<span data-i18n="mode_' + m[0] + '">' + label + "</span></button>";
      }).join("") + "</div>";
  }
  function topNavHTML() {
    var nav = NAV.map(function (n) {
      var label = t(n[3]) || n[2];
      return '<a href="' + n[1] + '" data-key="' + n[0] + '" title="' + label + '"' +
        ' data-i18n-title="' + n[3] + '">' +
        svgA11y(ICONS[n[0]]) + '<span data-i18n="' + n[3] + '">' + label + "</span></a>";
    }).join("");
    return '<nav class="top-nav" aria-label="' + (t("a11y_main_nav") || "主导航") + '"' +
      ' data-i18n-aria-label="a11y_main_nav">' + nav + "</nav>";
  }
  function topRightHTML() {
    var themeLabel = t("theme_toggle") || "切换明暗主题";
    return '<div class="top-right">' +
      '<button type="button" class="theme-btn" onclick="toggleTheme()" title="' + themeLabel + '"' +
      ' aria-label="' + themeLabel + '" data-i18n-aria-label="a11y_theme_btn" aria-pressed="false">◐</button>' +
      '<span class="ver" id="sl-ver">SiteLens</span></div>';
  }
  function fillVersion() {
    api.get("/api/version").then(function (v) {
      var el = document.getElementById("sl-ver");
      if (el && v && v.version) el.textContent = "v" + v.version;
    }).catch(function (e) { window.slReportError(e, { quiet: true }); });
  }
  function buildShell() {
    var app = document.querySelector(".tw-app");
    if (!app) return;
    var stale = document.querySelector(".wb-top");
    if (stale && stale.parentNode) stale.parentNode.removeChild(stale);

    // 模式行（同款组件单一来源）：工作台填槽，被动页补同款左列。
    // 注意：槽位首次渲染后被 outerHTML 替换掉 #tw-modeslot，后续渲染（Turbo
    // 换页/i18n 就绪重渲染）要按 .tw-left > .tw-modes 兜底重渲染，否则语言
    // 切换后模式行文案不更新。
    var row = modeRowHTML();
    var key = sideActive();
    var modeSlot = document.getElementById("tw-modeslot");
    if (modeSlot) {
      modeSlot.outerHTML = row;
    } else {
      var oldRow = app.querySelector(":scope > .tw-left > .tw-modes");
      if (oldRow) {
        oldRow.outerHTML = row;
      } else if (!app.querySelector(":scope > .tw-left")) {
        var col = document.createElement("aside");
        col.className = "tw-left";
        col.innerHTML = row;
        app.insertBefore(col, app.firstChild);
      }
    }
    document.querySelectorAll(".tw-modes .tab").forEach(function (b) {
      var on = b.getAttribute("data-tab") === key;
      b.classList.toggle("active", on);
      if (on) b.setAttribute("aria-current", "true"); else b.removeAttribute("aria-current");
    });

    // 工具条槽位（被动页导航 + 亮暗 + 版本）
    var slot = document.getElementById("tw-topslot");
    if (slot) {
      slot.innerHTML = topNavHTML() + topRightHTML();
      slUpdateNav();
      fillVersion();
    }
    // 无障碍外壳增强（跳过导航/main 地标/抽屉开关/页签 ARIA/进度条/分割条/i18n）
    slInitShellA11y();
    applyTheme(); // 同步明暗按钮 aria-pressed
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
