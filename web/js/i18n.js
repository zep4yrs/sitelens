/* SiteLens i18n（FE-07，5.2.x）
   ============================================================================
   UMD：浏览器挂 window.slI18n；Node（node --test / require）走 module.exports。
   职责：
     1) 字典：zh-CN 为源语言（键值即中文文案），en-US 必须键集合对称；
        覆盖导航/模式行/按钮/表单标签/状态提示/表头/严重度/空态/加载态/
        快捷键帮助/HTML 白名单文案（5.2.x 扩到 113 键）；
     2) t(key[, fallback][, vars])：当前语言 → zh-CN → fallback → null
        （返回 null 而不是键名，调用方可以 `t(k) || 中文默认` 平滑降级）；
        支持 {n} 具名插值（第二个参数传对象即 vars，兼容旧 t(key, fallback)）；
     3) apply(root)：扫描并替换
        [data-i18n] / [data-i18n-html]（白名单） / [data-i18n-aria-label] /
        [data-i18n-title] / [data-i18n-placeholder]；元素可带
        data-i18n-vars='{"n":3}' 提供插值变量。
   安全：data-i18n-html 只认 HTML_KEYS 白名单键，且插值值先转义；
        非白名单键退化为 textContent（文案表本身不能成为 HTML 注入面）。
   设计纪律：
     - 不改动 DOM 结构，只替换文本/属性，可重复调用（幂等）；
     - 与 common.js 的 PREFS.lang 联动：common.js 负责读取偏好并 setLang，
       本文件不直接读 localStorage（便于 node 测试与复用）；
     - 新增文案先加 zh-CN 键，再加 en-US 翻译；缺 en-US 时自动回退中文。
   ========================================================================== */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.slI18n = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var DEFAULT_LANG = "zh-CN";
  var SUPPORTED = ["zh-CN", "en-US"];

  var DICTS = {
    "zh-CN": {
      /* 顶栏导航（common.js topNavHTML 使用） */
      nav_scan: "综合扫描",
      nav_netsec: "网络层检测",
      nav_audit: "源码审计",
      nav_brute: "登录爆破",
      nav_batch: "批量扫描",
      nav_history: "历史",
      nav_intel: "情报库",
      nav_verified: "已验证漏洞",
      nav_settings: "设置",
      nav_feedback: "反馈",
      nav_chain: "攻击链",

      /* 左栏模式行（工作台五功能） */
      mode_scan: "综合扫描",
      mode_netsec: "网络层检测",
      mode_loginbrute: "登录爆破",
      mode_audit: "源码审计",
      mode_batch: "批量扫描",

      /* 通用动作 / 外壳 */
      theme_toggle: "切换明暗主题",
      side_toggle: "配置",
      skip_to_main: "跳到主要内容",
      keys_btn: "键盘快捷键",
      keys_dialog_title: "键盘快捷键",
      keys_dialog_close: "关闭快捷键帮助",
      keys_start: "开始扫描",
      keys_cancel: "取消扫描 / 关闭弹层",
      keys_export: "导出 JSON 结果",
      keys_ime_note: "输入法组合输入期间快捷键不触发。",

      /* 无障碍名称（aria-label / title） */
      a11y_main_nav: "主导航",
      a11y_mode_tabs: "功能模式",
      a11y_side_panel: "扫描配置面板",
      a11y_resize: "调整左栏宽度",
      a11y_progress: "进度",
      a11y_clear_url: "清空网址输入",
      a11y_dir_btn: "选择整个项目文件夹",
      a11y_dropzone: "选择文件或拖入文件夹",
      a11y_keys_btn: "键盘快捷键",
      a11y_preview_title: "登录页预览",
      a11y_theme_btn: "切换明暗主题",

      /* 主要按钮 */
      btn_start_scan: "开始扫描",
      btn_netsec_start: "开始检测",
      btn_loginbrute_start: "开始爆破",
      btn_audit_start: "开始审计",
      btn_batch_start: "开始批量扫描",
      btn_cancel_scan: "取消扫描",
      btn_export_json: "JSON",
      btn_export_csv: "明细 CSV",
      btn_export_wide: "宽表 CSV",
      btn_export_html: "HTML 报告",
      btn_export_md: "MD 报告",

      /* 表单标签（骨架示例，实际以 aria-label 直接写死为主） */
      url_label: "目标网址",
      ns_host_label: "网络层检测目标域名",
      lb_url_label: "登录页 URL",
      opt_cookie_label: "认证会话 Cookie",
      lb_cap_field_label: "验证码字段名",
      batch_urls_label: "批量扫描 URL 列表",

      /* ---- 扫描状态 / 提示（FE-07 扩展，5.2.x） ---- */
      toast_scan_started: "扫描已开始",
      toast_scan_cancelled: "已取消扫描",
      toast_scan_done: "扫描完成",
      toast_scan_failed: "扫描失败",
      toast_export_done: "导出已开始",
      toast_export_failed: "导出失败",
      toast_copy_ok: "已复制",
      toast_copy_failed: "复制失败",
      toast_net_error: "网络错误，请检查引擎服务",
      hint_url_required: "请输入目标网址",
      hint_scan_running: "扫描进行中，请稍候",
      hint_engine_down: "引擎服务无响应",

      /* ---- 空态 / 加载态 ---- */
      empty_no_result: "暂无扫描结果",
      empty_no_history: "暂无扫描历史",
      empty_no_intel: "未找到匹配条目",
      empty_no_chain: "暂无攻击链数据",
      loading_scanning: "扫描中…",
      loading_loading: "加载中…",
      loading_preparing: "准备中…",
      loading_skeleton: "内容加载中",

      /* ---- 结果列 / 表格表头 ---- */
      col_status: "状态",
      col_url: "URL",
      col_level: "级别",
      col_time: "时间",
      col_tech: "技术",
      col_method: "方法",
      col_endpoint: "端点",
      col_action: "操作",

      /* ---- 严重度 ---- */
      sev_critical: "严重",
      sev_high: "高危",
      sev_medium: "中危",
      sev_low: "低危",
      sev_info: "信息",

      /* ---- 通用动作 ---- */
      action_retry: "重试",
      action_refresh: "刷新",
      action_close: "关闭",
      action_copy: "复制",
      action_cancel: "取消",
      action_confirm: "确认",
      action_export: "导出",

      /* ---- 计数 / 时长（{n} 具名插值示例） ---- */
      count_items: "{n} 条",
      count_pages: "{n} 页",
      count_requests: "{n} 次请求",
      duration_sec: "{n} 秒",
      duration_min: "{n} 分钟",
      duration_hour: "{n} 小时",

      /* ---- 页面标题 ---- */
      page_scan: "扫描",
      page_history: "扫描历史",
      page_intel: "情报库",
      page_settings: "设置",
      page_audit: "源码审计",

      /* ---- 各功能主要提示 ---- */
      hint_batch_empty: "请粘贴至少一个 URL",
      hint_batch_running: "批量扫描进行中",
      hint_brute_authorized: "需要勾选授权确认",
      hint_netsec_target: "输入域名后开始检测",
      hint_audit_empty: "请选择文件或文件夹",

      /* ---- HTML 白名单文案（data-i18n-html 专用；含标记，插值值会被转义） ---- */
      msg_engine_down_html: "引擎服务无响应，请确认 <code>sitelens serve</code> 仍在运行",
      msg_shortcut_help_html: "按 <kbd>Esc</kbd> 关闭弹层",
      msg_count_html: "共 <b>{n}</b> 条"
    },
    "en-US": {
      nav_scan: "Scan",
      nav_netsec: "Net Scan",
      nav_audit: "Code Audit",
      nav_brute: "Login Brute",
      nav_batch: "Batch",
      nav_history: "History",
      nav_intel: "Intel",
      nav_verified: "Verified",
      nav_settings: "Settings",
      nav_feedback: "Feedback",
      nav_chain: "Attack Chain",

      mode_scan: "Scan",
      mode_netsec: "Net Scan",
      mode_loginbrute: "Login Brute",
      mode_audit: "Code Audit",
      mode_batch: "Batch",

      theme_toggle: "Toggle light/dark theme",
      side_toggle: "Options",
      skip_to_main: "Skip to main content",
      keys_btn: "Keyboard shortcuts",
      keys_dialog_title: "Keyboard shortcuts",
      keys_dialog_close: "Close keyboard shortcuts",
      keys_start: "Start scan",
      keys_cancel: "Cancel scan / close overlay",
      keys_export: "Export JSON result",
      keys_ime_note: "Shortcuts are ignored while an IME composition is active.",

      a11y_main_nav: "Main navigation",
      a11y_mode_tabs: "Workbench modes",
      a11y_side_panel: "Scan options panel",
      a11y_resize: "Resize sidebar",
      a11y_progress: "Progress",
      a11y_clear_url: "Clear target URL",
      a11y_dir_btn: "Select project folder",
      a11y_dropzone: "Choose files or drop a folder",
      a11y_keys_btn: "Keyboard shortcuts",
      a11y_preview_title: "Login page preview",
      a11y_theme_btn: "Toggle light/dark theme",

      btn_start_scan: "Start scan",
      btn_netsec_start: "Start check",
      btn_loginbrute_start: "Start brute force",
      btn_audit_start: "Start audit",
      btn_batch_start: "Start batch scan",
      btn_cancel_scan: "Cancel scan",
      btn_export_json: "JSON",
      btn_export_csv: "Detail CSV",
      btn_export_wide: "Wide CSV",
      btn_export_html: "HTML report",
      btn_export_md: "MD report",

      url_label: "Target URL",
      ns_host_label: "Target domain for network checks",
      lb_url_label: "Login page URL",
      opt_cookie_label: "Session cookie",
      lb_cap_field_label: "Captcha field name",
      batch_urls_label: "Batch URL list",

      /* ---- scan status / hints (FE-07 extension, 5.2.x) ---- */
      toast_scan_started: "Scan started",
      toast_scan_cancelled: "Scan cancelled",
      toast_scan_done: "Scan finished",
      toast_scan_failed: "Scan failed",
      toast_export_done: "Export started",
      toast_export_failed: "Export failed",
      toast_copy_ok: "Copied",
      toast_copy_failed: "Copy failed",
      toast_net_error: "Network error. Check the engine service.",
      hint_url_required: "Enter a target URL",
      hint_scan_running: "Scan in progress, please wait",
      hint_engine_down: "Engine service not responding",

      /* ---- empty / loading states ---- */
      empty_no_result: "No scan results yet",
      empty_no_history: "No scan history yet",
      empty_no_intel: "No matching entries",
      empty_no_chain: "No attack chain data",
      loading_scanning: "Scanning…",
      loading_loading: "Loading…",
      loading_preparing: "Preparing…",
      loading_skeleton: "Loading content",

      /* ---- result columns / table headers ---- */
      col_status: "Status",
      col_url: "URL",
      col_level: "Level",
      col_time: "Time",
      col_tech: "Technology",
      col_method: "Method",
      col_endpoint: "Endpoint",
      col_action: "Action",

      /* ---- severity ---- */
      sev_critical: "Critical",
      sev_high: "High",
      sev_medium: "Medium",
      sev_low: "Low",
      sev_info: "Info",

      /* ---- common actions ---- */
      action_retry: "Retry",
      action_refresh: "Refresh",
      action_close: "Close",
      action_copy: "Copy",
      action_cancel: "Cancel",
      action_confirm: "Confirm",
      action_export: "Export",

      /* ---- counts / durations ({n} named interpolation examples) ---- */
      count_items: "{n} items",
      count_pages: "{n} pages",
      count_requests: "{n} requests",
      duration_sec: "{n} s",
      duration_min: "{n} min",
      duration_hour: "{n} h",

      /* ---- page titles ---- */
      page_scan: "Scan",
      page_history: "Scan history",
      page_intel: "Intel library",
      page_settings: "Settings",
      page_audit: "Code audit",

      /* ---- feature hints ---- */
      hint_batch_empty: "Paste at least one URL",
      hint_batch_running: "Batch scan in progress",
      hint_brute_authorized: "Authorization confirmation required",
      hint_netsec_target: "Enter a domain to start",
      hint_audit_empty: "Choose files or a folder",

      /* ---- HTML-whitelisted copy (data-i18n-html; interpolated values escaped) ---- */
      msg_engine_down_html: "Engine service not responding. Make sure <code>sitelens serve</code> is still running.",
      msg_shortcut_help_html: "Press <kbd>Esc</kbd> to close the dialog.",
      msg_count_html: "<b>{n}</b> items in total"
    }
  };

  var currentLang = DEFAULT_LANG;

  function normalize(lang) {
    var l = String(lang || "").trim();
    if (!l) return DEFAULT_LANG;
    for (var i = 0; i < SUPPORTED.length; i++) {
      if (SUPPORTED[i].toLowerCase() === l.toLowerCase()) return SUPPORTED[i];
    }
    // 兼容 "en" / "zh" 之类短码
    if (/^en\b/i.test(l)) return "en-US";
    if (/^zh\b/i.test(l)) return "zh-CN";
    return DEFAULT_LANG;
  }

  function setLang(lang) {
    var next = normalize(lang);
    if (!DICTS[next]) return false;
    currentLang = next;
    // a11y：语言切换必须同步 <html lang>（屏幕阅读器按该属性选发音/断词规则；
    // docs/i18n-5.2.md §3.4 列为 FE-07 第一批必改项）。Node 环境无 document 时跳过。
    if (typeof document !== "undefined" && document.documentElement) {
      document.documentElement.setAttribute("lang", currentLang);
    }
    return true;
  }

  function getLang() {
    return currentLang;
  }

  /* ---------------- 取词 / 插值 / HTML 白名单 ---------------- */
  // data-i18n-html 只认这里的键：文案表本身不能成为 HTML 注入面。
  // 新增带标记的文案必须先加白名单并补测试（scripts/i18n.test.mjs）。
  var HTML_KEYS = {
    msg_engine_down_html: 1,
    msg_shortcut_help_html: 1,
    msg_count_html: 1
  };

  function escapeHTML(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // 具名占位符 {name}：缺变量时保留占位符（让缺陷可见，而不是静默变空）；
  // forHtml=true 时插值值先转义（HTML 白名单文案专用）。
  function interpolate(text, vars, forHtml) {
    if (text == null) return text;
    if (!vars || typeof vars !== "object") return String(text);
    return String(text).replace(/\{([a-zA-Z0-9_]+)\}/g, function (m, name) {
      if (!Object.prototype.hasOwnProperty.call(vars, name)) return m;
      var v = vars[name];
      if (v == null) return m;
      v = String(v);
      return forHtml ? escapeHTML(v) : v;
    });
  }

  function lookup(key) {
    if (key == null) return null;
    var k = String(key);
    var d = DICTS[currentLang];
    if (d && Object.prototype.hasOwnProperty.call(d, k) && d[k]) return d[k];
    var base = DICTS[DEFAULT_LANG];
    if (base && Object.prototype.hasOwnProperty.call(base, k) && base[k]) return base[k];
    return null;
  }

  // t(key[, fallback][, vars])
  //   - 第二个参数传对象即视为 vars（兼容旧的 t(key, fallback) 调用）
  //   - 返回 null 表示"没有这条文案"（不把键名漏到界面），缺键回退 zh-CN → fallback
  function t(key, fallback, vars) {
    if (fallback && typeof fallback === "object") { vars = fallback; fallback = null; }
    var raw = lookup(key);
    if (raw == null) {
      if (fallback == null) return null;
      return interpolate(String(fallback), vars, false);
    }
    return interpolate(raw, vars, false);
  }

  function isHtmlKey(key) {
    return !!(key != null && HTML_KEYS[String(key)]);
  }

  // html(key[, vars][, fallback])：仅白名单键返回 HTML 串（插值值已转义），否则 null。
  // 调用方/apply 对非白名单键必须退化为 textContent（安全默认）。
  function html(key, vars, fallback) {
    if (!isHtmlKey(key)) return null;
    var raw = lookup(key);
    if (raw == null) {
      if (fallback == null) return null;
      return interpolate(String(fallback), vars, true);
    }
    return interpolate(raw, vars, true);
  }

  // 读取元素上的 data-i18n-vars='{"n":3}'（JSON；非法/非对象按无变量处理）
  function varsOf(el) {
    var raw = el.getAttribute("data-i18n-vars");
    if (!raw) return null;
    try {
      var v = JSON.parse(raw);
      return v && typeof v === "object" ? v : null;
    } catch (e) {
      return null;
    }
  }

  function applyText(el, key, vars) {
    var v = t(key, vars);
    if (v == null) return 0;
    el.textContent = v;
    return 1;
  }

  function applyHTML(el, key, vars) {
    var v = html(key, vars);
    if (v == null) return applyText(el, key, vars); // 非白名单键退化为纯文本
    el.innerHTML = v;
    return 1;
  }

  function applyAttr(el, attr, key, vars) {
    var v = t(key, vars);
    if (v == null) return 0;
    el.setAttribute(attr, v);
    return 1;
  }

  // apply(root)：root 缺省为 document；返回替换次数（便于测试/断言）。
  // 支持 [data-i18n] / [data-i18n-html]（白名单）/ [data-i18n-aria-label]
  // / [data-i18n-title] / [data-i18n-placeholder]；元素可带 data-i18n-vars。
  function apply(root) {
    var doc = root || (typeof document !== "undefined" ? document : null);
    if (!doc || typeof doc.querySelectorAll !== "function") return 0;
    var n = 0, nodes, i, el;
    nodes = doc.querySelectorAll("[data-i18n]");
    for (i = 0; i < nodes.length; i++) {
      el = nodes[i];
      n += applyText(el, el.getAttribute("data-i18n"), varsOf(el));
    }
    nodes = doc.querySelectorAll("[data-i18n-html]");
    for (i = 0; i < nodes.length; i++) {
      el = nodes[i];
      n += applyHTML(el, el.getAttribute("data-i18n-html"), varsOf(el));
    }
    nodes = doc.querySelectorAll("[data-i18n-aria-label]");
    for (i = 0; i < nodes.length; i++) {
      el = nodes[i];
      n += applyAttr(el, "aria-label", el.getAttribute("data-i18n-aria-label"), varsOf(el));
    }
    nodes = doc.querySelectorAll("[data-i18n-title]");
    for (i = 0; i < nodes.length; i++) {
      el = nodes[i];
      n += applyAttr(el, "title", el.getAttribute("data-i18n-title"), varsOf(el));
    }
    nodes = doc.querySelectorAll("[data-i18n-placeholder]");
    for (i = 0; i < nodes.length; i++) {
      el = nodes[i];
      n += applyAttr(el, "placeholder", el.getAttribute("data-i18n-placeholder"), varsOf(el));
    }
    return n;
  }

  return {
    version: "5.2.0",
    defaultLang: DEFAULT_LANG,
    supported: SUPPORTED.slice(),
    dicts: DICTS,
    htmlKeys: Object.keys(HTML_KEYS),
    t: t,
    html: html,
    isHtmlKey: isHtmlKey,
    interpolate: interpolate,
    escapeHTML: escapeHTML,
    apply: apply,
    setLang: setLang,
    getLang: getLang,
    normalize: normalize
  };
});
