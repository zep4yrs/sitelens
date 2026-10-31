/* SiteLens i18n 骨架（FE-07 部分，5.2.x）
   ============================================================================
   UMD：浏览器挂 window.slI18n；Node（node --test / require）走 module.exports。
   职责只有三件：
     1) 字典：zh-CN 为缺省（键值即中文文案），en-US 为示例翻译；
     2) t(key[, fallback])：按当前语言取文案，缺键回退 zh-CN → fallback → null
        （返回 null 而不是键名，调用方可以 `t(k) || 中文默认` 平滑降级）；
     3) apply(root)：扫描 [data-i18n] / [data-i18n-aria-label] / [data-i18n-title]
        / [data-i18n-placeholder] 做静态替换（骨架期只覆盖导航/按钮/弹层示例，
        不要求全量替换文案）。
   设计纪律：
     - 不改动 DOM 结构，只替换文本/属性，可重复调用（幂等）；
     - 与 common.js 的 PREFS.lang 联动：common.js 负责读取偏好并 setLang，
       本文件不直接读 localStorage（便于 node 测试与复用）。
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
      batch_urls_label: "批量扫描 URL 列表"
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
      batch_urls_label: "Batch URL list"
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

  // t 返回 null 表示"没有这条文案"（调用方自行回退），不会把键名漏到界面上。
  function t(key, fallback) {
    if (key == null) return fallback == null ? null : fallback;
    var k = String(key);
    var d = DICTS[currentLang];
    if (d && Object.prototype.hasOwnProperty.call(d, k) && d[k]) return d[k];
    var base = DICTS[DEFAULT_LANG];
    if (base && Object.prototype.hasOwnProperty.call(base, k) && base[k]) return base[k];
    return fallback == null ? null : fallback;
  }

  function applyText(el, key) {
    var v = t(key);
    if (v == null) return 0;
    el.textContent = v;
    return 1;
  }

  function applyAttr(el, attr, key) {
    var v = t(key);
    if (v == null) return 0;
    el.setAttribute(attr, v);
    return 1;
  }

  // apply(root)：root 缺省为 document；返回替换次数（便于测试/断言）。
  function apply(root) {
    var doc = root || (typeof document !== "undefined" ? document : null);
    if (!doc || typeof doc.querySelectorAll !== "function") return 0;
    var n = 0;
    var nodes = doc.querySelectorAll("[data-i18n]");
    for (var i = 0; i < nodes.length; i++) n += applyText(nodes[i], nodes[i].getAttribute("data-i18n"));
    nodes = doc.querySelectorAll("[data-i18n-aria-label]");
    for (var j = 0; j < nodes.length; j++) n += applyAttr(nodes[j], "aria-label", nodes[j].getAttribute("data-i18n-aria-label"));
    nodes = doc.querySelectorAll("[data-i18n-title]");
    for (var k = 0; k < nodes.length; k++) n += applyAttr(nodes[k], "title", nodes[k].getAttribute("data-i18n-title"));
    nodes = doc.querySelectorAll("[data-i18n-placeholder]");
    for (var m = 0; m < nodes.length; m++) n += applyAttr(nodes[m], "placeholder", nodes[m].getAttribute("data-i18n-placeholder"));
    return n;
  }

  return {
    version: "5.2.0",
    defaultLang: DEFAULT_LANG,
    supported: SUPPORTED.slice(),
    dicts: DICTS,
    t: t,
    apply: apply,
    setLang: setLang,
    getLang: getLang,
    normalize: normalize
  };
});
