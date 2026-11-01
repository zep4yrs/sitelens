// i18n 骨架 + 扩展回归（node --test scripts/i18n.test.mjs）
// 覆盖：UMD 双端导出、字典键一致性/规模、t() 回退链、setLang/normalize、
// {n} 具名插值、data-i18n-html 白名单（转义/退化）、apply() 对
// data-i18n / data-i18n-html / data-i18n-aria-label / data-i18n-title /
// data-i18n-placeholder + data-i18n-vars 的替换。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "..", "web", "js", "i18n.js"), "utf8");
const mod = await import("../web/js/i18n.js");
const i18n = mod.default ?? mod;

test("UMD：浏览器环境挂 window.slI18n", () => {
  const sandbox = {};
  sandbox.window = sandbox; // 浏览器里 globalThis === window
  sandbox.globalThis = sandbox;
  runInNewContext(src, sandbox);
  assert.ok(sandbox.window.slI18n, "window.slI18n 未暴露");
  assert.equal(typeof sandbox.window.slI18n.t, "function");
  assert.equal(sandbox.window.slI18n.getLang(), "zh-CN");
});

test("字典：zh-CN 与 en-US 键集合一致", () => {
  const zh = Object.keys(i18n.dicts["zh-CN"]).sort();
  const en = Object.keys(i18n.dicts["en-US"]).sort();
  assert.deepEqual(en, zh, "en-US 与 zh-CN 键集合不一致（新增文案要同步两套）");
});

test("t()：当前语言 → zh-CN → fallback → null", () => {
  i18n.setLang("zh-CN");
  assert.equal(i18n.t("nav_history"), "历史");
  i18n.setLang("en-US");
  assert.equal(i18n.t("nav_history"), "History");
  assert.equal(i18n.t("no_such_key"), null, "缺键应返回 null 而不是键名");
  assert.equal(i18n.t("no_such_key", "兜底"), "兜底");
});

test("setLang/normalize：短码与未知语言", () => {
  assert.equal(i18n.normalize("en"), "en-US");
  assert.equal(i18n.normalize("zh"), "zh-CN");
  assert.equal(i18n.normalize("fr-FR"), "zh-CN", "未知语言回退缺省 zh-CN");
  assert.equal(i18n.setLang("en-US"), true);
  assert.equal(i18n.getLang(), "en-US");
  assert.equal(i18n.setLang("xx-YY"), true, "未知语言也应归一为缺省语言而不是失败");
  assert.equal(i18n.getLang(), "zh-CN");
});

test("apply()：替换文本/aria-label/title/placeholder（幂等）", () => {
  const makeEl = (attrs) => {
    const el = {
      _attrs: { ...attrs },
      textContent: "",
      getAttribute(k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      setAttribute(k, v) { this._attrs[k] = v; },
    };
    return el;
  };
  const text = makeEl({ "data-i18n": "nav_history" });
  const aria = makeEl({ "data-i18n-aria-label": "a11y_main_nav" });
  const title = makeEl({ "data-i18n-title": "theme_toggle" });
  const ph = makeEl({ "data-i18n-placeholder": "url_label" });
  const missing = makeEl({ "data-i18n": "no_such_key" });
  const bySel = {
    "[data-i18n]": [text, missing],
    "[data-i18n-aria-label]": [aria],
    "[data-i18n-title]": [title],
    "[data-i18n-placeholder]": [ph],
  };
  const doc = { querySelectorAll: (sel) => bySel[sel] || [] };
  i18n.setLang("zh-CN");
  assert.equal(i18n.apply(doc), 4, "缺键不应计入替换次数");
  assert.equal(text.textContent, "历史");
  assert.equal(aria.getAttribute("aria-label"), "主导航");
  assert.equal(title.getAttribute("title"), "切换明暗主题");
  assert.equal(ph.getAttribute("placeholder"), "目标网址");
  // 幂等：再跑一次结果不变
  i18n.apply(doc);
  assert.equal(text.textContent, "历史");
});

test("apply()：无 document 环境安全返回 0", () => {
  assert.equal(i18n.apply(null), 0);
});

test("setLang()：同步 <html lang>（a11y；Node 无 document 时安全跳过）", () => {
  const seen = [];
  globalThis.document = {
    documentElement: { setAttribute: (k, v) => seen.push([k, v]) },
  };
  try {
    i18n.setLang("en-US");
    assert.deepEqual(seen.pop(), ["lang", "en-US"]);
    i18n.setLang("zh-CN");
    assert.deepEqual(seen.pop(), ["lang", "zh-CN"]);
  } finally {
    delete globalThis.document;
  }
  // 无 document 环境仍可切语言（node 直测/服务端渲染预演）
  assert.equal(i18n.setLang("en-US"), true);
  assert.equal(i18n.getLang(), "en-US");
  i18n.setLang("zh-CN");
});

/* ================= FE-07 扩展（5.2.x）：规模 / 插值 / HTML 白名单 ================= */

test("字典扩展：总键数 ≥94（原 54 + 新增 ≥40），新键两语言都存在", () => {
  const zh = i18n.dicts["zh-CN"];
  const en = i18n.dicts["en-US"];
  assert.ok(Object.keys(zh).length >= 94, "字典键数不足（新增 ≥40 键的要求）: " + Object.keys(zh).length);
  // 覆盖扫描/批量/爆破/网络层/审计主要按钮与提示
  const required = [
    "toast_scan_started", "toast_scan_failed", "toast_export_failed",
    "hint_scan_running", "hint_engine_down", "hint_url_required",
    "empty_no_result", "empty_no_history", "loading_scanning", "loading_skeleton",
    "col_status", "col_url", "col_level", "col_time",
    "sev_critical", "sev_high", "sev_medium", "sev_low", "sev_info",
    "action_retry", "action_refresh", "action_close", "action_export",
    "count_items", "count_pages", "duration_sec", "duration_min",
    "page_history", "page_settings", "page_audit",
    "hint_batch_empty", "hint_batch_running", "hint_brute_authorized",
    "hint_netsec_target", "hint_audit_empty",
    "msg_engine_down_html", "msg_shortcut_help_html", "msg_count_html",
  ];
  for (const k of required) {
    assert.ok(zh[k], "zh-CN 缺扩展键 " + k);
    assert.ok(en[k], "en-US 缺扩展键 " + k);
  }
});

test("插值：{n} 具名占位符（两语言占位符一致；缺变量保留占位符）", () => {
  const interpolated = Object.keys(i18n.dicts["zh-CN"]).filter((k) => /\{n\}/.test(i18n.dicts["zh-CN"][k]));
  assert.ok(interpolated.length >= 6, "带 {n} 的键太少: " + interpolated.length);
  for (const k of interpolated) {
    assert.match(i18n.dicts["en-US"][k], /\{n\}/, "en-US 同键缺 {n} 占位符: " + k);
  }

  i18n.setLang("zh-CN");
  assert.equal(i18n.t("count_items", { n: 3 }), "3 条");
  assert.equal(i18n.t("duration_sec", { n: 2.5 }), "2.5 秒");
  // 第二个参数传对象即 vars（兼容旧 t(key, fallback)）
  assert.equal(i18n.t("count_pages", { n: 0 }), "0 页");
  // 缺变量 → 保留占位符（缺陷可见，不静默变空）
  assert.equal(i18n.t("count_items", { x: 1 }), "{n} 条");
  assert.equal(i18n.t("count_items", null), "{n} 条");
  // fallback 也参与插值
  assert.equal(i18n.t("no_such_key", "共 {n} 项", { n: 7 }), "共 7 项");

  i18n.setLang("en-US");
  assert.equal(i18n.t("count_items", { n: 3 }), "3 items");
  assert.equal(i18n.t("duration_min", { n: 5 }), "5 min");
  i18n.setLang("zh-CN");
});

test("HTML 白名单：仅白名单键返回 HTML；插值值转义；非白名单返回 null", () => {
  i18n.setLang("zh-CN");
  assert.deepEqual(i18n.htmlKeys.sort(), ["msg_count_html", "msg_engine_down_html", "msg_shortcut_help_html"]);
  assert.equal(i18n.isHtmlKey("msg_count_html"), true);
  assert.equal(i18n.isHtmlKey("nav_history"), false);

  assert.match(i18n.html("msg_engine_down_html"), /<code>sitelens serve<\/code>/);
  assert.match(i18n.html("msg_shortcut_help_html"), /<kbd>Esc<\/kbd>/);
  // 插值值在 HTML 模式必须转义（防 XSS）
  assert.equal(
    i18n.html("msg_count_html", { n: '<img src=x onerror="1">' }),
    "共 <b>&lt;img src=x onerror=&quot;1&quot;&gt;</b> 条"
  );
  // 非白名单键：不得返回 HTML
  assert.equal(i18n.html("nav_history"), null);
  assert.equal(i18n.html("no_such_key", null, "<b>兜底</b>"), null, "非白名单键的 fallback 也不能当 HTML");
});

test("apply()：data-i18n-html（白名单）+ data-i18n-vars；非白名单退化纯文本", () => {
  const makeEl = (attrs) => {
    const el = {
      _attrs: { ...attrs },
      textContent: "",
      innerHTML: "",
      getAttribute(k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
      setAttribute(k, v) { this._attrs[k] = v; },
    };
    return el;
  };
  const withVars = makeEl({ "data-i18n-html": "msg_count_html", "data-i18n-vars": '{"n":5}' });
  const plainHtml = makeEl({ "data-i18n-html": "nav_history" }); // 非白名单 → 退化 textContent
  const badVars = makeEl({ "data-i18n": "count_items", "data-i18n-vars": "{not json" }); // 非法 JSON 不抛
  const textVars = makeEl({ "data-i18n": "duration_sec", "data-i18n-vars": '{"n":9}' });
  const bySel = {
    "[data-i18n]": [badVars, textVars],
    "[data-i18n-html]": [withVars, plainHtml],
  };
  const doc = { querySelectorAll: (sel) => bySel[sel] || [] };
  i18n.setLang("zh-CN");
  assert.equal(i18n.apply(doc), 4, "白名单 1 + 退化 1 + 文本 2 = 4 次替换");
  assert.equal(withVars.innerHTML, "共 <b>5</b> 条");
  assert.equal(withVars.textContent, "", "HTML 模式不应写 textContent");
  assert.equal(plainHtml.innerHTML, "", "非白名单键不得写 innerHTML");
  assert.equal(plainHtml.textContent, "历史");
  assert.equal(badVars.textContent, "{n} 条", "非法 vars 按无变量处理，保留占位符");
  assert.equal(textVars.textContent, "9 秒");
});
