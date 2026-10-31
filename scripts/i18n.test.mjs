// i18n 骨架回归（node --test scripts/i18n.test.mjs）
// 覆盖：UMD 双端导出、字典键一致性、t() 回退链、setLang/normalize、
// apply() 对 data-i18n / data-i18n-aria-label / data-i18n-title / data-i18n-placeholder 的替换。
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
