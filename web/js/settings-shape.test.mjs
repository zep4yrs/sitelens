// F5 契约冒烟：GET /api/settings 响应形态变更后，设置页回填必须仍然正确。
//
// 背景：F5 把响应从 `{web:{listen}, crawler:{...}, ...}` 改成**扁平**形态
// `{listen, api_token_set, crawler:{...}, scan:{...}, ...}`，并且
// `web.api_token` 被彻底摘除（只留顶层 api_token_set 布尔）。
//
// 这里跑的是 settings.html 里**真实的 applySettings()**（正则抽取，不复制实现），
// 用一个记录型 ui 替身断言每个字段都被回填到正确控件。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../settings.html", import.meta.url), "utf8");
const m = html.match(/function applySettings\(c, ui\) \{[\s\S]*?\n  \}/);
if (!m) throw new Error("settings.html 中未找到 applySettings 定义");
const applySettings = new Function("return (" + m[0] + ")")();

/** 记录型 ui：setv/setChecked 都只记录，不碰 DOM。 */
function recorder() {
  const values = {};
  const checked = {};
  const calls = [];
  return {
    values,
    checked,
    calls,
    ui: {
      setv(id, v) { calls.push(["setv", id, v]); values[id] = v; },
      setChecked(id, v) { calls.push(["setChecked", id, v]); checked[id] = v; },
    },
  };
}

// F5 扁平形态（新契约）
const FLAT = {
  listen: "127.0.0.1:6000",
  api_token_set: true,
  crawler: { max_pages: 111, max_links_per_page: 222, timeout_sec: 33, respect_robots: true },
  scan: { rate_interval_ms: 44, timeout_sec: 55 },
  checks: { nuclei_cap: 66 },
  exploit: { enabled: true },
  ml: { predict: true, sev_linear: false, sev_onnx: true },
  intel: { overrides_path: "/tmp/ov.json" },
  batch: { max_urls: 50 },
  note: "保存后：扫描/爬取/Token 立即生效；监听地址需重启服务",
  config_path: "/home/u/.config/SiteLens-Wails/config.yml", // 仅 admin 可见
};

// 旧形态（web 段包裹 listen）
const LEGACY = {
  web: { listen: "127.0.0.1:5087" },
  crawler: { max_pages: 1, max_links_per_page: 2, timeout_sec: 3, respect_robots: false },
  scan: { rate_interval_ms: 4, timeout_sec: 5 },
  checks: { nuclei_cap: 6 },
  exploit: { enabled: false },
  ml: { predict: false, sev_linear: true, sev_onnx: false },
  intel: { overrides_path: "/old/ov.json" },
};

test("扁平形态：listen 与各段字段全部回填", () => {
  const r = recorder();
  const st = applySettings(FLAT, r.ui);
  assert.equal(r.values.listen, "127.0.0.1:6000", "listen 必须从顶层读（F5 新形态）");
  assert.equal(r.values.max_pages, 111);
  assert.equal(r.values.max_links_per_page, 222);
  assert.equal(r.values.crawl_timeout, 33);
  assert.equal(r.checked.respect_robots, true);
  assert.equal(r.values.rate_interval_ms, 44);
  assert.equal(r.values.scan_timeout, 55);
  assert.equal(r.values.nuclei_cap, 66);
  assert.equal(r.checked.exploit_enabled, true);
  assert.equal(r.checked.ml_predict, true);
  assert.equal(r.checked.ml_sev_linear, false);
  assert.equal(r.checked.ml_sev_onnx, true);
  assert.equal(r.values.overrides_path, "/tmp/ov.json");
  assert.equal(st.tokenSet, true, "api_token_set 必须从响应顶层读");
});

test("旧形态（web.listen 包裹）仍然兼容", () => {
  const r = recorder();
  const st = applySettings(LEGACY, r.ui);
  assert.equal(r.values.listen, "127.0.0.1:5087");
  assert.equal(r.values.max_pages, 1);
  assert.equal(r.checked.respect_robots, false);
  assert.equal(r.checked.ml_sev_linear, true);
  assert.equal(st.tokenSet, false, "旧形态无 api_token_set 且无明文 → 未启用");
});

test("token 状态：顶层 api_token_set 优先；旧引擎明文只作兼容值", () => {
  // 新形态：只有布尔
  assert.equal(applySettings({ listen: "x", api_token_set: true }, recorder().ui).tokenSet, true);
  assert.equal(applySettings({ listen: "x", api_token_set: false }, recorder().ui).tokenSet, false);
  // 旧引擎：明文存在性
  const legacy = applySettings({ web: { listen: "x", api_token: "secret" } }, recorder().ui);
  assert.equal(legacy.tokenSet, true);
  assert.equal(legacy.tokenLegacy, "secret", "明文只作为留空保存时的回写值");
  // 新形态不得把任何明文塞进 ui（防止回归成回填输入框）
  const r = recorder();
  applySettings(FLAT, r.ui);
  for (const [kind, id, v] of r.calls) {
    assert.ok(!(kind === "setv" && id === "api_token"), "禁止把 token 回填到输入框");
    assert.ok(String(v !== undefined ? v : "").indexOf("sk-") < 0, "不得出现掩码/明文 token 值");
  }
});

test("config_path 不进入任何表单字段（非 admin 不得泄漏主机路径）", () => {
  const r = recorder();
  applySettings(FLAT, r.ui);
  const ids = r.calls.map((c) => c[1]);
  assert.ok(!ids.includes("config_path"), "页面不应回填 config_path");
  const dumped = JSON.stringify(r.calls);
  assert.ok(!dumped.includes("/home/u/.config"), "config_path 不得出现在任何控件值里");
});

test("缺字段/空响应不抛异常（旧引擎/部分字段缺失时页面仍可用）", () => {
  for (const resp of [null, undefined, {}, { web: {} }, { listen: null }]) {
    const r = recorder();
    assert.doesNotThrow(() => applySettings(resp, r.ui), `applySettings(${JSON.stringify(resp)}) 不应抛异常`);
  }
  // listen 为空时回填 undefined 也不该炸；有 listen 时正常
  assert.equal(applySettings({ listen: "127.0.0.1:1" }, recorder().ui).tokenSet, false);
});
