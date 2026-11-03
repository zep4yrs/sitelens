// D-04 回归测试：API Token 的「写侧」必须真实存在且与读侧同键。
//
// 背景：修复前全仓只有读（common.js 的 tok() 读 localStorage["sitelens-token"]），
// 没有任何地方写这个键 —— 设置页保存 api_token 后引擎立即要求 X-Token，
// 前端手里没有 token，于是每个 /api/* 都 401（设置页自身也打不开）。
//
// 这里测的是**真实源码**（与 esc.test.mjs 同样的抽取手法，不是复制品）：
//   1) 从 common.js 抽 slStoreToken/slReadToken/tok，喂 mock localStorage 断言行为；
//   2) 从 settings.html 抽保存流程，断言它确实调用 slStoreToken 且不再回填明文。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const common = readFileSync(new URL("js/common.js", root), "utf8");
const settings = readFileSync(new URL("settings.html", root), "utf8");

/** 从源码里取出一个具名函数表达式（window.xxx = function ...）并实例化。 */
function extractWindowFn(src, name, deps) {
  const re = new RegExp("window\\." + name + " = function[\\s\\S]*?\\n  \\};");
  const m = src.match(re);
  if (!m) throw new Error("common.js 中未找到 window." + name + " 定义");
  const fnText = m[0].replace("window." + name + " = ", "").replace(/;\s*$/, "");
  const names = Object.keys(deps || {});
  return new Function(...names, "return (" + fnText + ")")(...names.map((n) => deps[n]));
}

/** 从源码里取出一个 function 声明（function tok() {...}）。 */
function extractFn(src, name, deps) {
  const re = new RegExp("function " + name + "\\(\\) \\{[\\s\\S]*?\\n  \\}");
  const m = src.match(re);
  if (!m) throw new Error("common.js 中未找到 function " + name);
  const names = Object.keys(deps || {});
  return new Function(...names, "return (" + m[0] + ")")(...names.map((n) => deps[n]));
}

/** 最小 localStorage 替身：记录调用，行为与浏览器一致。 */
function mockStorage(initial) {
  const data = new Map(Object.entries(initial || {}));
  return {
    calls: [],
    getItem(k) { return data.has(k) ? data.get(k) : null; },
    setItem(k, v) { this.calls.push(["setItem", k, String(v)]); data.set(k, String(v)); },
    removeItem(k) { this.calls.push(["removeItem", k]); data.delete(k); },
    dump() { return Object.fromEntries(data); },
  };
}

test("slStoreToken 把 token 写入 sitelens-token（读侧同一个键）", () => {
  const storage = mockStorage();
  const store = extractWindowFn(common, "slStoreToken", { localStorage: storage });
  assert.equal(store("  tok-abc  "), "tok-abc");
  assert.deepEqual(storage.calls, [["setItem", "sitelens-token", "tok-abc"]]);
  assert.equal(storage.dump()["sitelens-token"], "tok-abc");

  // 读侧（tok）必须能读到刚写入的值，并拼成 X-Token 头
  const tok = extractFn(common, "tok", { localStorage: storage });
  assert.deepEqual(tok(), { "X-Token": "tok-abc" });
});

test("slStoreToken 空值 = 清除（removeItem），不是写入空串", () => {
  for (const empty of ["", "   ", null, undefined]) {
    const storage = mockStorage({ "sitelens-token": "old" });
    const store = extractWindowFn(common, "slStoreToken", { localStorage: storage });
    assert.equal(store(empty), "");
    assert.deepEqual(storage.calls, [["removeItem", "sitelens-token"]]);
    assert.equal(storage.dump()["sitelens-token"], undefined);
    const tok = extractFn(common, "tok", { localStorage: storage });
    assert.deepEqual(tok(), {});
  }
});

test("slReadToken 读回本机 token（无值返回空串）", () => {
  const withTok = mockStorage({ "sitelens-token": "x1" });
  assert.equal(extractWindowFn(common, "slReadToken", { localStorage: withTok })(), "x1");
  const noTok = mockStorage();
  assert.equal(extractWindowFn(common, "slReadToken", { localStorage: noTok })(), "");
});

test("设置页保存流程会调用 slStoreToken（写侧接线不丢失）", () => {
  // 保存处理器：从 $("save").addEventListener 到下一个顶层 addEventListener
  const at = settings.indexOf('$("save").addEventListener');
  assert.ok(at > 0, "settings.html 应存在保存按钮处理器");
  const tail = settings.slice(at);
  const end = tail.indexOf('$("osvBtn").addEventListener');
  const handler = end > 0 ? tail.slice(0, end) : tail;
  assert.match(handler, /slStoreToken\s*\(/, "保存成功后必须写入本机 token（否则又回到全站 401）");
  assert.match(handler, /nextToken/, "必须区分「新填 token」与「留空不改」");
  // 留空保存不得把已设置的 token 清掉
  assert.match(handler, /tokenState\.set/, "留空保存时应保留已有 token（旧引擎回写兼容）");
});

test("设置页不再把明文 token 回填到输入框", () => {
  assert.doesNotMatch(settings, /setv\("api_token",\s*c\.web\.api_token/, "禁止明文回填（F5 契约）");
  assert.match(settings, /api_token_set/, "应读取 F5 契约的 api_token_set 布尔");
  assert.match(settings, /type="password"\s+id="api_token"/, "token 输入框应为 password");
});

test("与 F5 契约对齐：api_token_set 取响应顶层字段（web 内为兼容回退）", () => {
  // internal/server/settings.go:233-238 —— api_token_set 放在响应顶层，
  // 且 web.api_token 被彻底摘除（nil + omitempty）。
  // 回填逻辑集中在纯函数 applySettings（便于 settings-shape.test.mjs 冒烟）。
  const at = settings.indexOf("function applySettings(");
  assert.ok(at > 0, "应存在 applySettings 回填函数");
  const block = settings.slice(at, settings.indexOf("window.api.get(\"/api/settings\")"));
  assert.match(block, /c\.api_token_set\s*===?\s*true/, "主判据必须是响应顶层的 c.api_token_set");
  assert.match(block, /w\.api_token_set\s*===?\s*true/, "保留 web 内层的兼容回退");
  assert.match(block, /c\.listen != null \? c\.listen : w\.listen/, "listen 必须兼容扁平/旧形态");
  // 保存成功后应以服务端回执为准（PUT 响应带 api_token_set / token_cleared）
  const saveAt = settings.indexOf('$("save").addEventListener');
  const saveBlock = settings.slice(saveAt, settings.indexOf('$("osvBtn").addEventListener'));
  assert.match(saveBlock, /resp\.api_token_set/, "保存后应读取回执里的 api_token_set");
  assert.match(saveBlock, /token_cleared/, "显式清除时回执有 token_cleared，应据此提示");
});

test("PUT /api/settings 不再无条件发送 api_token", () => {
  assert.doesNotMatch(
    settings,
    /web:\s*\{\s*listen:\s*getv\("listen"\),\s*api_token:\s*getv\("api_token"\)/,
    "旧写法会无条件把输入框值（常为空）当新 token 提交，从而清掉已设置的 token",
  );
  assert.match(settings, /var web = \{ listen: getv\("listen"\) \}/, "web 段应单独构造");
});

/* =========================================================================
   F5 收尾：CSRF 自定义头 X-Requested-With: sitelens
   -------------------------------------------------------------------------
   internal/server/origin_guard.go 的 requireCSRFHeaderStrict 打开后，危险端点
   （PUT /api/settings、POST /api/history/clear、/api/batch/schedules*、
   /api/admin/*）必须带该自定义头。前端所有请求都必须走 slHeaders()。
   ========================================================================= */

/** 抽取 slHeaders 并注入它依赖的三个自由变量。 */
function makeSlHeaders(storage) {
  const tok = extractFn(common, "tok", { localStorage: storage });
  const m = common.match(/window\.slHeaders = function[\s\S]*?\n  \};/);
  if (!m) throw new Error("common.js 中未找到 window.slHeaders 定义");
  const fnText = m[0].replace("window.slHeaders = ", "").replace(/;\s*$/, "");
  const nameM = common.match(/var CSRF_HEADER_NAME = "([^"]+)";/);
  const valueM = common.match(/var CSRF_HEADER_VALUE = "([^"]+)";/);
  if (!nameM || !valueM) throw new Error("common.js 中未找到 CSRF 头常量");
  return new Function("tok", "CSRF_HEADER_NAME", "CSRF_HEADER_VALUE",
    "return (" + fnText + ")")(tok, nameM[1], valueM[1]);
}

test("slHeaders：始终带 X-Requested-With: sitelens（CSRF 显式头）", () => {
  const h = makeSlHeaders(mockStorage())();
  assert.deepEqual(h, { "X-Requested-With": "sitelens" });
});

test("slHeaders：有 token 时同时带 X-Token；extra 头合并", () => {
  const h = makeSlHeaders(mockStorage({ "sitelens-token": "tok-1" }))();
  assert.deepEqual(h, { "X-Requested-With": "sitelens", "X-Token": "tok-1" });

  const withExtra = makeSlHeaders(mockStorage())(
    { "Content-Type": "application/json" });
  assert.deepEqual(withExtra, {
    "X-Requested-With": "sitelens",
    "Content-Type": "application/json",
  });
  // extra 不得覆盖 CSRF 头为任意值（调用方只传业务头）
  const merged = makeSlHeaders(mockStorage())(
    { "Content-Type": "application/json", "X-Token": "explicit" });
  assert.equal(merged["X-Requested-With"], "sitelens");
  assert.equal(merged["X-Token"], "explicit");
});

test("所有 API 请求都走 slHeaders（api.* / slDownload / 裸 fetch 的 apiTok）", () => {
  // api.get / request（POST/PUT/DELETE 共用）/ slDownload
  assert.match(common, /function request\(method, u, d\) \{[\s\S]*?headers: window\.slHeaders\(\{ "Content-Type": "application\/json" \}\)/,
    "request() 必须带 CSRF 头");
  assert.match(common, /get: function \(u\) \{ return fetch\(u, \{ headers: window\.slHeaders\(\) \}\)/,
    "api.get 必须带 CSRF 头");
  assert.match(common, /window\.slDownload = function[\s\S]*?fetch\(url, \{ headers: window\.slHeaders\(\) \}\)/,
    "slDownload 必须带 CSRF 头");
  assert.match(common, /window\.apiTok = window\.slHeaders;/, "裸 fetch 用的 apiTok 必须是 slHeaders");
  // 裸 fetch 调用点（FormData 上传 / 图查询）不得再直接传 tok()
  const audit = readFileSync(new URL("js/audit.js", root), "utf8");
  const chain = readFileSync(new URL("chain.html", root), "utf8");
  assert.match(audit, /fetch\("\/api\/audit", \{ method: "POST", headers: apiTok\(\)/, "审计上传必须用 apiTok()");
  for (const line of chain.split(/\r?\n/)) {
    if (!/\bfetch\(/.test(line)) continue;
    assert.match(line, /headers: apiTok\(\)/, `chain.html 的裸 fetch 必须用 apiTok()：${line.trim()}`);
  }
});

/* =========================================================================
   A-01/D-02：URL fragment token 引导
   -------------------------------------------------------------------------
   桌面壳把引擎的 web.api_token 经 URL fragment 交给前端；common.js 必须在
   任何 API 请求前识别 → 存入本机 → 立刻抹掉地址栏 fragment（token 不得停留
   在可截图/可复制的 URL 里）。非法格式只清理、不写入。
   ========================================================================= */

/** 抽取 bootstrapTokenFromFragment(loc, store, replace)（带参函数，需单独匹配）。 */
function extractBootstrap() {
  const m = common.match(/function bootstrapTokenFromFragment\(loc, store, replace\) \{[\s\S]*?\n  \}/);
  if (!m) throw new Error("common.js 中未找到 bootstrapTokenFromFragment");
  return new Function("return (" + m[0] + ")")();
}

test("bootstrap：合法 #token=64hex → 写入存储并从地址栏抹掉 fragment", () => {
  const fn = extractBootstrap();
  const tok64 = "a".repeat(64);
  const stored = [];
  const replaced = [];
  const ok = fn(
    { hash: "#token=" + tok64, pathname: "/settings.html", search: "?tab=engine" },
    (v) => stored.push(v),
    (u) => replaced.push(u),
  );
  assert.equal(ok, true);
  assert.deepEqual(stored, [tok64], "合法 token 必须交给 slStoreToken");
  assert.deepEqual(replaced, ["/settings.html?tab=engine"], "fragment 必须被清除且保留 path+query");
});

test("bootstrap：无 fragment → 不写不清理", () => {
  const fn = extractBootstrap();
  const stored = [];
  const replaced = [];
  assert.equal(fn({ hash: "", pathname: "/app.html", search: "" }, (v) => stored.push(v), (u) => replaced.push(u)), false);
  assert.equal(fn({ hash: "#scan", pathname: "/app.html", search: "" }, (v) => stored.push(v), (u) => replaced.push(u)), false);
  assert.deepEqual(stored, []);
  assert.deepEqual(replaced, []);
});

test("bootstrap：非法 token（长度/字符集不符）→ 只清理不写入", () => {
  const fn = extractBootstrap();
  for (const bad of ["#token=short", "#token=" + "z".repeat(64), "#token=" + "a".repeat(63), "#token="]) {
    const stored = [];
    const replaced = [];
    const ok = fn({ hash: bad, pathname: "/x", search: "" }, (v) => stored.push(v), (u) => replaced.push(u));
    assert.equal(ok, false, bad + " 不应被接受");
    assert.deepEqual(stored, [], bad + " 不得写入存储");
    assert.deepEqual(replaced, ["/x"], bad + " 的 fragment 仍须清除");
  }
});

test("bootstrap：大写 hex 归一化为小写（服务端比较不区分大小写，存储统一）", () => {
  const fn = extractBootstrap();
  const stored = [];
  const up = "AB".repeat(32);
  assert.equal(fn({ hash: "#token=" + up, pathname: "/", search: "" }, (v) => stored.push(v), () => {}), true);
  assert.deepEqual(stored, [up.toLowerCase()]);
});
