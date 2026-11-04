// 外壳脚本冒烟：防止 common.js 早期异常导致整个壳（顶栏/模式行）不渲染。
// 背景：FE-04 引入 SL.* 全局状态但漏了定义，common.js 在 SL.globalReady 处
// 抛错，后续 api/initCDD 定义全部跳过 → 顶栏导航消失、app.js/batch.js 报
// "api is not defined"。本测试静态锚定"先定义、后使用"，避免回归。
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

const common = readFileSync(new URL("../web/js/common.js", import.meta.url), "utf8");
const appHtml = readFileSync(new URL("../web/app.html", import.meta.url), "utf8");
// 注释里也会出现 SL.xxx 字样，比较前先剥掉注释，只看真实代码。
const code = common
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\/\/[^\n]*/g, "");

test("common.js 先定义 SL 再使用", () => {
  const def = code.indexOf("var SL = window.SL");
  const firstUse = code.search(/\bSL\./);
  assert.ok(def >= 0, "common.js 必须定义 var SL = window.SL = ...");
  assert.ok(firstUse >= 0, "common.js 应使用 SL.*");
  assert.ok(def < firstUse, `SL 定义位置(${def})必须早于首次使用(${firstUse})`);
});

test("common.js 提供壳依赖的公共入口", () => {
  for (const sym of ["window.api =", "window.initCDD =", "window.slT", "window.slUpdateNav"]) {
    assert.ok(common.includes(sym), `common.js 缺少 ${sym}`);
  }
});

test("app.html 脚本顺序：common.js 先于 app.js/batch.js", () => {
  const iCommon = appHtml.indexOf("/js/common.js");
  const iApp = appHtml.indexOf("/js/app.js");
  const iBatch = appHtml.indexOf("/js/batch.js");
  assert.ok(iCommon >= 0 && iApp > iCommon, "common.js 必须在 app.js 之前");
  assert.ok(iBatch > iCommon, "common.js 必须在 batch.js 之前");
});
// 桌面形态判定回归：Wails 运行时（window._wails）可能晚于 bridge.js 执行，
// 若在脚本加载瞬间把 available 固化成 !!post，桌面版会被误判成「浏览器模式」
// （关于与更新页显示浏览器模式、桌面端页签隐藏、检查更新跳发布页）。
// 5.2.3 实机事故：bridge.js 加载时 _wails 尚未注入 → available=false。
const bridge = readFileSync(new URL("../web/js/bridge.js", import.meta.url), "utf8");
const settingsHtml = readFileSync(new URL("../web/settings.html", import.meta.url), "utf8");

test("bridge.js 桌面形态判定必须动态（不能固化加载瞬间的 window._wails）", () => {
  assert.ok(bridge.includes("function shellReady()"), "bridge.js 缺少 shellReady()");
  assert.ok(!bridge.includes("var available = !!post;"), "available 不得在加载瞬间固化为 !!post");
  assert.match(bridge, /available:\s*shellReady\(\)/, "api.available 必须走 shellReady()");
  assert.match(bridge, /if \(!shellReady\(\)\)/, "写动作应实时判断 shellReady()");
  // si 注入（壳静态信息）本身即桌面壳证据：加载时 _wails 未注入也要判桌面
  assert.match(bridge, /function shellReady\(\) \{ return !!\(info \|\| postFn\(\)\); \}/,
    "shellReady 应以 si 注入或桥可用为准");
});

test("设置页「关于与更新」用 available 判定桌面/浏览器", () => {
  assert.match(settingsHtml, /window\.sitelens && window\.sitelens\.available/,
    "设置页必须用 window.sitelens.available 判定桌面形态");
  assert.match(settingsHtml, /"桌面版" : "浏览器模式"/, "缺少桌面版/浏览器模式文案分支");
});
test("关于与更新：只展示当前形态的更新说明（避免桌面版误读浏览器模式文案）", () => {
  assert.match(settingsHtml, /id="updNoteDesktop"/, "缺少桌面版更新说明节点");
  assert.match(settingsHtml, /id="updNoteBrowser"/, "缺少浏览器模式更新说明节点");
  assert.match(settingsHtml, /d\.style\.display = isDesktop/, "桌面版说明未按形态切换");
  assert.match(settingsHtml, /b\.style\.display = isDesktop \? "none"/, "浏览器说明未按形态隐藏");
  assert.match(settingsHtml, /turbo:load", slEnsureShellMode/, "Turbo 导航后未重算形态");
  assert.match(settingsHtml, /s\.src = "\/js\/bridge\.js"/, "bridge.js 缺失时未补加载");
});
test("桌面端页签：桥晚就绪时也要补上（Turbo 导航外部脚本异步）", () => {
  assert.match(settingsHtml, /function ensureDesktopTab\(\)/, "缺少 ensureDesktopTab");
  assert.match(settingsHtml, /window\.slEnsureDesktopTab = ensureDesktopTab/, "未暴露补页签入口");
  assert.match(settingsHtml, /setTimeout\(ensureDesktopTab, ms\)/, "缺少桥就绪后的重试");
  assert.match(settingsHtml, /document\.addEventListener\("turbo:load", ensureDesktopTab\)/, "Turbo 导航后未重试补页签");
});