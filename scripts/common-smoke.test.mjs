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
