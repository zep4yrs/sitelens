// esc() 转义函数的行为回归测试（node --test 运行）。
// 方式：从 common.js 源码中提取 window.esc 真实实现并在此处重建——
// 测试的是真实代码，不是复制品。
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./common.js', import.meta.url), 'utf8');
const m = src.match(/window\.esc = function[\s\S]*?\n  \};/);
if (!m) throw new Error('common.js 中未找到 window.esc 定义');
const fnText = m[0].replace('window.esc = ', '').replace(/;\s*$/, '');
const esc = new Function('return (' + fnText + ')')();

test('esc 转义五种危险字符（含单引号与反引号）', () => {
  const out = esc(`x' onmouseover=alert(1) y='`);
  assert.ok(out.includes('&#39;'), `单引号应被转义: ${out}`);
  assert.ok(!out.includes(`'`), `单引号不应原样保留: ${out}`);
  assert.equal(esc('`'), '&#96;');
  assert.equal(esc('"'), '&quot;');
  assert.equal(esc('<'), '&lt;');
});

test('esc 保持普通文本不变', () => {
  assert.equal(esc('hello 世界 123'), 'hello 世界 123');
});

test('esc 处理 null/undefined/空串', () => {
  assert.equal(esc(null), '');
  assert.equal(esc(''), '');
});

/* =========================================================================
   D-15：JS 字符串上下文（内联事件处理器）的转义维度
   -------------------------------------------------------------------------
   为什么需要单独一套用例：esc() 的语义是「HTML 转义」，而浏览器会把属性值
   **先做实体解码、再交给 JS 解析**。所以
       onclick="f(' + esc(v) + ')"
   对 v = x');alert(1)// 仍然可被利用（D-03 的真实成因）。
   escJs() 产出的是「HTML 转义后的 JSON 字符串字面量」，解码后是合法 JS
   字符串——下面用「解码 → new Function → 捕获实参」的方式证明注入串只能
   作为一个字符串参数存在，无法变成可执行语句。
   ========================================================================= */

const mJs = src.match(/window\.escJs = function[\s\S]*?\n  \};/);
if (!mJs) throw new Error('common.js 中未找到 window.escJs 定义');
const escJsText = mJs[0].replace('window.escJs = ', '').replace(/;\s*$/, '');
// escJs 内部调用 window.esc(...)：给它一个只带 esc 的 sandbox 当 window
const escJs = new Function('window', 'return (' + escJsText + ')')({ esc });

/** 浏览器对 HTML 属性值做的实体解码（只覆盖 esc/escJs 会产出的实体）。 */
function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#96;/g, '`');
}

/** 把「HTML 属性值」还原成浏览器实际交给 JS 解析的代码，并取出 f 的实参。
 *  真实标记是 onclick="f(<escJs 输出>)"，属性值 = "f(" + attr + ")"。 */
function argPassedToF(attrValue) {
  const code = decodeEntities('f(' + attrValue + ')'); // 浏览器行为：先解码
  const calls = [];
  const f = (x) => { calls.push(x); };
  new Function('f', code)(f); // 再按 JS 解析执行（只有 f(...) 一条语句）
  assert.equal(calls.length, 1, `注入串逃逸出了字符串参数：${code}`);
  return calls[0];
}

const HOSTILE = [
  `x');alert(1);//`,
  `");alert(1);//`,
  `');document.location='http://evil.example'//`,
  `a\\`,
  `back\\slash"quote'`,
  `line1\nline2\r\nline3`,
  `</script><img src=x onerror=alert(1)>`,
  `{ "json": "looking" }`,
  `\u2028\u2029`,
];

test('escJs：注入串无法逃逸 JS 字符串（解码后仍是单个字符串实参）', () => {
  for (const payload of HOSTILE) {
    const attr = escJs(payload); // 放进 onclick="f(<attr>)" 的正是这段
    assert.equal(argPassedToF(attr), payload, `payload 应原样成为字符串实参: ${payload}`);
  }
});

test('escJs：输出是 HTML 转义过的 JSON 字面量（不含裸引号）', () => {
  const out = escJs(`x');alert(1)//`);
  assert.ok(out.includes('&quot;'), `应带 HTML 转义的引号: ${out}`);
  assert.ok(!/['`]/.test(out), `不应残留单引号/反引号: ${out}`);
  assert.ok(!/[\r\n]/.test(out), `不应含裸换行: ${out}`);
  assert.equal(escJs(null), '&quot;&quot;');
  assert.equal(escJs(undefined), '&quot;&quot;');
  assert.equal(escJs(42), '&quot;42&quot;');
});

test('回归证明：只用 esc() 挡不住 JS 字符串上下文（这就是 escJs 存在的理由）', () => {
  const payload = `x');alert(1);//`;
  // 旧写法：onclick="f('<esc(payload)>')" → 属性值 f('x&#39;);alert(1);//') → 解码后：
  const code = decodeEntities("f('" + esc(payload) + "')");
  assert.equal(code, "f('x');alert(1);//')", '解码后应提前闭合字符串');
  let ran = false;
  const f = () => {};
  const alertStub = () => { ran = true; };
  new Function('f', 'alert', code)(f, alertStub);
  assert.ok(ran, `esc() 单独使用时注入串会执行（证明缺口真实存在）：${code}`);
});

