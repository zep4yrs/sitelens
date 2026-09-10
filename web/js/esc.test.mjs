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
