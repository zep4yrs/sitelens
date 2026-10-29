// API 错误分级回归测试（node --test 运行）。
// 方式：从 common.js 源码中提取 asJson / apiError 的**真实实现**并在此重建——
// 测试的是真实代码，不是复制品。
//
// 背景（BUG-034）：此前 asJson 不区分「网络失败 / HTTP 错误 / 响应非 JSON」
// 三种情况，网络失败时抛的是浏览器原生的 "Failed to fetch"——不带 URL、
// 不带状态码、不带原因；再加上一堆 .catch(function(){}) 把异常静默吞掉，
// 用户只看到一行红字，界面毫无反应。
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./common.js', import.meta.url), 'utf8');

function grab(re, what) {
  const m = src.match(re);
  if (!m) throw new Error('common.js 中未找到：' + what);
  return m[0];
}
const apiErrorSrc = grab(/function apiError\(url, kind, detail\) \{[\s\S]*?\n  \}/, 'apiError');
const asJsonSrc = grab(/function asJson\(r, url\) \{[\s\S]*?\n  \}/, 'asJson');
// clearEngineDown 是同文件里的界面态清理函数（成功路径会调它撤掉「无响应」遮罩），
// 与本用例的断言无关——给个空实现即可。
const asJson = new Function(
  'function clearEngineDown() {}\n' + apiErrorSrc + '\n' + asJsonSrc + '\nreturn asJson;'
)();

/** 构造一个 Response 替身：text() 返回给定正文（成功）或 reject（网络失败）。 */
function mockResp(opts = {}) {
  const { ok = true, status = 200, text = '{}', fail = false } = opts;
  return {
    ok,
    status,
    text: () => (fail ? Promise.reject(new TypeError('Failed to fetch')) : Promise.resolve(text)),
  };
}

test('网络失败：报「无法连接引擎服务」并带 URL，不出现裸的 Failed to fetch', async () => {
  const err = await asJson(mockResp({ fail: true }), '/api/job/abc/results').catch((e) => e);
  assert.ok(err instanceof Error, '应抛出 Error');
  assert.match(err.message, /无法连接引擎服务/, '应说明是引擎连不上');
  assert.match(err.message, /\/api\/job\/abc\/results/, '错误信息应带请求 URL');
  assert.ok(!/Failed to fetch/.test(err.message), '不应把浏览器的裸文案直接抛给用户');
});

test('HTTP 错误：透传服务端的 error 字段，并带 URL 与状态码', async () => {
  const err = await asJson(
    mockResp({ ok: false, status: 500, text: JSON.stringify({ error: '引擎内部错误' }) }),
    '/api/scan'
  ).catch((e) => e);
  assert.match(err.message, /引擎返回错误/);
  assert.match(err.message, /引擎内部错误/, '应透传服务端给出的原因');
  assert.match(err.message, /\/api\/scan/, '错误信息应带请求 URL');
});

test('HTTP 错误但响应非 JSON：退化为状态码文案，仍带 URL', async () => {
  const err = await asJson(mockResp({ ok: false, status: 502, text: '<html>502</html>' }), '/api/stats')
    .catch((e) => e);
  assert.match(err.message, /引擎返回错误/);
  assert.match(err.message, /502/, '应带状态码');
  assert.match(err.message, /\/api\/stats/);
});

test('响应非 JSON（被网关/代理替换）：报格式异常，不抛 Unexpected token', async () => {
  const err = await asJson(mockResp({ text: '<!doctype html><html>hi</html>' }), '/api/version')
    .catch((e) => e);
  assert.match(err.message, /响应格式异常/);
  assert.match(err.message, /\/api\/version/);
  assert.ok(!/Unexpected token/.test(err.message), '不应把解析器的裸文案抛给用户');
});

test('成功：原样返回解析后的 JSON', async () => {
  const j = await asJson(mockResp({ text: JSON.stringify({ version: '5.1.0' }) }), '/api/version');
  assert.equal(j.version, '5.1.0');
});
