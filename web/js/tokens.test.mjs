// 设计令牌门禁（对应 open-claude-ui 的 check:tokens 思路）：
// tokens.css 是颜色/圆角/间距/阴影/字体/动效的唯一来源；app.css 只许 var() 消费。
// 这里在 CI 里守住两件事：
//   1) app.css 里每个 var(--x) 都在 tokens.css 有定义（防拼错/防漂移）；
//   2) tokens.css 只允许 :root / .dark 令牌块（不许混入组件样式）；
//   3) 颜色类令牌浅/深两套都要有（防只改浅色漏深色）。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tokens = readFileSync(join(root, "css/tokens.css"), "utf8");
const app = readFileSync(join(root, "css/app.css"), "utf8");

function definitions(css) {
  const out = new Set();
  for (const m of css.matchAll(/(^|[;{,\s])(--[a-zA-Z0-9-]+)\s*:/g)) out.add(m[2]);
  return out;
}

function usages(css) {
  const out = new Set();
  for (const m of css.matchAll(/var\(\s*(--[a-zA-Z0-9-]+)/g)) out.add(m[1]);
  return out;
}

test("app.css 引用的令牌全部在 tokens.css 定义", () => {
  const defined = definitions(tokens);
  const missing = [...usages(app)].filter((n) => !defined.has(n));
  assert.deepEqual(missing, [], "未定义令牌（先在 tokens.css 补，再在 app.css 用）: " + missing.join(", "));
});

test("tokens.css 只包含 :root / .dark 令牌块", () => {
  const selectors = [...tokens.matchAll(/([^{}]+)\{/g)]
    .map((m) => m[1].replace(/\/\*[\s\S]*?\*\//g, "").trim())
    .filter(Boolean);
  const bad = selectors.filter((s) => !/^(:root|\.dark)$/.test(s));
  assert.deepEqual(bad, [], "tokens.css 不应出现组件选择器: " + bad.join(" | "));
});

test("颜色令牌浅色/深色两套齐全", () => {
  const idx = tokens.search(/^\.dark\s*\{/m);
  assert.ok(idx > 0, "tokens.css 缺少 .dark 深色块");
  const light = tokens.slice(0, idx);
  const dark = tokens.slice(idx);
  const colorTokens = [
    "--background", "--foreground", "--card", "--muted", "--accent", "--secondary",
    "--muted-fg", "--border", "--input", "--ring", "--primary", "--primary-fg",
    "--ok", "--warn", "--danger", "--info",
  ];
  const lightMissing = colorTokens.filter((n) => !new RegExp(n + "\\s*:").test(light));
  const darkMissing = colorTokens.filter((n) => !new RegExp(n + "\\s*:").test(dark));
  assert.deepEqual(lightMissing, [], "浅色缺少颜色令牌: " + lightMissing.join(", "));
  assert.deepEqual(darkMissing, [], "深色缺少颜色令牌: " + darkMissing.join(", "));
});

test("动效令牌三档齐全且带签名缓动", () => {
  for (const n of ["--t-fast", "--t-med", "--t-slow", "--ease"]) {
    assert.match(tokens, new RegExp(n + "\\s*:"), "缺少动效令牌 " + n);
  }
});
