// 前端质量门禁自身的回归（node --test scripts/frontend-check.test.mjs）
// 用临时目录造好/坏两份 HTML，断言脚本的退出码与规则命中，防止门禁「静默失效」。
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const checker = join(here, "frontend-check.mjs");

function makeRoot(files) {
  const root = mkdtempSync(join(tmpdir(), "sl-fe-check-"));
  mkdirSync(join(root, "web"));
  for (const [name, html] of Object.entries(files)) {
    writeFileSync(join(root, "web", name), html, "utf8");
  }
  return root;
}

function run(root, extraArgs = []) {
  return spawnSync(process.execPath, [checker, "--root", root, ...extraArgs], {
    encoding: "utf8",
  });
}

const GOOD = `<!DOCTYPE html><html lang="zh-CN"><head><title>ok</title></head><body>
<button type="button">开始扫描</button>
<button type="button" aria-label="关闭">✕</button>
<img src="a.png" alt="">
<input id="q" aria-label="搜索">
<label for="name">名称</label><input id="name">
<label>邮箱<input type="email"></label>
<input type="hidden" id="h">
<input type="submit" value="提交">
<textarea aria-label="备注"></textarea>
</body></html>`;

const BAD = `<!DOCTYPE html><html lang="zh-CN"><head><title>bad</title></head><body>
<button type="button"></button>
<button type="button"><svg viewBox="0 0 1 1"></svg></button>
<img src="a.png">
<input id="x">
<textarea id="y"></textarea>
</body></html>`;

test("好页面：门禁通过（exit 0）", () => {
  const root = makeRoot({ "ok.html": GOOD });
  try {
    const r = run(root);
    assert.equal(r.status, 0, "应通过，实际输出:\n" + r.stdout + r.stderr);
    assert.match(r.stdout, /通过/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("坏页面：三类错误全部命中且 exit 1", () => {
  const root = makeRoot({ "bad.html": BAD });
  try {
    const r = run(root);
    assert.equal(r.status, 1, "应失败，实际输出:\n" + r.stdout + r.stderr);
    assert.match(r.stdout, /E-BUTTON-NAME/);
    assert.match(r.stdout, /E-IMG-ALT/);
    assert.match(r.stdout, /E-INPUT-LABEL/);
    assert.match(r.stdout, /不通过/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("--json 输出可被 CI 消费", () => {
  const root = makeRoot({ "bad.html": BAD });
  try {
    const r = run(root, ["--json"]);
    assert.equal(r.status, 1);
    const data = JSON.parse(r.stdout);
    assert.ok(Array.isArray(data.errors));
    assert.ok(data.errors.some((e) => e.rule === "E-BUTTON-NAME"));
    assert.equal(data.files, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("inline onclick 默认警告；--strict-onclick 升级为错误", () => {
  const html = `<!DOCTYPE html><html><head><title>x</title></head><body>
<button type="button" onclick="go()">执行</button></body></html>`;
  const root = makeRoot({ "click.html": html });
  try {
    const warn = run(root);
    assert.equal(warn.status, 0, "默认 onclick 只是警告");
    assert.match(warn.stdout, /W-ONCLICK/);
    const strict = run(root, ["--strict-onclick"]);
    assert.equal(strict.status, 1, "--strict-onclick 应失败");
    assert.match(strict.stdout, /E-ONCLICK/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("script/style 内的 < 与 HTML 字符串不被当作标签解析", () => {
  const html = `<!DOCTYPE html><html><head><title>x</title></head><body>
<script>for (var i=0;i<list.length;i++){ el.innerHTML = '<button></button>'; }</script>
<style>.a::after{content:"<b>"}</style>
<button type="button">正常按钮</button></body></html>`;
  const root = makeRoot({ "raw.html": html });
  try {
    const r = run(root);
    assert.equal(r.status, 0, "script 内的字符串不应产生误报，实际输出:\n" + r.stdout + r.stderr);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
