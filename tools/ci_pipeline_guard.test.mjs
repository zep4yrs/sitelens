// CI 配置门禁：把「容器内跑 wine 必须带虚拟显示」固化成断言——
// 历史事故（tag 构建在 wine process failed 处中断）的根因是
// 32 位 PE 在没有 display driver 时秒退（err:winediag:nodrv_CreateWindow），
// 而不是缺 32 位库。行为一致性靠测试守住，不靠注释。
//
// node --test 运行（Node 22+ 无参自动发现；带目录参数会被当模块路径）。
import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";

const cnb = readFileSync(new URL("../.cnb.yml", import.meta.url), "utf8");
const nsisHelper = readFileSync(new URL("./ci_nsis_exe.sh", import.meta.url), "utf8");

/** 取出 v* tag 触发的那一节（wine / NSIS 相关 job 都在这里） */
function tagSection() {
  const i = cnb.indexOf('"v*":');
  assert.ok(i > 0, "未找到 v* tag 流水线节");
  return cnb.slice(i);
}

test("所有 wine 调用都套了 xvfb-run（无 display driver 时必须）", () => {
  const section = tagSection();
  // 逐行取「实际会执行的命令」：先剥掉注释与空行，再看该行是否调用 wine
  const bare = section
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    // wine / wine64 / wineboot 作为独立命令词出现即算一次 wine 调用
    .filter((l) => /(^|[\s;|&(])wine(64|boot)?([\s;|&)]|$)/.test(l))
    // 安装行（apt-get install ... wine wine64）不是调用
    .filter((l) => !/^(-\s*)?apt-get\b/.test(l))
    .filter((l) => !l.includes("xvfb-run"));
  assert.deepStrictEqual(
    bare,
    [],
    `以下 wine 调用缺少 xvfb-run:\n  ${bare.join("\n  ")}`
  );
});

test("electron-builder 调用（隐式经 wine）也必须在 xvfb-run 下", () => {
  const section = tagSection();
  const eb = section
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    // 只认真正的调用：行首/管道后是 electron-builder 或 npx electron-builder
    .filter((l) => /(^|[\s;|&(])(npx\s+)?electron-builder([\s;|&)]|$)/.test(l))
    // 排除 ELECTRON_BUILDER_* 环境变量行
    .filter((l) => !/^export\s+ELECTRON_/.test(l));
  assert.ok(eb.length > 0, "未找到 electron-builder 调用");
  for (const l of eb) {
    assert.ok(l.includes("xvfb-run"), `electron-builder 调用缺少 xvfb-run: ${l}`);
  }
});

test("tag 流水线安装了 xvfb（含 xauth，xvfb-run 依赖它）", () => {
  assert.match(tagSection(), /apt-get install[^\n]*\bxvfb\b/, "未安装 xvfb");
  assert.match(tagSection(), /apt-get install[^\n]*\bxauth\b/, "未安装 xauth");
});

test("lite / full 的 makensis 统一走 tools/ci_nsis_exe.sh", () => {
  const section = tagSection();
  const calls = section.match(/bash tools\/ci_nsis_exe\.sh[^\n]*/g) || [];
  assert.equal(calls.length, 2, `期望 lite/full 各一次，实际 ${calls.length} 次`);
  // 不允许再有裸 makensis 调用（LANG=C.UTF-8 的坑已在脚本内处理）
  const naked = section.split("\n").filter((l) => /^\s*[-\s]*LANG=.*makensis/.test(l));
  assert.deepStrictEqual(naked, [], "仍有裸 makensis 调用，应改走 ci_nsis_exe.sh");
});

test("环境变量前置导出：electron-builder 相关 export 必须在 npm ci 之前", () => {
  const section = tagSection();
  const iExport = section.indexOf("export ELECTRON_MIRROR");
  const iNpm = section.indexOf("npm ci");
  assert.ok(iExport > 0, "未找到 ELECTRON_MIRROR 导出");
  assert.ok(iNpm === -1 || iExport < iNpm, "ELECTRON_MIRROR 必须早于 npm ci");
});

test("ci_nsis_exe.sh：makensis 带 UTF-8 locale，且不拿 wine 退出码当成败判据", () => {
  assert.match(nsisHelper, /LANG=C\.UTF-8\s+LC_ALL=C\.UTF-8\s+makensis/, "缺 UTF-8 locale");
  assert.match(nsisHelper, /xvfb-run -a/, "缺 xvfb-run");
  assert.match(nsisHelper, /-s "\$OUTFILE"/, "缺产物非空校验");
});

test("lite / full 的 tar 解包必须 --no-same-owner（跨平台属主）", () => {
  const section = tagSection();
  const tars = section.split("\n").filter((l) => /\btar\s/.test(l) && /\.tar\.gz/.test(l));
  assert.ok(tars.length > 0, "未找到 tar 解包行");
  for (const t of tars) {
    assert.match(t, /--no-same-owner/, `tar 解包缺少 --no-same-owner: ${t.trim()}`);
  }
});
