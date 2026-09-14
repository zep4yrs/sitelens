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

/**
 * tag 流水线是否处于**启用**状态。
 *
 * v3.0.1 起发版改为本地（tools/release_local.sh）——原因是 CI 在 Linux 上构建
 * 出的「sitelens.exe」实为 ELF 二进制（build-engine.js 当时未设 GOOS），
 * 装进 Windows 包后引擎起不来。原 tag 流水线已整体注释保留（见 .cnb.yml 说明）。
 *
 * 本判定的意义：**停用时明确跳过（不是静默通过）**；一旦有人取消注释重新启用，
 * 下列 wine / xvfb / 裸包 / 平台相关断言立即恢复生效——守护不失效。
 */
function tagPipelineActive() {
  // 活跃形态：行首（允许前导空格）为 "v*": 且未被 # 注释
  return /^\s*"v\*":\s*$/m.test(cnb);
}

/** 停用时跳过（带明确原因），启用时返回 false 继续断言。 */
function skipIfRetired(t) {
  if (!tagPipelineActive()) {
    t.skip("tag 流水线已停用：发版改为本地 tools/release_local.sh（CI 在 Linux 构建的 exe 实为 ELF，见 .cnb.yml 说明）");
    return true;
  }
  return false;
}

test("所有 wine 调用都套了 xvfb-run（无 display driver 时必须）", (t) => {
  if (skipIfRetired(t)) return;
  const section = tagSection();
  // 逐行取「实际会执行的命令」：先剥掉注释与空行，再看该行是否调用 wine
  const bare = section
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    // wine / wine64 / wineboot 作为独立命令词出现即算一次 wine 调用
    .filter((l) => /(^|[\s;|&(])wine(64|boot)?([\s;|&)]|$)/.test(l))
    // 安装行（apt-get install ... wine wine64）与其反斜杠续行不是调用
    .filter((l) => !/^(-\s*)?apt-get\b/.test(l))
    .filter((l) => !/^(wine|libwine|fonts-wine)\S*\s.*>\s*\/dev\/null\s*$/.test(l))
    .filter((l) => !l.includes("xvfb-run"));
  assert.deepStrictEqual(
    bare,
    [],
    `以下 wine 调用缺少 xvfb-run:\n  ${bare.join("\n  ")}`
  );
});

test("electron-builder 调用（隐式经 wine）也必须在 xvfb-run 下", (t) => {
  if (skipIfRetired(t)) return;
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

test("tag 流水线安装了 xvfb（含 xauth，xvfb-run 依赖它）", (t) => {
  if (skipIfRetired(t)) return;
  assert.match(tagSection(), /apt-get install[^\n]*\bxvfb\b/, "未安装 xvfb");
  assert.match(tagSection(), /apt-get install[^\n]*\bxauth\b/, "未安装 xauth");
});

test("流水线不再产出引擎裸包（4.0 起桌面版是唯一交付形态）", (t) => {
  if (skipIfRetired(t)) return;
  const section = tagSection();
  // lite / full / linux 打包 stage 已移除：构建/上传指令里不得再引入
  assert.ok(!section.includes("ci_nsis_exe.sh"), "不应再有 makensis 裸包构建");
  // 上传只有一条路：v3.0.0 版本页 exe（release_upload.sh，带重试）。
  // CNB 不做自动更新源（desktop-stable 已删，更新源唯一在 GitHub）。
  const uploads = section.split("\n").filter((l) => l.includes("release_upload.sh"));
  const replaces = section.split("\n").filter((l) => l.includes("release_replace.sh"));
  assert.strictEqual(uploads.length, 1, `版本页上传应为 1 条，实际 ${uploads.length}`);
  assert.strictEqual(replaces.length, 0, "CNB 不做更新源，不应有 desktop-stable 替换步骤");
  for (const l of uploads) {
    assert.ok(!/lite|setup-lite|setup-full|full-win64|linux-amd64/.test(l),
      `上传指令不应涉及裸包: ${l.trim()}`);
  }
  // 版本页安装包与发行说明（SHA256 占位符）必须就位；CNB 不传 latest.yml/blockmap
  assert.match(section, /SiteLens-Setup-3\.0\.0\.exe/);
  assert.match(section, /__SHA256__/, "发行说明 SHA256 占位符替换步骤缺失");
  assert.match(section, /SITLENS_BODY_FILE/, "发行说明未挂载");
  assert.ok(!/release_upload\.sh[^\n]*latest\.yml/.test(section), "CNB 不应上传 latest.yml（更新源在 GitHub）");
});

test("环境变量前置导出：electron-builder 相关 export 必须在 npm ci 之前", (t) => {
  if (skipIfRetired(t)) return;
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

test("tag 流水线如出现 tar 解包必须 --no-same-owner（跨平台属主）", (t) => {
  if (skipIfRetired(t)) return;
  const section = tagSection();
  const tars = section.split("\n").filter((l) => /\btar\s/.test(l) && /\.tar\.gz/.test(l));
  for (const t of tars) {
    assert.match(t, /--no-same-owner/, `tar 解包缺少 --no-same-owner: ${t.trim()}`);
  }
});
