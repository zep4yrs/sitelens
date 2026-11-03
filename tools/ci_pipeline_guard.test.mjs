// CI 配置门禁：把「容器内跑 wine 必须带虚拟显示」固化成断言——
// 历史事故（tag 构建在 wine process failed 处中断）的根因是
// 32 位 PE 在没有 display driver 时秒退（err:winediag:nodrv_CreateWindow），
// 而不是缺 32 位库。行为一致性靠测试守住，不靠注释。
//
// 另外守**生效中**的 main 回归流水线（E-01/E-09）：步骤不被注释吞掉、
// benchmark 自检必须在「前端转义回归」里真跑、-race 覆盖范围与验收报告一致。
//
// node --test 运行（Node 22+ 无参自动发现；带目录参数会被当模块路径）。
import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";

const cnb = readFileSync(new URL("../.cnb.yml", import.meta.url), "utf8");
const nsisHelper = readFileSync(new URL("./ci_nsis_exe.sh", import.meta.url), "utf8");

/** 取出 v* tag 触发的那一节（只取**生效中**的顶层 `"v*":`，不取注释里的历史配置） */
function tagSection() {
  const m = cnb.match(/^"v\*":\s*$/m);
  assert.ok(m, "未找到生效中的 v* tag 流水线节");
  return cnb.slice(m.index);
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

test("Wails tag 流水线：NSIS 统一经 ci_nsis_exe.sh，不直接调 makensis/electron-builder", (t) => {
  if (skipIfRetired(t)) return;
  const section = tagSection();
  const active = section
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  assert.ok(
    active.some((l) => /tools\/release_local\.sh\b/.test(l) && !l.includes("--publish")),
    "tag 流水线应先调用 tools/release_local.sh（只构建，上传统一走 release_upload.sh）"
  );
  assert.ok(
    active.some((l) => l.includes("tools/release_upload.sh")),
    "tag 流水线应调用 tools/release_upload.sh（内部经 ci_nsis_exe.sh 打 NSIS 后上传）"
  );
  for (const l of active) {
    assert.ok(!/electron-builder/.test(l), `Wails 线不应再调 electron-builder: ${l}`);
    assert.ok(!/^makensis\b/.test(l), `不得裸调 makensis（应由 ci_nsis_exe.sh 包裹）: ${l}`);
  }
});

test("tag 流水线安装了 xvfb（含 xauth，xvfb-run 依赖它）", (t) => {
  if (skipIfRetired(t)) return;
  assert.match(tagSection(), /apt-get install[^\n]*\bxvfb\b/, "未安装 xvfb");
  assert.match(tagSection(), /apt-get install[^\n]*\bxauth\b/, "未安装 xauth");
});

test("Wails tag 流水线：产物与上传路径（安装包 + Linux deb，不传 latest.yml）", (t) => {
  if (skipIfRetired(t)) return;
  const section = tagSection();
  const active = section
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  // 1) 构建：Windows 安装包走 release_local.sh（只构建）；Linux deb 走 wails_build_unix.sh
  assert.ok(
    active.some((l) => /tools\/release_local\.sh\b/.test(l) && !l.includes("--publish")),
    "缺少 Windows 安装包构建（tools/release_local.sh）"
  );
  assert.ok(
    active.some((l) => l.includes("tools/wails_build_unix.sh")),
    "缺少 Linux deb 构建（tools/wails_build_unix.sh）"
  );
  // 2) 上传：一条 release_upload.sh 同时传 exe + deb（发行说明占位符一次回填）
  const uploads = active.filter((l) => l.includes("release_upload.sh"));
  const replaces = active.filter((l) => l.includes("release_replace.sh"));
  assert.strictEqual(uploads.length, 1, `附件上传应为 1 条（exe+deb 合并），实际 ${uploads.length}`);
  assert.strictEqual(replaces.length, 0, "CNB 不做更新源，不应有 desktop-stable 替换步骤");
  assert.ok(
    uploads[0].includes("SiteLens-Setup-*.exe") && uploads[0].includes("SiteLens_*_amd64.deb"),
    `上传应同时包含 Windows 安装包与 Linux deb，实际：${uploads[0]}`
  );
  assert.match(section, /SITLENS_BODY_FILE/, "发行说明未挂载");
  // 3) 不传 latest.yml / blockmap（自动更新源唯一在 GitHub desktop-stable）
  assert.ok(!/release_upload\.sh[^\n]*latest\.yml/.test(section), "CNB 不应上传 latest.yml");
  assert.ok(!active.some((l) => /\.blockmap/.test(l)), "CNB 不应上传 blockmap");
});

test("Wails tag 流水线：GOTOOLCHAIN=auto（desktop go.mod 要求 1.26.9）", (t) => {
  if (skipIfRetired(t)) return;
  assert.match(tagSection(), /export GOTOOLCHAIN=auto/, "缺少 GOTOOLCHAIN=auto 导出");
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

// ---------------------------------------------------------------------------
// E-01：生效中回归流水线的「步骤完整性」门禁
//
// 背景：`.cnb.yml` 里 `node benchmark/score.mjs --selftest` 曾被写成
// 「上一行末尾 + 字面量反引号 n」的形式，YAML 把 ` #` 之后全部当注释，
// 于是该步骤**从未执行**且 CI 一直是绿的（门禁静默失效）。
// 上面的 tagSection() 只守已停用的 v* 节，抓不到这个问题；此处专门守 main 节。
// ---------------------------------------------------------------------------

/** 取出**生效中**的回归流水线块（`.main: &regression` 之后、顶层 `main:` 之前）。 */
function regressionBlock() {
  const start = cnb.indexOf(".main: &regression");
  assert.ok(start > 0, "未找到 .main: &regression 回归流水线定义");
  const rest = cnb.slice(cnb.indexOf("\n", start) + 1);
  const end = rest.match(/^main:\s*$/m);
  assert.ok(end, "未找到 main: 触发节（回归流水线块边界）");
  return rest.slice(0, end.index);
}

/** 取某个 stage 的 script 列表项（只认真实 list item，跳过 `script:` 键、空行与注释）。 */
function stageScriptItems(block, stageName) {
  const lines = block.split("\n");
  const i = lines.findIndex((l) => l.trim() === `- name: ${stageName}`);
  assert.ok(i >= 0, `未找到 stage「${stageName}」`);
  const items = [];
  for (let j = i + 1; j < lines.length; j++) {
    const t = lines[j].trim();
    if (t.startsWith("- name:")) break; // 进入下一个 stage
    if (!t.startsWith("- ")) continue; // script: / 空行 / 注释
    items.push(t.slice(2));
  }
  return items;
}

test("回归流水线不含被吞掉的换行（字面量反引号 n）", () => {
  const block = regressionBlock();
  assert.ok(
    !block.includes("`n"),
    "检测到字面量反引号 n：YAML 会把其后的步骤当注释吞掉，请改为真实换行"
  );
});

test("「前端转义回归」stage 必须执行 benchmark 评分器自检（E-01 防退化）", () => {
  const items = stageScriptItems(regressionBlock(), "前端转义回归");
  assert.ok(items.length >= 5, `前端 stage 项数异常（${items.length}），疑似步骤被合并或注释掉`);
  const hit = items.some((it) => /^node\s+benchmark\/score\.mjs\s+--selftest/.test(it));
  assert.ok(
    hit,
    `「前端转义回归」缺少 benchmark/score.mjs --selftest；实际项：\n  ${items.join("\n  ")}`
  );
});

test("回归流水线的 -race 门禁覆盖 ./cmd/...（与验收报告声明一致，E-09）", () => {
  const items = stageScriptItems(regressionBlock(), "引擎回归");
  const race = items.find((it) => /^go\s+test\s+-race\b/.test(it));
  assert.ok(race, "未找到 -race 门禁");
  assert.match(race, /\.\/internal\/\.\.\./, `-race 应覆盖 ./internal/...：${race}`);
  assert.match(race, /\.\/cmd\/\.\.\./, `-race 应覆盖 ./cmd/...（与 docs/验收报告 声明一致）：${race}`);
});
