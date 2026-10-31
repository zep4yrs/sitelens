// engine-config 单测：桌面壳「配置落点」的核心不变量——
// 配置必须落在可写目录（用户数据目录）而非安装目录；
// 首启内容选择：用户目录优先 > 带壳标记的旧配置迁移 > 全新；
// 只读类错误识别与可操作提示。
//
// 回归来源（v3.0.0 实测）：装到 D:\Program Files 后首启写
// resources\engine\.sitelens.yml → EPERM，引擎起不来。
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const cfg = require("../lib/engine-config.js");

test("configPath：落在用户数据目录，不在安装目录", () => {
  const userDir = path.join("C:", "Users", "u", "AppData", "Roaming", "SiteLens");
  const engineDir = path.join("D:", "Program Files", "SiteLens", "resources", "engine");
  const p = cfg.configPath(userDir);
  assert.strictEqual(p, path.join(userDir, ".sitelens.yml"));
  assert.ok(p.startsWith(userDir), "配置必须在用户数据目录内");
  assert.ok(!p.startsWith(engineDir), "配置不得落在安装目录（只读）");
});

test("chooseSeed：用户目录已有配置 → 直接沿用，不迁移", () => {
  const r = cfg.chooseSeed({ userText: "scan:\n  deep: true\n", legacyText: "old" });
  assert.strictEqual(r.source, "user");
  assert.strictEqual(r.migrate, false);
  assert.strictEqual(r.text, "scan:\n  deep: true\n");
});

test("chooseSeed：安装目录有带壳标记的旧配置 → 迁移（保留用户改过的键）", () => {
  const legacy = cfg.MARKER + "\nscan:\n  deep: false\n"; // 用户改过 deep
  const r = cfg.chooseSeed({ userText: null, legacyText: legacy });
  assert.strictEqual(r.source, "legacy");
  assert.strictEqual(r.migrate, true, "应把旧内容迁移到用户目录");
  assert.strictEqual(r.text, legacy);
});

test("chooseSeed：都没有 → 全新（仅壳标记行）", () => {
  const r = cfg.chooseSeed({ userText: null, legacyText: null });
  assert.strictEqual(r.source, "fresh");
  assert.strictEqual(r.migrate, false);
  assert.strictEqual(r.text, cfg.MARKER + "\n");
});

test("chooseSeed：旧文件不带壳标记（开发仓库残留）→ 不继承，全新", () => {
  const r = cfg.chooseSeed({ userText: null, legacyText: "headless: true\n" });
  assert.strictEqual(r.source, "fresh", "无标记的旧配置不应被当作桌面配置继承");
  assert.strictEqual(r.migrate, false);
});

test("chooseSeed：空串视同不存在", () => {
  const r = cfg.chooseSeed({ userText: "", legacyText: "" });
  assert.strictEqual(r.source, "fresh");
});

test("isReadOnlyError：EPERM/EACCES/EROFS 命中，其它不命中", () => {
  assert.strictEqual(cfg.isReadOnlyError({ code: "EPERM" }), true);
  assert.strictEqual(cfg.isReadOnlyError({ code: "EACCES" }), true);
  assert.strictEqual(cfg.isReadOnlyError({ code: "EROFS" }), true);
  assert.strictEqual(cfg.isReadOnlyError({ code: "ENOENT" }), false);
  assert.strictEqual(cfg.isReadOnlyError(null), false);
});

test("explainError：只读错误给出可操作提示（含落点与建议）", () => {
  const msg = cfg.explainError({ code: "EPERM" }, "C:\\Users\\u\\AppData\\Roaming\\SiteLens\\.sitelens.yml");
  assert.ok(msg.includes("EPERM"), "应保留错误码便于排障");
  assert.ok(msg.includes(".sitelens.yml"), "应含落点路径");
  assert.ok(msg.includes("不可写"), "应说明原因");
  assert.ok(msg.includes("只读") || msg.includes("重装"), "应给出可操作建议");
});

test("explainError：非只读错误 → 通用文案（不误报为权限问题）", () => {
  const msg = cfg.explainError({ code: "ENOSPC", message: "no space left" }, "x");
  assert.ok(msg.includes("no space left"));
  assert.ok(!msg.includes("不可写"));
});

test("resolveEngineDir：打包 → resourcesPath/engine", () => {
  const p = cfg.resolveEngineDir({
    isDev: false, dirname: "/app", resourcesPath: "/app/resources",
    exeName: "sitelens.exe", hasBin: () => true
  });
  assert.strictEqual(p, path.join("/app/resources", "engine"));
});

test("resolveEngineDir：开发 + 仓库根有引擎程序 → 用仓库根", () => {
  const root = path.join("/repo", "desktop", ".."); // dirname=.../desktop
  const p = cfg.resolveEngineDir({
    isDev: true, dirname: path.join("/repo", "desktop"), resourcesPath: "/x",
    exeName: "sitelens.exe",
    hasBin: (f) => f === path.join(root, "sitelens.exe")
  });
  assert.strictEqual(p, root, "仓库根有引擎程序时应优先仓库根（可带 live 数据）");
});

test("resolveEngineDir：开发 + 仓库根无程序但 desktop/engine 有 → 回退暂存产物（回归）", () => {
  const staged = path.join("/repo", "desktop", "engine");
  const p = cfg.resolveEngineDir({
    isDev: true, dirname: path.join("/repo", "desktop"), resourcesPath: "/x",
    exeName: "sitelens.exe",
    hasBin: (f) => f === path.join(staged, "sitelens.exe")
  });
  assert.strictEqual(p, staged,
    "仓库根无引擎程序时应回退 desktop/engine（否则源码启动报「引擎程序缺失」）");
});

test("resolveEngineDir：两处皆无 → 保留仓库根（交由启动校验报错）", () => {
  const p = cfg.resolveEngineDir({
    isDev: true, dirname: path.join("/repo", "desktop"), resourcesPath: "/x",
    exeName: "sitelens.exe", hasBin: () => false
  });
  assert.strictEqual(p, path.join("/repo", "desktop", ".."));
});
