// 三维选择器映射单测：强度档位必须有真差异（fast==std 回归）、
// 被动互斥、范围互锁、依赖项与警告语义。
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const scanOpts = require("./scan-options.js");
const assert = require("node:assert");
const test = require("node:test");

const base = { strength: "std" };

test("强度三档产出真差异（fast==std 回归）", () => {
  const input = (st) => ({
    scope: { web: true, sub: true, srv: true },
    verify: { dir: true, ws: true, dast: true, afp: true },
    strength: st
  });
  const fast = scanOpts.build(input("fast"));
  const std = scanOpts.build(input("std"));
  const full = scanOpts.build(input("full"));
  assert.notDeepStrictEqual(fast.options, std.options, "fast 与 std 不得再相同");
  assert.notDeepStrictEqual(std.options, full.options, "std 与 full 不得再相同");
  assert.strictEqual(fast.options.checks, "none");
  assert.strictEqual(std.options.checks, "core");
  assert.strictEqual(full.options.checks, "all");
  assert.strictEqual(full.options.probe_ports, "full");
  assert.ok(std.options.nuclei_cap > fast.options.nuclei_cap);
  assert.ok(full.options.nuclei_cap > std.options.nuclei_cap);
});

test("被动互斥：主动验证被忽略、强度不消费、范围探测保留", () => {
  const r = scanOpts.build({
    scope: { web: true, sub: true, srv: true, weak: true, js: true },
    verify: { passive: true, dast: true, dir: true, ex: true },
    strength: "full"
  });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.effectiveStrength, null);
  assert.strictEqual(r.options.passive, true);
  assert.strictEqual(r.options.checks, "none");
  assert.strictEqual(r.options.dast, undefined);
  assert.strictEqual(r.options.dir_scan, undefined);
  assert.strictEqual(r.options.deep, undefined);
  assert.strictEqual(r.options.exploit, undefined);
  assert.strictEqual(r.options.subdomain, true, "范围探测仍可运行");
  assert.strictEqual(r.options.service_probe, true);
  // 忽略与跳过都产生警告
  assert.ok(r.warnings.some((w) => w.includes("已忽略")));
});

test("范围全不选：拒绝并给出原因", () => {
  const r = scanOpts.build({ scope: {}, verify: { dast: true }, strength: "std" });
  assert.strictEqual(r.ok, false);
  assert.ok(r.error.includes("至少选择一个范围项"));
});

test("范围逐项映射引擎布尔（子域带接管）", () => {
  const r = scanOpts.build({
    scope: { sub: true, srv: true, np: true, js: true, weak: true },
    verify: {},
    strength: "std"
  });
  assert.strictEqual(r.options.subdomain, true);
  assert.strictEqual(r.options.takeover, true);
  assert.strictEqual(r.options.service_probe, true);
  assert.strictEqual(r.options.netproto, true);
  assert.strictEqual(r.options.js_map, true);
  assert.strictEqual(r.options.weak_audit, true);
});

test("依赖与覆盖面警告：403 绕过需目录探测；未选 Web 提示覆盖有限", () => {
  const r = scanOpts.build({
    scope: { srv: true },
    verify: { by: true, dast: true },
    strength: "std"
  });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.options.dir_bypass, undefined, "无目录探测时 403 绕过应被忽略");
  assert.ok(r.warnings.some((w) => w.includes("403 绕过需与「目录探测」同开")));
  assert.ok(r.warnings.some((w) => w.includes("覆盖面有限")));
  assert.strictEqual(r.options.dast, true, "验证勾选仍按用户意愿下发");
});

test("利用级验证映射并附总闸/禁扫警示", () => {
  const r = scanOpts.build({
    scope: { web: true },
    verify: { ex: true },
    strength: "std"
  });
  assert.strictEqual(r.options.exploit, true);
  assert.ok(r.warnings.some((w) => w.includes("利用级验证") && w.includes("总闸")),
    "警示应提示设置页总闸");
  assert.ok(r.warnings.some((w) => w.includes("gov.cn")), "警示应包含 gov.cn 禁扫说明");
});

test("字典旋钮只随已选模块下发", () => {
  const r = scanOpts.build({
    scope: { web: true, sub: true },
    verify: { dir: true },
    strength: "full"
  });
  assert.strictEqual(r.options.dir_max_paths, 300);
  assert.strictEqual(r.options.sub_max_words, 2000);
  assert.strictEqual(r.options.shell_max_paths, undefined, "WebShell 未选则无此旋钮");
});

test("耗时预估：同范围下 fast < std < full", () => {
  const input = (st) => ({
    scope: { web: true, sub: true, srv: true },
    verify: { dir: true, ws: true, dast: true, afp: true },
    strength: st
  });
  const f = scanOpts.estimateSeconds(scanOpts.build(input("fast")).options);
  const s = scanOpts.estimateSeconds(scanOpts.build(input("std")).options);
  const fu = scanOpts.estimateSeconds(scanOpts.build(input("full")).options);
  assert.ok(f < s && s < fu, `预估应递增: ${f} < ${s} < ${fu}`);
});

test("结构化事实图：勾选 settle 下发 graph，未选不下发", () => {
  const on = scanOpts.build({
    scope: { web: true }, verify: { settle: true }, strength: "std"
  });
  assert.strictEqual(on.options.graph, true);

  const off = scanOpts.build({
    scope: { web: true }, verify: {}, strength: "std"
  });
  assert.strictEqual(off.options.graph, undefined, "未勾选不应下发 graph");
});

test("结构化事实图：被动模式下不消费（随扫描顺带，但被动不爬取）", () => {
  const r = scanOpts.build({
    scope: { web: true }, verify: { passive: true, settle: true }, strength: "std"
  });
  // 被动为互斥分支：settle 属主动验证项 → 触发忽略提示，且不下发 graph
  assert.strictEqual(r.options.graph, undefined);
  assert.ok(r.warnings.some(w => w.indexOf("被动") >= 0));
});
