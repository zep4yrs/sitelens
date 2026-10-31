// 扫描前预检 / 扫描中 ETA 纯函数单测（node --test）。
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const live = require("./scan-live.js");

test("validateTarget：空/非法/非 http 协议给出明确错误", () => {
  assert.equal(live.validateTarget("").ok, false);
  assert.match(live.validateTarget("").error, /请输入目标地址/);
  assert.equal(live.validateTarget("not a url").ok, false);
  assert.match(live.validateTarget("not a url").error, /地址格式不正确/);
  assert.equal(live.validateTarget("ftp://example.com").ok, false);
  assert.match(live.validateTarget("ftp://example.com").error, /http\/https/);
});

test("validateTarget：合法目标归一化 + 内网/IP 风险提示", () => {
  const a = live.validateTarget("https://example.com/path?q=1");
  assert.equal(a.ok, true);
  assert.equal(a.normalized, "https://example.com/path?q=1");
  assert.deepEqual(a.warnings, []);
  const b = live.validateTarget("http://192.168.1.10/");
  assert.equal(b.ok, true);
  assert.ok(b.warnings.some((w) => /IP 地址/.test(w)));
  assert.ok(b.warnings.some((w) => /内网/.test(w)));
  const c = live.validateTarget("http://localhost:8080/");
  assert.equal(c.ok, true);
  assert.ok(c.warnings.some((w) => /内网/.test(w)));
});

test("etaSeconds：低进度用经验估时，高进度按实际速率外推且不小于 3 秒", () => {
  assert.equal(live.etaSeconds(0, 10, 100), 90);
  assert.equal(live.etaSeconds(5, 10, 100), 90);
  // 50% 用时 40s → 剩余约 40s
  assert.equal(live.etaSeconds(50, 40, 100), 40);
  // 90% 用时 90s → 剩余 10s
  assert.equal(live.etaSeconds(90, 90, 100), 10);
  // 接近完成也不显示 0
  assert.equal(live.etaSeconds(99, 100, 100), 3);
});

test("requestBucket：DAST/全量模板/主动模块抬升请求量级", () => {
  assert.equal(live.requestBucket({ deep: true }), "低");
  assert.equal(live.requestBucket({ deep: true, dast: true }), "中");
  assert.equal(live.requestBucket({ deep: true, dast: true, checks: "all", dir_scan: true }), "高");
});

test("suggest：WAF 目标降 DAST、CMS 保留专项、静态站给快速档", () => {
  const waf = live.suggest({ status: 403, blocked: true, block_reason: "waf-header:cf-ray", tech: [] });
  assert.equal(waf.strength, "std");
  assert.equal(waf.verify.dast, false);
  assert.ok(waf.reasons.some((r) => /WAF/.test(r)));

  const cms = live.suggest({ status: 200, tech: ["WordPress", "nginx"] });
  assert.equal(cms.strength, "std");
  assert.equal(cms.verify.dast, true);
  assert.ok(cms.reasons.some((r) => /WordPress/.test(r)));

  const stat = live.suggest({ status: 200, tech: [], server: "nginx" });
  assert.equal(stat.strength, "fast");
  assert.equal(stat.verify.dast, false);
  assert.equal(stat.verify.dir, false);
});

test("suggest：401/403/429/慢响应/跨主机给出警告", () => {
  assert.ok(live.suggest({ status: 401 }).warnings.some((w) => /认证/.test(w)));
  assert.ok(live.suggest({ status: 403 }).warnings.some((w) => /浏览器 UA/.test(w)));
  assert.ok(live.suggest({ status: 429 }).warnings.some((w) => /polite/.test(w)));
  assert.ok(live.suggest({ status: 200, response_ms: 3000 }).warnings.some((w) => /响应较慢/.test(w)));
  const cross = live.suggest({ status: 200, requested_url: "https://a.com/", final_url: "https://b.com/" });
  assert.ok(cross.warnings.some((w) => /其他主机/.test(w)));
});
