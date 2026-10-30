// port-policy 单测：桌面壳端口粘性的核心不变量——
// 壳偏好 > 配置原文 > 默认；端口合法性校验；来源标签。
// 覆盖两度静默回归（引号读不回回退 5087 / 协商端口未回写漂移）。
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { validPort, resolvePreferredPort, describePortSource } = require("../lib/port-policy.js");

test("validPort：仅接受 1-65535 整数", () => {
  assert.strictEqual(validPort(5087), true);
  assert.strictEqual(validPort(1), true);
  assert.strictEqual(validPort(65535), true);
  assert.strictEqual(validPort(0), false);
  assert.strictEqual(validPort(-1), false);
  assert.strictEqual(validPort(65536), false);
  assert.strictEqual(validPort(5087.5), false);
  assert.strictEqual(validPort("5087"), false);
  assert.strictEqual(validPort(undefined), false);
  assert.strictEqual(validPort(null), false);
});

test("壳偏好优先：协商出的随机端口重启后被认领（P0 回归）", () => {
  const r = resolvePreferredPort({ prefPort: 51234, confPort: 5087 });
  assert.strictEqual(r.port, 51234);
  assert.strictEqual(r.source, "shell");
});

test("无壳偏好时沿用配置原文端口", () => {
  const r = resolvePreferredPort({ prefPort: undefined, confPort: 6001 });
  assert.strictEqual(r.port, 6001);
  assert.strictEqual(r.source, "config");
});

test("两者皆无时回退默认端口", () => {
  const r = resolvePreferredPort({});
  assert.strictEqual(r.port, 5087);
  assert.strictEqual(r.source, "default");
});

test("壳偏好非法（undefined/越界/非整数）不得遮蔽配置原文", () => {
  for (const bad of [undefined, null, 0, 70000, "5087", 5087.2]) {
    const r = resolvePreferredPort({ prefPort: bad, confPort: 6002 });
    assert.strictEqual(r.port, 6002, "prefPort=" + String(bad));
    assert.strictEqual(r.source, "config");
  }
});

test("自定义 defaultPort 生效，非法默认值回落 5087", () => {
  assert.strictEqual(resolvePreferredPort({ defaultPort: 8080 }).port, 8080);
  assert.strictEqual(resolvePreferredPort({ defaultPort: 0 }).port, 5087);
});

test("describePortSource：三种来源中文标签", () => {
  assert.strictEqual(describePortSource("shell"), "壳偏好");
  assert.strictEqual(describePortSource("config"), "配置原文");
  assert.strictEqual(describePortSource("default"), "默认");
});
