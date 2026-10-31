// 桌面壳端口决策（纯函数，无依赖，node:test 可测）。
//
// 背景（P0 回归）：端口粘性曾两度静默断裂——
//   ① 合并写出的 listen 带引号，旧正则读不回 → 每次回退 5087；
//   ② 壳偏好里的协商端口没回写，JSON.stringify 丢 undefined，重启漂移。
// 这里把「最终用哪个端口」的规则抽成单一实现，engine.js 只是调用方，
// 避免同一逻辑散落两处、改一份忘一份。
//
// 优先级：壳偏好(prefPort) > 配置原文(confPort) > 默认(defaultPort)。
// 壳偏好是权威源：上次协商出的随机端口必须能被认领回来。
"use strict";

var DEFAULT_FALLBACK = 5087;

// validPort 判定是否为可用端口数值（1-65535 整数）。
function validPort(v) {
  return typeof v === "number" && Number.isInteger(v) && v > 0 && v <= 65535;
}

// resolvePreferredPort 决定「优先尝试」的端口与来源标签。
//   opts.prefPort    壳偏好端口（可为 undefined/null）
//   opts.confPort    配置原文端口（可为 undefined/null）
//   opts.defaultPort 兜底默认端口（可选，默认 5087）
// 返回 { port, source }: source ∈ 'shell' | 'config' | 'default'
function resolvePreferredPort(opts) {
  opts = opts || {};
  var def = validPort(opts.defaultPort) ? opts.defaultPort : DEFAULT_FALLBACK;
  if (validPort(opts.prefPort)) return { port: opts.prefPort, source: "shell" };
  if (validPort(opts.confPort)) return { port: opts.confPort, source: "config" };
  return { port: def, source: "default" };
}

// describePortSource 来源标签 → 中文排障文案（写日志用）。
function describePortSource(source) {
  if (source === "shell") return "壳偏好";
  if (source === "config") return "配置原文";
  return "默认";
}

module.exports = {
  validPort: validPort,
  resolvePreferredPort: resolvePreferredPort,
  describePortSource: describePortSource,
  DEFAULT_FALLBACK: DEFAULT_FALLBACK
};
