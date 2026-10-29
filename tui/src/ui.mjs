// ui.mjs —— 终端呈现的共用小工具（颜色、摘要、表格）。
//
// 单一事实源：命令表（commands.mjs）、扫描流程（cli.mjs）、诊断/历史
// （doctor.mjs）都从这里取颜色与格式化，避免各写一份导致风格漂移。
export const SEV_COLOR = {
  critical: "\x1b[31;1m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};

export const C = {
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  amber: "\x1b[33m",
  cyan: "\x1b[36m",
  reset: "\x1b[0m",
  bold: "\x1b[1m",
};

/** 引擎事件类型 → 颜色（与产品语义一致：命中红 / 绕过琥珀 / 认证青）。 */
export const colorOf = (kind) =>
  kind === "hit" ? C.red : kind === "bypass" ? C.amber : kind === "auth" ? C.cyan : C.dim;

/** 变暗：非 TTY（管道/CI）时自动去色，不污染日志。 */
export const dim = (s) => (process.stderr.isTTY ? C.dim + s + C.reset : s);

/** 严重度 → 颜色（用于已验证发现的徽章）。 */
export const sevColor = (sev) => SEV_COLOR[sev] ?? "";

/** 一行 KV 对齐输出。 */
export function kv(out, label, value, width = 16) {
  out(`  ${C.dim}${label.padEnd(width)}${C.reset}${value}`);
}

/** 简易表格：headers 是列名，rows 是字符串数组。 */
export function table(out, headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(displayWidth(h), ...rows.map((r) => displayWidth(String(r[i] ?? "")))),
  );
  out(C.dim + headers.map((h, i) => pad(h, widths[i])).join("  ") + C.reset);
  for (const r of rows) {
    out(r.map((cell, i) => pad(cell, widths[i])).join("  "));
  }
}

/**
 * 按**显示宽度**补空格（不是字符数）——单元格里带 ANSI 色码时，
 * String.padEnd 会把转义序列也算进长度，导致列错位。
 */
function pad(s, w) {
  const str = String(s ?? "");
  const gap = w - displayWidth(str);
  return gap > 0 ? str + " ".repeat(gap) : str;
}

/** 去掉 ANSI 序列后的显示宽度（CJK 按 2 列计）。 */
export function displayWidth(s) {
  const plain = String(s).replace(/\x1b\[[0-9;]*m/g, "");
  let w = 0;
  for (const ch of plain) {
    const c = ch.codePointAt(0);
    w += c > 0x2e80 ? 2 : 1;
  }
  return w;
}

/** 截断到指定显示宽度（超长加省略号）。 */
export function truncate(s, max) {
  const str = String(s ?? "");
  if (displayWidth(str) <= max) return str;
  let out = "";
  let w = 0;
  for (const ch of str) {
    const cw = ch.codePointAt(0) > 0x2e80 ? 2 : 1;
    if (w + cw > max - 1) break;
    out += ch;
    w += cw;
  }
  return out + "…";
}
