#!/usr/bin/env node
/* SiteLens 前端质量门禁（FE-06 基础，5.2.x）
   ============================================================================
   静态检查 web/*.html 的可访问性基础项（零依赖、可在 CI 里直接跑）：

     E-BUTTON-NAME   <button> 没有可访问名
                     可访问名来源：可见文本 / aria-label / aria-labelledby（引用存在的 id）
                     / title / value（仅 input[type=button|submit|reset]）
     E-IMG-ALT       <img> 缺 alt 属性（alt="" 表示装饰图，合法）
     E-INPUT-LABEL   <input>/<textarea>/<select> 没有标签
                     标签来源：aria-label / aria-labelledby（引用存在的 id）/
                     title / 关联的 <label for="id"> / 被 <label> 包裹
                     （type=hidden 跳过；type=submit|button|reset 用 value 当名称）
     W-ONCLICK       inline onclick（默认只警告；--strict-onclick 升级为错误）

   允许例外：脚本内 ALLOW 列表（file + rule + contains + reason），用于
   记录「本轮范围外、已登记待修」的已知问题；每条例外必须写原因。
   范围纪律：只登记 web/ 下**不在本次改动范围**的页面问题；能改的页面直接改掉。

   用法：
     node scripts/frontend-check.mjs                    # 检查 web/*.html
     node scripts/frontend-check.mjs --root .           # 指定仓库根目录
     node scripts/frontend-check.mjs --files web/app.html web/404.html
     node scripts/frontend-check.mjs --json             # 机器可读输出
     node scripts/frontend-check.mjs --strict-onclick   # inline onclick 也算错误
     node scripts/frontend-check.mjs --help

   退出码：0 = 通过（可含警告/允许例外）；1 = 存在错误。
   ========================================================================== */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");

/* 已知例外：web/ 下不在本轮（FE-04/06/11）改动范围、但已登记的问题。
   只在**无法改动的文件**上登记；原因必须写清楚，禁止用例外掩盖新问题。
   注：这些页面本轮范围外不能改静态 HTML；运行时已由 common.js 的
   「无标签控件兜底」补 aria-label（placeholder / 相邻 label 文本），
   静态标签在 5.3 统一补齐后应删除本列表。 */
const ALLOW = [
  {
    file: "web/settings.html",
    rule: "E-INPUT-LABEL",
    reason: "设置页表单标签待 5.3 统一补（本轮范围外；common.js 运行时已兜底 aria-label）",
  },
  {
    file: "web/history.html",
    rule: "E-INPUT-LABEL",
    reason: "历史页搜索框标签待 5.3 补（本轮范围外；common.js 运行时已兜底 aria-label）",
  },
  {
    file: "web/intel.html",
    rule: "E-INPUT-LABEL",
    reason: "情报页搜索框标签待 5.3 补（本轮范围外；common.js 运行时已兜底 aria-label）",
  },
  {
    file: "web/feedback.html",
    rule: "E-INPUT-LABEL",
    reason: "反馈页文本域标签待 5.3 补（本轮范围外；common.js 运行时已兜底 aria-label）",
  },
];

const RULES = {
  BUTTON: "E-BUTTON-NAME",
  IMG: "E-IMG-ALT",
  INPUT: "E-INPUT-LABEL",
  ONCLICK: "W-ONCLICK",
};

/* ---------------- 极简 HTML 词法（不引依赖；只解析标签/属性/文本） ---------------- */
function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&nbsp;/gi, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&amp;/gi, "&");
}

function parseAttrs(html, pos) {
  const attrs = Object.create(null);
  let i = pos;
  while (i < html.length) {
    const before = i;
    while (i < html.length && /\s/.test(html[i])) i++;
    if (i >= html.length) break;
    if (html[i] === ">") { i++; break; }
    if (html[i] === "/" && html[i + 1] === ">") { i += 2; break; }
    // 标签内出现孤立 "/"（不是自闭合）时直接跳过，避免不前进
    if (html[i] === "/") { i++; continue; }
    const nameStart = i;
    while (i < html.length && !/[\s=/>]/.test(html[i])) i++;
    const name = html.slice(nameStart, i).toLowerCase();
    while (i < html.length && /\s/.test(html[i])) i++;
    let value = "";
    if (html[i] === "=") {
      i++;
      while (i < html.length && /\s/.test(html[i])) i++;
      if (html[i] === '"' || html[i] === "'") {
        const q = html[i];
        i++;
        const vs = i;
        while (i < html.length && html[i] !== q) i++;
        value = html.slice(vs, i);
        if (html[i] === q) i++;
      } else {
        const vs = i;
        while (i < html.length && !/[\s>]/.test(html[i])) i++;
        value = html.slice(vs, i);
      }
    }
    if (name) attrs[name] = decodeEntities(value);
    if (i <= before) i = before + 1; // 兜底：畸形属性不前进时强制推进
  }
  return { attrs, end: i };
}

// <script>/<style> 内部是原始文本（可能含 `<`、HTML 字符串），不能按标签解析。
const RAW_TEXT_TAGS = new Set(["script", "style"]);

function forEachTag(html, cb) {
  const lower = html.toLowerCase();
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt < 0) break;
    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      i = end < 0 ? html.length : end + 3;
      continue;
    }
    const next = html[lt + 1];
    if (next === "!" || next === "?" || next === "/") {
      const gt = html.indexOf(">", lt + 2);
      i = gt < 0 ? html.length : gt + 1;
      continue;
    }
    const m = /^<([a-zA-Z][a-zA-Z0-9:-]*)/.exec(html.slice(lt, lt + 64));
    if (!m) { i = lt + 1; continue; }
    const tag = m[1].toLowerCase();
    const parsed = parseAttrs(html, lt + m[0].length);
    if (RAW_TEXT_TAGS.has(tag)) {
      // 整段原始文本跳过（含闭合标签本身）
      const closeTag = "</" + tag;
      const close = lower.indexOf(closeTag, parsed.end);
      if (close < 0) { i = html.length; continue; }
      const gt = html.indexOf(">", close + closeTag.length);
      i = gt < 0 ? html.length : gt + 1;
      continue;
    }
    cb({ tag, attrs: parsed.attrs, start: lt, end: parsed.end });
    i = parsed.end > lt ? parsed.end : lt + 1;
  }
}

function stripTags(html) {
  return decodeEntities(html.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
}

function elementText(html, openEnd, tagName) {
  const close = html.toLowerCase().indexOf("</" + tagName, openEnd);
  if (close < 0) return stripTags(html.slice(openEnd));
  return stripTags(html.slice(openEnd, close));
}

function lineIndex(html) {
  const starts = [0];
  for (let i = 0; i < html.length; i++) if (html[i] === "\n") starts.push(i + 1);
  return (pos) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= pos) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
}

function snippet(html, start, end) {
  const raw = html.slice(start, Math.min(end + 1, start + 160)).replace(/\s+/g, " ").trim();
  return raw.length >= 160 ? raw.slice(0, 157) + "..." : raw;
}

/* ---------------- 检查 ---------------- */
function checkFile(file, text) {
  const errors = [];
  const warnings = [];
  const lineOf = lineIndex(text);

  // 文档内全部 id（aria-labelledby / label[for] 引用校验）
  const ids = new Set();
  for (const m of text.matchAll(/\bid\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    const id = m[1] ?? m[2] ?? m[3];
    if (id) ids.add(id);
  }
  // <label for="x"> 关联
  const labelFor = new Set();
  for (const m of text.matchAll(/<label\b[^>]*\bfor\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    const id = m[1] ?? m[2] ?? m[3];
    if (id) labelFor.add(id);
  }
  // <label> 区间（用于「被 label 包裹」判定）
  const labelRanges = [];
  const openRe = /<label\b/gi;
  let om;
  while ((om = openRe.exec(text))) {
    const close = text.toLowerCase().indexOf("</label>", om.index);
    labelRanges.push([om.index, close < 0 ? text.length : close]);
  }

  const ariaLabel = (a) => (a["aria-label"] || "").trim();
  const ariaLabelledbyOk = (a) => {
    const ref = (a["aria-labelledby"] || "").trim();
    if (!ref) return false;
    return ref.split(/\s+/).every((id) => ids.has(id));
  };
  const hasTitle = (a) => (a["title"] || "").trim() !== "";

  forEachTag(text, (el) => {
    const a = el.attrs;
    const hiddenFromAT = a["aria-hidden"] === "true" || "hidden" in a;

    // inline onclick 统一记警告（与元素类型无关；--strict-onclick 可升级为错误）
    if ("onclick" in a) {
      warnings.push({
        rule: RULES.ONCLICK,
        file,
        line: lineOf(el.start),
        snippet: snippet(text, el.start, el.end),
        message: "<" + el.tag + "> 使用 inline onclick（建议 data-* + 事件委托）",
      });
    }

    if (el.tag === "button") {
      if (hiddenFromAT) return;
      const nameOk =
        ariaLabel(a) !== "" ||
        ariaLabelledbyOk(a) ||
        hasTitle(a) ||
        elementText(text, el.end, "button") !== "";
      if (!nameOk) {
        errors.push({
          rule: RULES.BUTTON,
          file,
          line: lineOf(el.start),
          snippet: snippet(text, el.start, el.end),
          message: "<button> 没有可访问名（补可见文本或 aria-label）",
        });
      }
      return;
    }

    if (el.tag === "img") {
      if (hiddenFromAT) return;
      if (!("alt" in a)) {
        errors.push({
          rule: RULES.IMG,
          file,
          line: lineOf(el.start),
          snippet: snippet(text, el.start, el.end),
          message: "<img> 缺 alt 属性（装饰图请写 alt=\"\"）",
        });
      }
      return;
    }

    if (el.tag === "input" || el.tag === "textarea" || el.tag === "select") {
      if (hiddenFromAT) return;
      const type = (a["type"] || (el.tag === "input" ? "text" : "")).toLowerCase();
      if (type === "hidden") return;
      if (el.tag === "input" && (type === "submit" || type === "button" || type === "reset")) {
        if ((a["value"] || "").trim() !== "" || ariaLabel(a) !== "" || hasTitle(a)) return;
        errors.push({
          rule: RULES.INPUT,
          file,
          line: lineOf(el.start),
          snippet: snippet(text, el.start, el.end),
          message: "<input> 按钮缺 value/aria-label",
        });
        return;
      }
      if (el.tag === "input" && type === "image") {
        if (!("alt" in a) && ariaLabel(a) === "") {
          errors.push({
            rule: RULES.IMG,
            file,
            line: lineOf(el.start),
            snippet: snippet(text, el.start, el.end),
            message: "<input type=image> 缺 alt/aria-label",
          });
        }
        return;
      }
      const id = (a.id || "").trim();
      const labelled =
        ariaLabel(a) !== "" ||
        ariaLabelledbyOk(a) ||
        hasTitle(a) ||
        (id !== "" && labelFor.has(id)) ||
        labelRanges.some(([s, e]) => el.start > s && el.start < e);
      if (!labelled) {
        errors.push({
          rule: RULES.INPUT,
          file,
          line: lineOf(el.start),
          snippet: snippet(text, el.start, el.end),
          message: "<" + el.tag + "> 没有标签（补 aria-label 或关联 <label>）",
        });
      }
      return;
    }
  });

  return { errors, warnings };
}

function applyAllowlist(items) {
  const kept = [];
  const allowed = [];
  for (const it of items) {
    const hit = ALLOW.find(
      (x) =>
        x.rule === it.rule &&
        (x.file === it.file || x.file === basename(it.file)) &&
        (!x.contains || it.snippet.includes(x.contains))
    );
    if (hit) allowed.push({ ...it, reason: hit.reason });
    else kept.push(it);
  }
  return { kept, allowed };
}

/* ---------------- CLI ---------------- */
function parseArgs(argv) {
  const opts = { files: [], root: REPO_ROOT, json: false, strictOnclick: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--strict-onclick") opts.strictOnclick = true;
    else if (a === "--root") opts.root = resolve(argv[++i] || ".");
    else if (a === "--files") {
      while (i + 1 < argv.length && !argv[i + 1].startsWith("--")) opts.files.push(argv[++i]);
    } else if (!a.startsWith("-")) opts.files.push(a);
  }
  return opts;
}

function collectFiles(opts) {
  if (opts.files.length) return opts.files.map((f) => resolve(f));
  const webDir = join(opts.root, "web");
  return readdirSync(webDir)
    .filter((f) => f.toLowerCase().endsWith(".html"))
    .sort()
    .map((f) => join(webDir, f));
}

function printHelp() {
  console.log(`SiteLens 前端质量门禁（FE-06）
用法: node scripts/frontend-check.mjs [选项] [html 文件...]

选项:
  --root <dir>       仓库根目录（默认脚本上级目录）
  --files <a> <b>    只检查指定 HTML 文件
  --json             输出 JSON（CI 消费）
  --strict-onclick   inline onclick 从警告升级为错误
  --help             显示本帮助

规则: ${Object.values(RULES).join(" / ")}
退出码: 0 通过（可含警告）；1 存在错误`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { printHelp(); return 0; }

  const files = collectFiles(opts);
  if (!files.length) {
    console.error("× 没有找到待检查的 HTML 文件");
    return 1;
  }

  const errors = [];
  const warnings = [];
  for (const f of files) {
    const rel = relative(opts.root, f).replace(/\\/g, "/");
    let text;
    try {
      text = readFileSync(f, "utf8");
    } catch (e) {
      errors.push({ rule: "E-READ", file: rel, line: 0, snippet: "", message: "读取失败: " + e.message });
      continue;
    }
    const res = checkFile(rel, text);
    errors.push(...res.errors);
    warnings.push(...res.warnings);
  }

  const allowErrors = applyAllowlist(errors);
  const allowWarnings = applyAllowlist(warnings);
  const fatal = allowErrors.kept;
  const warn = allowWarnings.kept;
  const allowed = [...allowErrors.allowed, ...allowWarnings.allowed];

  if (opts.strictOnclick) {
    for (const w of warn) {
      if (w.rule === RULES.ONCLICK) fatal.push({ ...w, rule: "E-ONCLICK" });
    }
    for (let i = warn.length - 1; i >= 0; i--) if (warn[i].rule === RULES.ONCLICK) warn.splice(i, 1);
  }

  if (opts.json) {
    console.log(JSON.stringify({ files: files.length, errors: fatal, warnings: warn, allowed }, null, 2));
  } else {
    console.log("SiteLens 前端质量门禁（FE-06）— 检查 " + files.length + " 个 HTML");
    for (const e of fatal) console.log(`× [${e.rule}] ${e.file}:${e.line}  ${e.message}\n    ${e.snippet}`);
    for (const w of warn) console.log(`! [${w.rule}] ${w.file}:${w.line}  ${w.message}`);
    // 允许例外按 文件+规则 聚合，避免刷屏；明细看 --json
    const groups = new Map();
    for (const a of allowed) {
      const key = a.file + "\u0000" + a.rule;
      const g = groups.get(key) || { file: a.file, rule: a.rule, count: 0, reason: a.reason };
      g.count++;
      groups.set(key, g);
    }
    for (const g of groups.values()) {
      console.log(`· [允许] ${g.file} ${g.rule} ×${g.count} — ${g.reason}`);
    }
    console.log(
      `合计：错误 ${fatal.length} / 警告 ${warn.length} / 允许例外 ${allowed.length} → ` +
      (fatal.length ? "不通过" : "通过")
    );
  }
  return fatal.length ? 1 : 0;
}

process.exitCode = main();
