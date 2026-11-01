#!/usr/bin/env node
// benchmark/score.mjs — CP-04 基准评测评分器（Node ≥18，零第三方依赖）。
//
// 输入：
//   --raw <dir>        run.ps1 / run.sh 产出的 raw 结果目录（每个目标一个 <id>.json）
//   --truth <file>     ground-truth.json（用例、期望漏洞类型、版本冻结信息）
//   --out <dir>        输出目录（默认 <raw>/../out）
//   --catalog <file>   覆盖率口径目录（默认 benchmark/coverage-catalog.json）
//   --suite <name>     覆盖 ground-truth 里的 suite 名（报告用）
//
// 输出：summary.md + summary.csv（Precision/Recall/F1、类型覆盖率、逐用例明细、
//       FN/FP 明细），供 docs/基准评测-5.2.md 的季度复评直接引用。
//
// 自检：node benchmark/score.mjs --selftest    （内置 fixtures，断言精确数值，exit 0/1）
//
// 计分口径（与 docs/基准评测-5.2.md 一致）：
//   - 检出归一：raw 里的 vulnerabilities[] + verified[] + extras.netsec.findings[]
//     经文本归一（小写、去非字母数字）后按目录别名映射到漏洞类型；映射不上的
//     finding 记 out_of_catalog，只报告不计 FP（避免把配置建议混进误报）。
//   - 每个目标同一类型多条检出只算 1 次（去重）；同类型多次标注请拆独立 target。
//   - TP = 命中的期望条目数；FN = 未命中的期望条目；FP = 检出类型不在期望集合
//     里的条目数；Precision=TP/(TP+FP)，Recall=TP/(TP+FN)，F1=2PR/(P+R)。
//   - 覆盖率两口径：expectedTypeCoverage = TP 覆盖的期望类型 / 期望类型总数；
//     catalogCoverage = TP 覆盖的类型 / 目录类型总数（G02 的 ≥80% 口径）。
//   - 安全用例（expected=[]）：有任意目录内检出即 false_positive_case；
//     caseFPR = 误报用例数 / 安全用例数。
//
// 退出码：0 成功（含 selftest 通过）；1 参数/输入/自检失败。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const SCORER_VERSION = "CP-04/1.0";

// ---------- 基础工具 ----------

function fail(msg) {
  const err = new Error(msg);
  err.userFacing = true;
  throw err;
}

function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    fail(`读取文件失败：${file}（${e.code || e.message}）`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    fail(`JSON 解析失败：${file}\n  ${e.message}`);
  }
}

function writeFile(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
}

/** 文本归一：小写 + 只保留 Unicode 字母/数字（中英文、空格/连字符差异消除）。 */
function norm(s) {
  return String(s ?? "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "");
}

/** 安全除法：分母为 0 时记 0（报告里同时给出原始计数，避免误读）。 */
function safeDiv(a, b) {
  return b === 0 ? 0 : a / b;
}

/** 比率展示：4 位小数（比分用）。 */
function ratio(x) {
  return Number.isFinite(x) ? x.toFixed(4) : "0.0000";
}

/** 百分比展示：1 位小数。 */
function pct(x) {
  return Number.isFinite(x) ? `${(x * 100).toFixed(1)}%` : "0.0%";
}

/** CSV 字段转义（含逗号/引号/换行的字段加双引号）。 */
function csvCell(v) {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csvRow(cells) {
  return cells.map(csvCell).join(",");
}

function truncate(s, n = 80) {
  const str = String(s ?? "");
  return str.length <= n ? str : str.slice(0, n - 1) + "…";
}

// ---------- 参数解析 ----------

const USAGE = `用法：
  node benchmark/score.mjs --raw <dir> --truth <file> [--out <dir>] [--catalog <file>] [--suite <name>]
  node benchmark/score.mjs --selftest

选项：
  --raw <dir>       raw 结果目录（run.ps1/run.sh 产出，文件名 = <target id>.json）
  --truth <file>    ground-truth.json（标注真值）
  --out <dir>       输出目录（默认 <raw>/../out）
  --catalog <file>  覆盖率目录（默认 benchmark/coverage-catalog.json）
  --suite <name>    覆盖报告中的 suite 名
  --quiet           只输出错误与结果路径
  --selftest        用内置 fixtures 做自检并退出（CI 门禁用）
  --help            显示本帮助
`;

function parseArgs(argv) {
  const opts = {
    raw: "",
    truth: "",
    out: "",
    catalog: "",
    suite: "",
    quiet: false,
    selftest: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    const eq = tok.indexOf("=");
    const name = tok.startsWith("--") && eq > 0 ? tok.slice(0, eq) : tok;
    const inline = tok.startsWith("--") && eq > 0 ? tok.slice(eq + 1) : null;
    const value = (flag) => {
      if (inline !== null) return inline;
      if (i + 1 >= argv.length) fail(`参数 ${flag} 缺少取值`);
      return argv[++i];
    };
    switch (name) {
      case "--raw":
        opts.raw = value(name);
        break;
      case "--truth":
        opts.truth = value(name);
        break;
      case "--out":
        opts.out = value(name);
        break;
      case "--catalog":
        opts.catalog = value(name);
        break;
      case "--suite":
        opts.suite = value(name);
        break;
      case "--quiet":
        opts.quiet = true;
        break;
      case "--selftest":
        opts.selftest = true;
        break;
      case "--help":
      case "-h":
        opts.help = true;
        break;
      default:
        fail(`未知参数：${tok}\n\n${USAGE}`);
    }
  }
  return opts;
}

// ---------- 目录（漏洞类型 → 别名）----------

function loadCatalog(file) {
  const j = readJson(file);
  if (!Array.isArray(j.types) || j.types.length === 0) {
    fail(`目录文件 ${file} 缺少非空 types[]`);
  }
  const byId = new Map();
  const types = [];
  for (const t of j.types) {
    if (!t || typeof t.id !== "string" || t.id.trim() === "") {
      fail(`目录 ${file} 存在缺少 id 的类型项：${JSON.stringify(t)}`);
    }
    const id = t.id.trim();
    if (byId.has(id)) fail(`目录 ${file} 类型 id 重复：${id}`);
    const rawAliases = [id, ...(Array.isArray(t.aliases) ? t.aliases : [])];
    const aliases = [];
    for (const a of rawAliases) {
      const n = norm(a);
      if (n.length >= 3 && !aliases.includes(n)) aliases.push(n);
    }
    if (aliases.length === 0) fail(`目录类型 ${id} 无可用的别名（长度需 ≥3）`);
    const item = {
      id,
      label: t.label || id,
      owasp: t.owasp || "",
      cnvd: t.cnvd || "",
      aliases,
    };
    byId.set(id, item);
    types.push(item);
  }
  return { version: j.version || "", types, byId };
}

// ---------- ground-truth ----------

function loadTruth(file, catalog) {
  const j = readJson(file);
  if (!Array.isArray(j.targets) || j.targets.length === 0) {
    fail(`ground-truth ${file} 缺少非空 targets[]`);
  }
  const seen = new Set();
  const targets = [];
  for (const t of j.targets) {
    if (!t || typeof t.id !== "string" || t.id.trim() === "") {
      fail(`ground-truth 目标缺少 id：${JSON.stringify(t)}`);
    }
    const id = t.id.trim();
    if (seen.has(id)) fail(`ground-truth 目标 id 重复：${id}（raw 文件名以 id 为键）`);
    seen.add(id);
    if (typeof t.url !== "string" || t.url.trim() === "") {
      fail(`ground-truth 目标 ${id} 缺少 url`);
    }
    const expected = [];
    const expSeen = new Set();
    const rawExpected = Array.isArray(t.expected) ? t.expected : [];
    for (const e of rawExpected) {
      const type = typeof e === "string" ? e : e && e.type;
      if (typeof type !== "string" || !catalog.byId.has(type)) {
        fail(
          `目标 ${id} 的 expected 类型 ${JSON.stringify(type)} 不在目录中（先加入 benchmark/coverage-catalog.json）`
        );
      }
      if (expSeen.has(type)) {
        fail(`目标 ${id} 的 expected 重复类型 ${type}：同一用例同一类型只标注一次，多实例请拆成独立 target id`);
      }
      expSeen.add(type);
      const match = Array.isArray(e && e.match) ? e.match.map(norm).filter((x) => x.length >= 3) : null;
      expected.push({
        type,
        note: (e && e.note) || "",
        match: match && match.length > 0 ? match : null,
      });
    }
    targets.push({ id, url: t.url.trim(), expected, tags: Array.isArray(t.tags) ? t.tags : [] });
  }
  return {
    suite: (typeof j.suite === "string" && j.suite) || path.basename(file, path.extname(file)),
    version: typeof j.version === "string" ? j.version : "",
    frozen: j.frozen && typeof j.frozen === "object" ? j.frozen : {},
    // 可选：ground-truth 自带目录路径（相对 truth 文件），缺省用仓库默认目录
    catalogRef: typeof j.catalog === "string" ? j.catalog : "",
    targets,
  };
}

// ---------- raw 结果 → 归一检出 ----------

// 归一时刻意**不看 url**：靶场 URL 路径本身常含漏洞名（如 DVWA 的
// /vulnerabilities/sqli/），把 URL 纳入匹配会把同目标其它 finding 错判成
// SQL 注入（实测踩过）。URL 只作为证据列展示。
const PRIMARY_TEXT_KEYS = ["type", "name", "title", "check", "cve", "product"];
const SECONDARY_TEXT_KEYS = ["evidence", "advice", "severity", "src"];

function textOf(f, keys) {
  return norm(keys.map((k) => (typeof f[k] === "string" ? f[k] : "")).join(" "));
}

/** 把单条 raw finding 映射到目录类型；映射不上返回 null。
 * 先按结构化字段（type/name/title/check…）匹配，匹配不到再看 evidence；
 * 最长别名优先（避免 "sql injection" 被更短的 "sqli" 抢先）。 */
function classifyFinding(f, catalog) {
  const primary = textOf(f, PRIMARY_TEXT_KEYS);
  let best = null;
  let bestLen = 0;
  for (const t of catalog.types) {
    for (const a of t.aliases) {
      if (a.length > bestLen && primary.includes(a)) {
        best = t.id;
        bestLen = a.length;
      }
    }
  }
  if (best) return best;
  const secondary = textOf(f, SECONDARY_TEXT_KEYS);
  for (const t of catalog.types) {
    for (const a of t.aliases) {
      if (a.length > bestLen && secondary.includes(a)) {
        best = t.id;
        bestLen = a.length;
      }
    }
  }
  return best;
}

/** 抽取 raw 中所有可计分的 finding（含 netsec extras；不含 info 级技术栈等）。 */
function findingsOf(raw) {
  const out = [];
  const push = (arr, source) => {
    if (!Array.isArray(arr)) return;
    for (const f of arr) {
      if (!f || typeof f !== "object") continue;
      // 未验证情报不计分：SiteLens 等扫描器会把 CVE/模板情报放进 vulnerabilities[]，
      // 并标 verdict=possible；这类条目不是“检出”，计入会把情报当成 FP 污染 P/R/F1。
      if (source === "vulnerabilities") {
        const verdict = String(f.verdict || "").toLowerCase();
        if (verdict === "possible" || verdict === "potential" || verdict === "unverified") continue;
      }
      out.push({
        source,
        title: f.title || f.name || f.check || f.type || "",
        check: f.check || f.type || "",
        url: f.url || raw.url || "",
        raw: f,
      });
    }
  };
  push(raw.vulnerabilities, "vulnerabilities");
  push(raw.verified, "verified");
  push(raw.extras && raw.extras.netsec && raw.extras.netsec.findings, "netsec");
  return out;
}

// ---------- 计分 ----------

function score({ catalog, truth, rawDir }) {
  const meta = {
    scorerVersion: SCORER_VERSION,
    suite: truth.suite,
    version: truth.version,
    frozen: truth.frozen,
    catalogVersion: catalog.version,
    catalogTypes: catalog.types.length,
    rawDir,
    generatedAt: new Date().toISOString(),
  };
  const targets = [];
  const fnList = [];
  const fpList = [];
  const outOfCatalogSamples = [];
  const typeStats = new Map(
    catalog.types.map((t) => [t.id, { id: t.id, label: t.label, owasp: t.owasp, cnvd: t.cnvd, expected: 0, tp: 0, fp: 0, fn: 0 }])
  );
  const expectedTypes = new Set();
  const tpTypes = new Set();
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let expectedTotal = 0;
  let detectedTotal = 0;
  let secureCases = 0;
  let fpCases = 0;
  let cleanSecureCases = 0;
  let missingRaw = 0;
  let invalidRaw = 0;
  let scanErrorCases = 0;
  let outOfCatalog = 0;

  const truthIds = new Set(truth.targets.map((t) => t.id));

  for (const t of truth.targets) {
    const rawFile = path.join(rawDir, `${t.id}.json`);
    let raw = null;
    let status = "ok";
    if (!fs.existsSync(rawFile)) {
      status = "missing_raw";
      missingRaw++;
    } else {
      try {
        raw = readJson(rawFile);
      } catch (e) {
        status = "invalid_raw";
        invalidRaw++;
        raw = null;
      }
    }
    if (raw && typeof raw.error === "string" && raw.error.trim() !== "") {
      status = "scan_error";
      scanErrorCases++;
    }

    // 目标级自定义别名（expected[].match），作为目录别名的补充
    const targetAliases = [];
    for (const e of t.expected) {
      if (e.match) {
        for (const a of e.match) targetAliases.push({ type: e.type, alias: a });
      }
    }

    const detected = new Map(); // type -> sample
    if (raw) {
      for (const f of findingsOf(raw)) {
        let type = classifyFinding(f.raw, catalog);
        if (!type) {
          const text = textOf(f.raw, PRIMARY_TEXT_KEYS) + " " + textOf(f.raw, SECONDARY_TEXT_KEYS);
          for (const ta of targetAliases) {
            if (text.includes(ta.alias)) {
              type = ta.type;
              break;
            }
          }
        }
        if (!type) {
          outOfCatalog++;
          if (outOfCatalogSamples.length < 20) {
            outOfCatalogSamples.push({ target: t.id, title: truncate(f.title, 80), check: f.check, source: f.source });
          }
          continue;
        }
        if (!detected.has(type)) {
          detected.set(type, { type, title: truncate(f.title, 100), check: f.check, url: f.url, source: f.source });
        }
      }
    }

    const expectedSet = new Set(t.expected.map((e) => e.type));
    const tpTypesHere = [];
    const fnTypesHere = [];
    for (const type of expectedSet) {
      if (detected.has(type)) tpTypesHere.push(type);
      else fnTypesHere.push(type);
    }
    const fpHere = [];
    for (const [type, sample] of detected) {
      if (!expectedSet.has(type)) fpHere.push(sample);
    }

    tp += tpTypesHere.length;
    fp += fpHere.length;
    fn += fnTypesHere.length;
    expectedTotal += expectedSet.size;
    detectedTotal += detected.size;
    for (const type of expectedSet) {
      expectedTypes.add(type);
      typeStats.get(type).expected++;
    }
    for (const type of tpTypesHere) {
      tpTypes.add(type);
      typeStats.get(type).tp++;
    }
    for (const type of fnTypesHere) typeStats.get(type).fn++;
    for (const sample of fpHere) {
      typeStats.get(sample.type).fp++;
      fpList.push({ target: t.id, url: t.url, type: sample.type, title: sample.title, check: sample.check, findingURL: sample.url });
    }
    for (const type of fnTypesHere) {
      const note = (t.expected.find((e) => e.type === type) || {}).note || "";
      fnList.push({ target: t.id, url: t.url, type, note });
    }

    if (expectedSet.size === 0) {
      secureCases++;
      if (fpHere.length > 0) fpCases++;
      else cleanSecureCases++;
    }

    if (status === "ok" || status === "scan_error") {
      if (expectedSet.size === 0) status = fpHere.length > 0 ? "fp" : "ok";
      else if (tpTypesHere.length === expectedSet.size && fpHere.length === 0) status = "ok";
      else if (tpTypesHere.length > 0) status = "partial";
      else status = "miss";
    }

    targets.push({
      id: t.id,
      url: (raw && typeof raw.url === "string" && raw.url) || t.url,
      expected: [...expectedSet],
      detected: [...detected.keys()],
      tp: tpTypesHere,
      fp: fpHere.map((x) => x.type),
      fn: fnTypesHere,
      status,
      duration: raw && Number.isFinite(raw.duration) ? raw.duration : null,
      error: raw && typeof raw.error === "string" ? raw.error : "",
      tags: t.tags,
    });
  }

  // raw 目录里多出来的结果文件（未在 ground-truth 中声明）只提示，不计分
  let extraRawFiles = 0;
  try {
    for (const name of fs.readdirSync(rawDir)) {
      if (!name.endsWith(".json")) continue;
      const id = name.slice(0, -".json".length);
      if (!truthIds.has(id)) extraRawFiles++;
    }
  } catch {
    /* raw 目录不可读时按 0 处理，主流程已在 readJson 报错 */
  }

  const metrics = {
    targets: targets.length,
    expected: expectedTotal,
    detected: detectedTotal,
    tp,
    fp,
    fn,
    precision: safeDiv(tp, tp + fp),
    recall: safeDiv(tp, tp + fn),
    f1: safeDiv(2 * tp, 2 * tp + fp + fn),
    expectedTypes: expectedTypes.size,
    detectedTypes: tpTypes.size,
    expectedTypeCoverage: safeDiv(tpTypes.size, expectedTypes.size),
    catalogTypes: catalog.types.length,
    catalogCoverage: safeDiv(tpTypes.size, catalog.types.length),
    secureCases,
    fpCases,
    cleanSecureCases,
    caseFPR: safeDiv(fpCases, secureCases),
    missingRaw,
    invalidRaw,
    scanErrorCases,
    outOfCatalog,
    extraRawFiles,
  };

  return {
    meta,
    targets,
    metrics,
    typeStats: [...typeStats.values()],
    fnList,
    fpList,
    outOfCatalogSamples,
  };
}

// ---------- 报告渲染 ----------

function frozenLine(frozen) {
  const keys = ["product", "version", "mode", "date", "note"];
  const parts = [];
  for (const k of keys) {
    if (frozen && frozen[k] !== undefined && frozen[k] !== "") parts.push(`${k}=${frozen[k]}`);
  }
  return parts.length > 0 ? parts.join("；") : "（未记录——评测必须冻结版本/配置/口径）";
}

function renderMarkdown(report) {
  const { meta, metrics, targets, typeStats, fnList, fpList, outOfCatalogSamples } = report;
  const lines = [];
  lines.push(`# 基准评测结果：${meta.suite}`);
  lines.push("");
  lines.push(`- 评分器：${meta.scorerVersion}`);
  lines.push(`- 套件版本：${meta.version || "（未标注）"}`);
  lines.push(`- 版本冻结：${frozenLine(meta.frozen)}`);
  lines.push(`- 覆盖率目录：${meta.catalogVersion || "（未标注）"}（${meta.catalogTypes} 类）`);
  lines.push(`- raw 目录：\`${meta.rawDir}\``);
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push("");
  lines.push("## 汇总指标");
  lines.push("");
  lines.push("| 指标 | 数值 | 原始计数 |");
  lines.push("|---|---:|---|");
  lines.push(`| Precision | ${ratio(metrics.precision)} | TP=${metrics.tp} FP=${metrics.fp} |`);
  lines.push(`| Recall | ${ratio(metrics.recall)} | TP=${metrics.tp} FN=${metrics.fn} |`);
  lines.push(`| F1 | ${ratio(metrics.f1)} | — |`);
  lines.push(`| 期望漏洞条目 | ${metrics.expected} | 检出类型 ${metrics.detected} |`);
  lines.push(`| 期望类型覆盖率 | ${pct(metrics.expectedTypeCoverage)} | ${metrics.detectedTypes}/${metrics.expectedTypes} |`);
  lines.push(`| 目录类型覆盖率（G02） | ${pct(metrics.catalogCoverage)} | ${metrics.detectedTypes}/${metrics.catalogTypes} |`);
  lines.push(`| 安全用例误报率 | ${pct(metrics.caseFPR)} | ${metrics.fpCases}/${metrics.secureCases} 用例误报 |`);
  lines.push(`| 缺失/异常 raw | ${metrics.missingRaw + metrics.invalidRaw} | missing=${metrics.missingRaw} invalid=${metrics.invalidRaw} |`);
  lines.push(`| 扫描报错用例 | ${metrics.scanErrorCases} | error 字段非空 |`);
  lines.push(`| 目录外检出（不计 FP） | ${metrics.outOfCatalog} | 配置建议类 finding |`);
  lines.push(`| 未声明的 raw 文件 | ${metrics.extraRawFiles} | ground-truth 中无对应 target |`);
  lines.push("");
  lines.push("## 类型明细");
  lines.push("");
  lines.push("| 类型 | 期望 | TP | FN | 额外误报 | OWASP | CNVD |");
  lines.push("|---|---:|---:|---:|---:|---|---|");
  for (const s of typeStats) {
    if (s.expected === 0 && s.fp === 0) continue;
    lines.push(`| ${s.label}（${s.id}） | ${s.expected} | ${s.tp} | ${s.fn} | ${s.fp} | ${s.owasp || ""} | ${s.cnvd || ""} |`);
  }
  lines.push("");
  lines.push("## 用例明细");
  lines.push("");
  lines.push("| 用例 | 期望 | 检出 | TP | FP | FN | 状态 |");
  lines.push("|---|---|---:|---:|---:|---:|---|");
  for (const t of targets) {
    lines.push(
      `| ${t.id} | ${t.expected.join(", ") || "（安全用例）"} | ${t.detected.join(", ") || "—"} | ${t.tp.length} | ${t.fp.length} | ${t.fn.length} | ${t.status} |`
    );
  }
  lines.push("");
  const MAX_LIST = 50;
  lines.push(`## False Negative（${fnList.length}）`);
  lines.push("");
  if (fnList.length === 0) lines.push("（无）");
  else {
    lines.push("| 用例 | 类型 | 备注 |");
    lines.push("|---|---|---|");
    for (const x of fnList.slice(0, MAX_LIST)) lines.push(`| ${x.target} | ${x.type} | ${x.note || ""} |`);
    if (fnList.length > MAX_LIST) lines.push(`\n> 其余 ${fnList.length - MAX_LIST} 条见 summary.csv/raw。`);
  }
  lines.push("");
  lines.push(`## False Positive（${fpList.length}）`);
  lines.push("");
  if (fpList.length === 0) lines.push("（无）");
  else {
    lines.push("| 用例 | 类型 | 检出标题 | check |");
    lines.push("|---|---|---|---|");
    for (const x of fpList.slice(0, MAX_LIST)) lines.push(`| ${x.target} | ${x.type} | ${x.title} | ${x.check} |`);
    if (fpList.length > MAX_LIST) lines.push(`\n> 其余 ${fpList.length - MAX_LIST} 条见 summary.csv/raw。`);
  }
  lines.push("");
  if (outOfCatalogSamples.length > 0) {
    lines.push(`## 目录外检出样例（共 ${metrics.outOfCatalog}，不计入 P/R）`);
    lines.push("");
    lines.push("| 用例 | 标题 | check | 来源 |");
    lines.push("|---|---|---|---|");
    for (const x of outOfCatalogSamples) lines.push(`| ${x.target} | ${x.title} | ${x.check} | ${x.source} |`);
    lines.push("");
  }
  lines.push("## 口径说明");
  lines.push("");
  lines.push("- 检出归一：`vulnerabilities[] + verified[] + extras.netsec.findings[]`，文本小写去符号后按目录别名映射；目录外 finding 不计 FP。");
  lines.push("- 同目标同类型多条检出只算 1 次；期望条目按类型去重标注（多实例拆独立 target）。");
  lines.push("- 安全用例（expected=[]）出现任意目录内检出即记误报用例；caseFPR = 误报用例 / 安全用例。");
  lines.push("- 完整定义与季度流程见 [docs/基准评测-5.2.md](../docs/基准评测-5.2.md)。");
  lines.push("");
  return lines.join("\n");
}

function renderCSV(report) {
  const { metrics, targets } = report;
  const lines = [];
  lines.push(csvRow(["target_id", "url", "expected_count", "detected_count", "tp", "fp", "fn", "status", "duration_s"]));
  for (const t of targets) {
    lines.push(
      csvRow([
        t.id,
        t.url,
        t.expected.length,
        t.detected.length,
        t.tp.length,
        t.fp.length,
        t.fn.length,
        t.status,
        t.duration === null ? "" : t.duration.toFixed(3),
      ])
    );
  }
  lines.push(
    csvRow(["TOTAL", "", metrics.expected, metrics.detected, metrics.tp, metrics.fp, metrics.fn, "", ""])
  );
  lines.push("");
  return lines.join("\n");
}

// ---------- 自检 ----------

const SELFTEST_EXPECT = {
  targets: 6,
  expected: 6,
  tp: 4,
  fp: 1,
  fn: 2,
  precision: 0.8,
  recall: 4 / 6,
  f1: 8 / 11,
  expectedTypes: 5,
  detectedTypes: 4,
  expectedTypeCoverage: 0.8,
  catalogTypes: 6,
  catalogCoverage: 4 / 6,
  secureCases: 2,
  fpCases: 1,
  cleanSecureCases: 1,
  caseFPR: 0.5,
  missingRaw: 1,
  invalidRaw: 0,
  scanErrorCases: 0,
  outOfCatalog: 1,
  extraRawFiles: 0,
};

function runSelftest() {
  const fx = path.join(SCRIPT_DIR, "fixtures");
  const rawDir = path.join(fx, "raw");
  const catalogFile = path.join(fx, "catalog.json");
  const truthFile = path.join(fx, "ground-truth.json");
  for (const p of [rawDir, catalogFile, truthFile]) {
    if (!fs.existsSync(p)) fail(`selftest 缺少 fixture：${p}（benchmark/fixtures/ 应随仓库提供）`);
  }
  const catalog = loadCatalog(catalogFile);
  const truth = loadTruth(truthFile, catalog);
  const report = score({ catalog, truth, rawDir });
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "sitelens-bench-selftest-"));
  const md = renderMarkdown(report);
  const csv = renderCSV(report);
  writeFile(path.join(outDir, "summary.md"), md);
  writeFile(path.join(outDir, "summary.csv"), csv);

  let checked = 0;
  const eq = (name, got, want) => {
    if (got !== want) fail(`selftest 断言失败 ${name}：got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
    checked++;
  };
  const close = (name, got, want, eps = 1e-9) => {
    if (!Number.isFinite(got) || Math.abs(got - want) > eps) {
      fail(`selftest 断言失败 ${name}：got=${got} want=${want}`);
    }
    checked++;
  };

  // 1) 指标数值
  for (const [k, want] of Object.entries(SELFTEST_EXPECT)) {
    const got = report.metrics[k];
    if (typeof want === "number" && !Number.isInteger(want)) close(`metrics.${k}`, got, want);
    else eq(`metrics.${k}`, got, want);
  }

  // 2) 逐用例：去重 / 安全用例 / 缺失 raw
  const byId = new Map(report.targets.map((t) => [t.id, t]));
  const t1 = byId.get("case-sqli-xss");
  eq("case-sqli-xss.tp", t1.tp.length, 2);
  eq("case-sqli-xss.detected 去重", t1.detected.length, 2);
  eq("case-sqli-xss.status", t1.status, "ok");
  const t4 = byId.get("case-secure-fp");
  eq("case-secure-fp.fp", t4.fp.length, 1);
  eq("case-secure-fp.status", t4.status, "fp");
  eq("case-missing.status", byId.get("case-missing").status, "missing_raw");
  eq("case-secure-clean.status", byId.get("case-secure-clean").status, "ok");
  eq("fn 明细条数", report.fnList.length, 2);
  eq("fp 明细条数", report.fpList.length, 1);

  // 3) 渲染产物：文件落盘 + 关键内容
  const mdOnDisk = fs.readFileSync(path.join(outDir, "summary.md"), "utf8");
  const csvOnDisk = fs.readFileSync(path.join(outDir, "summary.csv"), "utf8");
  eq("summary.md 含 Precision", mdOnDisk.includes("Precision"), true);
  eq("summary.md 含 F1=0.8000", mdOnDisk.includes("0.8000"), true);
  eq("summary.md 含 FN 小节", mdOnDisk.includes("False Negative（2）"), true);
  const csvLines = csvOnDisk.trimEnd().split("\n");
  eq("summary.csv 行数（表头+6 用例+TOTAL）", csvLines.length, 8);
  eq("summary.csv TOTAL 行", csvLines[csvLines.length - 1].startsWith("TOTAL,"), true);

  fs.rmSync(outDir, { recursive: true, force: true });

  const m = report.metrics;
  console.log(
    `[selftest] fixture=${path.relative(process.cwd(), fx)} TP=${m.tp} FP=${m.fp} FN=${m.fn} ` +
      `P=${ratio(m.precision)} R=${ratio(m.recall)} F1=${ratio(m.f1)}`
  );
  console.log(
    `[selftest] 类型覆盖=${pct(m.expectedTypeCoverage)}（${m.detectedTypes}/${m.expectedTypes}） ` +
      `目录覆盖=${pct(m.catalogCoverage)}（${m.detectedTypes}/${m.catalogTypes}） ` +
      `安全用例误报=${m.fpCases}/${m.secureCases} missing_raw=${m.missingRaw} out_of_catalog=${m.outOfCatalog}`
  );
  console.log(`SELFTEST PASS（${checked} 条断言）`);
}

// ---------- 主入口 ----------

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(USAGE);
    return;
  }
  if (opts.selftest) {
    runSelftest();
    return;
  }
  if (!opts.raw) fail(`缺少 --raw\n\n${USAGE}`);
  if (!opts.truth) fail(`缺少 --truth\n\n${USAGE}`);

  const rawDir = path.resolve(opts.raw);
  if (!fs.existsSync(rawDir) || !fs.statSync(rawDir).isDirectory()) {
    fail(`raw 目录不存在：${rawDir}`);
  }
  const truthFile = path.resolve(opts.truth);
  // 目录选择：显式 --catalog > ground-truth 自带 catalog 引用 > 仓库默认目录
  const truthPeek = readJson(truthFile);
  const truthCatalogRef =
    typeof truthPeek.catalog === "string" && truthPeek.catalog.trim() !== ""
      ? path.resolve(path.dirname(truthFile), truthPeek.catalog)
      : "";
  const catalogFile = opts.catalog
    ? path.resolve(opts.catalog)
    : truthCatalogRef || path.join(SCRIPT_DIR, "coverage-catalog.json");
  const catalog = loadCatalog(catalogFile);
  const truth = loadTruth(truthFile, catalog);
  if (opts.suite) truth.suite = opts.suite;
  const outDir = opts.out ? path.resolve(opts.out) : path.join(path.dirname(rawDir), "out");

  const report = score({ catalog, truth, rawDir });
  writeFile(path.join(outDir, "summary.md"), renderMarkdown(report));
  writeFile(path.join(outDir, "summary.csv"), renderCSV(report));

  const m = report.metrics;
  if (!opts.quiet) {
    console.log(`suite=${report.meta.suite} targets=${m.targets} TP=${m.tp} FP=${m.fp} FN=${m.fn}`);
    console.log(`Precision=${ratio(m.precision)} Recall=${ratio(m.recall)} F1=${ratio(m.f1)}`);
    console.log(
      `类型覆盖=${pct(m.expectedTypeCoverage)}（${m.detectedTypes}/${m.expectedTypes}） ` +
        `目录覆盖=${pct(m.catalogCoverage)}（${m.detectedTypes}/${m.catalogTypes}）`
    );
    if (m.missingRaw + m.invalidRaw > 0) {
      console.log(`警告：missing_raw=${m.missingRaw} invalid_raw=${m.invalidRaw}（对应期望条目记为 FN）`);
    }
    if (m.extraRawFiles > 0) console.log(`警告：${m.extraRawFiles} 个 raw 文件未在 ground-truth 中声明，已忽略`);
  }
  console.log(`summary: ${path.join(outDir, "summary.md")}`);
  console.log(`csv:     ${path.join(outDir, "summary.csv")}`);
}

try {
  main();
} catch (e) {
  console.error(`score.mjs 失败：${e.userFacing ? e.message : e.stack || e.message}`);
  process.exitCode = 1;
}
