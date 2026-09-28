// cli.mjs —— 非交互 scan 主流程（管道/CI 友好）：进度与事件走 stderr，
// 结果 JSON 走 stdout（--json 完整结果，默认摘要），退出码 0/1。
import { startServe } from "./engine.mjs";
import { scan, LEVELS } from "./client.mjs";

const SEV_COLOR = { critical: "\x1b[31;1m", high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m", info: "\x1b[90m" };
const C = { dim: "\x1b[2m", red: "\x1b[31m", amber: "\x1b[33m", cyan: "\x1b[36m", reset: "\x1b[0m", bold: "\x1b[1m" };
const colorOf = (kind) => (kind === "hit" ? C.red : kind === "bypass" ? C.amber : kind === "auth" ? C.cyan : C.dim);

export async function main(args) {
  let url = null;
  let level = "standard";
  let asJson = false;
  let allowPrivate = process.env.SITLENS_ALLOW_PRIVATE === "1";
  let timeoutSec = 1800;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--level") level = (args[++i] || "").toLowerCase();
    else if (a === "--json") asJson = true;
    else if (a === "--allow-private") allowPrivate = true;
    else if (a === "--timeout") timeoutSec = Number(args[++i]) || 1800;
    else if (!a.startsWith("-")) url = a;
  }
  if (!url) {
    console.error("用法：sitelens scan <url> [--level L] [--json] [--timeout 秒]");
    return 2;
  }
  if (!LEVELS.includes(level)) {
    console.error(`未知 level：${level}（可选：${LEVELS.join(" / ")}）`);
    return 2;
  }
  const dim = process.stderr.isTTY ? (s) => C.dim + s + C.reset : (s) => "";
  const err = (s) => process.stderr.write(s + "\n");

  let srv;
  try {
    srv = await startServe((m) => err(dim(m)), { allowPrivate });
  } catch (e) {
    err(`${C.red}${e.message}${C.reset}`);
    return 1;
  }
  err(dim(`引擎就绪（${srv.engineFrom}）：${srv.baseUrl}`));
  const t0 = Date.now();
  try {
    const job = await scan(srv.baseUrl, url, {
      level,
      timeoutSec,
      onProgress: (pct, msg) => {
        const line = `[${String(pct).padStart(3)}%] ${msg ?? ""}`;
        process.stderr.write(process.stderr.isTTY ? `\r${C.dim}${line}${C.reset}\x1b[K` : line + "\n");
      },
      onEvent: (kind, text) => err(`${colorOf(kind)}${kind}${C.reset} ${text}`),
    });
    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    if (asJson) {
      console.log(JSON.stringify(job.results ?? {}, null, 2));
    }
    summarize(err, job.results, url, level, secs, asJson);
    return 0;
  } catch (e) {
    err(`${C.red}${e.message}${C.reset}`);
    return 1;
  } finally {
    await srv.stop();
  }
}

function summarize(out, res, url, level, secs, asJson) {
  if (!res) return;
  const techs = res.technologies?.length ?? 0;
  const verified = res.verified ?? [];
  const vulns = res.vulnerabilities?.length ?? 0;
  const ml = res.extras?.ml_prior;
  out(`\n${C.bold}${url}${C.reset}（${level}，${secs}s）：${techs} 项技术，${verified.length} 条已验证发现，${vulns} 条漏洞情报`);
  if (ml) {
    const top = ml.products?.[0];
    out(dim(`ML 先验：${top?.product}（${top?.prob}）提权 ${ml.boosted} 项` + (ml.promoted?.length ? `、增量纳入 ${ml.promoted.length} 项` : "")));
  }
  const bySev = {};
  for (const v of verified) bySev[v.severity] = (bySev[v.severity] || 0) + 1;
  if (verified.length) {
    out("  " + Object.entries(bySev).map(([s, n]) => `${SEV_COLOR[s] ?? ""}${s}×${n}${C.reset}`).join("  "));
  }
  for (const v of verified.slice(0, 20)) {
    out(`  ${SEV_COLOR[v.severity] ?? ""}[${v.severity}]${C.reset} ${v.title}  ${dim(v.url ?? "")}`);
  }
  if (verified.length > 20) out(dim(`  …其余 ${verified.length - 20} 条见 --json 输出`));
  if (asJson) out(dim("（完整结果已输出到 stdout）"));
}
