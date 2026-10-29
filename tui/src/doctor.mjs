// doctor.mjs —— 只读诊断类命令：doctor / history / verified。
//
// 三者都走引擎的 HTTP API（起一次私有 serve，用完即停）——不新增引擎端点，
// 复用既有 /api/diagnostics、/api/history、/api/verified。
//
// doctor 的价值：它直接回答"为什么某个功能没输出"——绝大多数"没结果"其实是
// 某个数据资产缺失导致该能力静默降级，诊断包的「资产就位矩阵」一眼可见。
import { startServe } from "./engine.mjs";
import { C, dim, kv, table, truncate } from "./ui.mjs";

const err = (s) => process.stderr.write(s + "\n");
const out = (s) => process.stdout.write(s + "\n");

/** 起一次引擎服务，执行 fn(baseUrl)，用完即停。 */
async function withEngine(fn, { allowPrivate = false } = {}) {
  let srv;
  try {
    srv = await startServe((m) => err(dim(m)), { allowPrivate });
  } catch (e) {
    err(`${C.red}${e.message}${C.reset}`);
    return 1;
  }
  try {
    return await fn(srv.baseUrl);
  } catch (e) {
    err(`${C.red}${e.message}${C.reset}`);
    return 1;
  } finally {
    await srv.stop();
  }
}

async function getJson(baseUrl, path) {
  const r = await fetch(baseUrl + path);
  if (!r.ok) throw new Error(`GET ${path} 返回 HTTP ${r.status}`);
  return r.json();
}

/**
 * doctor —— 生成本机脱敏诊断包并渲染。
 *
 * 与桌面端「反馈」页同一个接口（GET /api/diagnostics）：同一套口径，
 * 两端看到的内容一致。诊断包**只在本机生成**，本命令不联网、不上传。
 */
export async function doctorCmd(args) {
  const json = args.includes("--json");
  return withEngine(async (base) => {
    const rep = await getJson(base, "/api/diagnostics");
    if (json) {
      out(JSON.stringify(rep, null, 2));
      return 0;
    }
    out(`${C.bold}SiteLens 本机诊断${C.reset}`);
    kv(out, "生成时间", rep.generated_at ?? "-");
    kv(out, "引擎版本", rep.version ?? "-");
    kv(out, "平台", `${rep.platform ?? "-"}（${rep.runtime?.go_version ?? "-"}）`);

    out("");
    out(`${C.bold}数据资产就位情况${C.reset}`);
    const rows = (rep.assets ?? []).map((a) => [
      a.name,
      a.present ? `${C.green}就位${C.reset}` : `${C.red}缺失${C.reset}`,
      a.size_kb ? `${a.size_kb} KB` : "-",
      truncate(a.note || "", 40),
    ]);
    if (rows.length) table(out, ["资产", "状态", "体积", "缺失影响"], rows);
    else out(dim("  （无资产信息）"));

    if ((rep.degraded ?? []).length) {
      out("");
      out(`${C.amber}当前降级的能力${C.reset}`);
      for (const d of rep.degraded) out(`  ${C.amber}·${C.reset} ${d}`);
    } else {
      out("");
      out(dim("当前无降级能力——全部能力均处于完整状态。"));
    }

    if ((rep.recent_errors ?? []).length) {
      out("");
      out(`${C.red}最近的失败记录${C.reset}`);
      for (const e of rep.recent_errors) out(`  ${truncate(e, 110)}`);
    }
    out("");
    out(dim("提示：本诊断包不含 Token、凭证与完整目标地址；需要反馈请用「反馈」入口或复制上面的内容到 Issue。"));
    return 0;
  });
}

/** history —— 扫描历史列表。 */
export async function historyCmd(args) {
  const limit = Number(args.find((a) => !a.startsWith("-")) || 20) || 20;
  const json = args.includes("--json");
  return withEngine(async (base) => {
    const rep = await getJson(base, `/api/history?limit=${limit}`);
    const list = rep.scans ?? [];
    if (json) {
      out(JSON.stringify(list, null, 2));
      return 0;
    }
    if (!list.length) {
      out(dim("暂无扫描历史。"));
      return 0;
    }
    out(`${C.bold}扫描历史${C.reset}（最近 ${list.length} 条）`);
    const rows = list.map((s) => [
      String(s.id ?? "-"),
      truncate(s.url ?? "-", 44),
      s.security_grade ?? "-",
      String(s.tech_count ?? 0),
      String(s.vuln_count ?? 0),
      truncate(s.scanned_at ?? "-", 19),
    ]);
    table(out, ["#", "目标", "评分", "技术", "情报", "时间"], rows);
    return 0;
  });
}

/** verified —— 跨扫描的已验证发现汇总。 */
export async function verifiedCmd(args) {
  const limit = Number(args.find((a) => !a.startsWith("-")) || 20) || 20;
  const json = args.includes("--json");
  return withEngine(async (base) => {
    const rep = await getJson(base, `/api/verified?limit=${limit}`);
    const list = rep.items ?? [];
    if (json) {
      out(JSON.stringify(list, null, 2));
      return 0;
    }
    if (!list.length) {
      out(dim("暂无已验证发现。"));
      return 0;
    }
    out(`${C.bold}已验证发现汇总${C.reset}（最近 ${list.length} 条）`);
    const rows = list.map((v) => [
      v.severity ?? "-",
      truncate(v.title ?? "-", 40),
      truncate(v.url ?? "-", 44),
    ]);
    table(out, ["严重度", "检测项", "地址"], rows);
    return 0;
  });
}
