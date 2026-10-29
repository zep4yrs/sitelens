// commands.mjs —— 命令表（唯一事实源）。
//
// 5.2 起 Go CLI（cmd/sitelens）退回内部实现，用户只面对 TUI：扫描 / 源码审计 /
// 诊断 / 历史 / 数据更新 / 事实图 / 攻击链 / 回归 / PG 迁移，全部从这里进。
//
// help 也由本表生成——避免"命令表与帮助文案两处维护"漂移（与
// web/api-docs.html 与 internal/server/server.go 两处独立维护的教训同源）。
//
// 两层：
//   common   —— 终端用户日常用的
//   advanced —— 运维 / 进阶（数据更新、事实图、攻击链、回归、PG 迁移）
//
// 两种实现形态：
//   orchestrated —— TUI 自己起引擎 serve、走 HTTP API（scan / doctor / history / verified）
//   passthrough  —— 直接 spawn 引擎二进制执行原生命令，stdio 直通、退出码透传
//                   （serve / audit / correlate / graph-read / regression / migrate-pg / update-*）
import { main as scanCmd } from "./cli.mjs";
import { doctorCmd, historyCmd, verifiedCmd } from "./doctor.mjs";
import { passthrough, passthroughServe } from "./engine.mjs";

/** update 聚合子命令 → 引擎原生命令名。 */
export const UPDATE_TARGETS = {
  nuclei: { cmd: "update-nuclei", desc: "官方 Nuclei 模板库（数百 MB）" },
  afrog: { cmd: "update-afrog", desc: "afrog 社区 POC 库" },
  fp: { cmd: "update-fp", desc: "社区指纹库（webappanalyzer）" },
  ehole: { cmd: "update-ehole", desc: "EHole 中文产品指纹" },
  nvd: { cmd: "update-nvd", desc: "NVD CVE 全量字典（数十 MB）" },
  osv: { cmd: "update-osv", desc: "OSV 受影响区间与 CVSS 评分" },
  tplintel: { cmd: "update-tplintel", desc: "模板情报行（模板池 × NVD 关联）" },
};

/**
 * 命令清单。
 *
 * group    common | advanced
 * desc     一句话说明（help 与交互式菜单共用）
 * usage    用法行
 * options  选项说明行（help 渲染）
 * run      实现，参数为 argv 去掉子命令名后的数组，返回退出码
 */
export const COMMANDS = [
  {
    name: "scan",
    group: "common",
    desc: "非交互扫描（管道 / CI 友好）",
    usage: "sitelens scan <url> [选项]",
    options: [
      "--level <L>       quick|standard|deep|full|assets|stealth|apocalypse（默认 standard）",
      "--json            完整结果 JSON 输出到 stdout（摘要走 stderr）",
      "--allow-private   允许内网/保留地址目标（本机靶场 / 授权内网）",
      "--timeout <秒>    扫描超时（默认 1800）",
    ],
    run: (args) => scanCmd(args),
  },
  {
    name: "audit",
    group: "common",
    desc: "源码静态审计（污点分析 + 规则匹配）",
    usage: "sitelens audit <目录>",
    options: [],
    run: (args) => passthrough(["audit", ...args]),
  },
  {
    name: "doctor",
    group: "common",
    desc: "本机诊断：资产就位 / 降级能力 / 最近失败",
    usage: "sitelens doctor [--json]",
    options: ["--json            输出完整诊断包 JSON"],
    run: (args) => doctorCmd(args),
  },
  {
    name: "history",
    group: "common",
    desc: "扫描历史列表",
    usage: "sitelens history [条数] [--json]",
    options: ["--json            输出 JSON"],
    run: (args) => historyCmd(args),
  },
  {
    name: "verified",
    group: "common",
    desc: "跨扫描的已验证发现汇总",
    usage: "sitelens verified [条数] [--json]",
    options: ["--json            输出 JSON"],
    run: (args) => verifiedCmd(args),
  },
  {
    name: "serve",
    group: "common",
    desc: "启动引擎 Web 控制台（前台）",
    usage: "sitelens serve [引擎参数...]",
    options: [],
    run: (args) => passthroughServe(args),
  },

  {
    name: "update",
    group: "advanced",
    desc: "更新数据资产（模板库 / 指纹 / 情报）",
    usage: "sitelens update <目标> [引擎参数...]",
    options: Object.entries(UPDATE_TARGETS).map(
      ([k, v]) => `${k.padEnd(11)}${v.desc}`,
    ),
    run: async (args) => {
      const what = args[0];
      const t = what && UPDATE_TARGETS[what];
      if (!t) {
        console.error("用法：sitelens update <目标>");
        console.error("可选目标：\n" + Object.entries(UPDATE_TARGETS)
          .map(([k, v]) => `  ${k.padEnd(11)}${v.desc}`).join("\n"));
        return 2;
      }
      return passthrough([t.cmd, ...args.slice(1)]);
    },
  },
  {
    name: "correlate",
    group: "advanced",
    desc: "黑白盒事实图关联（合并两张图并建证据链）",
    usage: "sitelens correlate <blackbox.graph.jsonl> <whitebox.graph.jsonl>",
    options: [],
    run: (args) => passthrough(["correlate", ...args]),
  },
  {
    name: "graph-read",
    group: "advanced",
    desc: "读取结构化事实图（摘要 / 契约自检）",
    usage: "sitelens graph-read <file.graph.jsonl> [--self-test]",
    options: ["--self-test        只做契约自检（只读）"],
    run: (args) => passthrough(["graph-read", ...args]),
  },
  {
    name: "regression",
    group: "advanced",
    desc: "验证回归：重放历史扫描的已验证发现",
    usage: "sitelens regression <scan_id>",
    options: [],
    run: (args) => passthrough(["regression", ...args]),
  },
  {
    name: "migrate-pg",
    group: "advanced",
    desc: "历史库迁移（PG → 本地文件，一次性）",
    usage: "sitelens migrate-pg [-env <文件>] [-config <文件>]",
    options: [],
    run: (args) => passthrough(["migrate-pg", ...args]),
  },
];

/** 命令名 → 命令定义。 */
export const COMMAND_MAP = new Map(COMMANDS.map((c) => [c.name, c]));

/** 生成 help 文本（按 common / advanced 两层分组）。 */
export function renderHelp() {
  const lines = [];
  lines.push("SiteLens 站点透视 —— 终端扫描台");
  lines.push("");
  lines.push("用法：");
  lines.push("  sitelens                     交互式 TUI（选功能 → 扫描 / 审计 / 诊断 / 历史）");
  for (const g of ["common", "advanced"]) {
    const title = g === "common" ? "常用" : "高级（运维 / 进阶）";
    lines.push("");
    lines.push(`【${title}】`);
    for (const c of COMMANDS.filter((x) => x.group === g)) {
      lines.push(`  sitelens ${c.usage.replace(/^sitelens /, "")}`);
      lines.push(`      ${c.desc}`);
      for (const o of c.options ?? []) lines.push(`      ${o}`);
    }
  }
  lines.push("");
  lines.push("引擎二进制解析顺序：环境变量 SITELENS_ENGINE → 随包平台包");
  lines.push("（@fengqiao666/sitelens-<平台>-engine）→ PATH 中的 sitelens。");
  lines.push("用户区（数据/历史/配置）：~/.sitelens/");
  lines.push("扫描仅限授权目标，合规责任在使用者。");
  return lines.join("\n");
}
