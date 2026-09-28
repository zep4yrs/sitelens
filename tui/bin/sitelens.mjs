#!/usr/bin/env node
// sitelens 命令入口：
//   sitelens                     交互式 TUI（TTY 下）
//   sitelens scan <url>          非交互扫描（管道/CI；--json 出完整结果）
//   sitelens serve [args...]     引擎 serve 直通（复用包内引擎二进制）
//   sitelens --version | help
import { main } from "../src/cli.mjs";

const argv = process.argv.slice(2);
const cmd = argv[0];

if (cmd === "--version" || cmd === "-v") {
  const v = (await import("../package.json", { with: { type: "json" } })).default.version;
  console.log(`sitelens-cli v${v}`);
  process.exit(0);
}
if (cmd === "help" || cmd === "--help" || cmd === "-h") {
  help();
  process.exit(0);
}
if (cmd === "scan") {
  process.exit(await main(argv.slice(1)));
}
if (cmd === "serve") {
  const { passthroughServe } = await import("../src/engine.mjs");
  process.exit(await passthroughServe(argv.slice(1)));
}
if (cmd === undefined) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    help();
    process.exit(2);
  }
  const { runTUI } = await import("../dist/app.mjs");
  process.exit(await runTUI());
}
help();
process.exit(2);

function help() {
  console.log(`SiteLens 站点透视 —— 终端扫描台

用法：
  sitelens                     交互式 TUI
  sitelens scan <url>          非交互扫描
      --level <L>              quick|standard|deep|full|assets|stealth|apocalypse（默认 standard）
      --json                   结果以完整 JSON 输出到 stdout（摘要走 stderr）
      --allow-private          允许内网/保留地址目标（本机靶场/授权内网；等价 SITLENS_ALLOW_PRIVATE=1）
      --timeout <秒>           扫描超时（默认 1800）
  sitelens serve [args...]     引擎 serve 直通（参数原样传递）
  sitelens --version

引擎二进制解析顺序：环境变量 SITLENS_ENGINE → 随包平台包
（@fengqiao666/sitelens-<平台>-engine）→ PATH 中的 sitelens。
扫描历史与状态落 ~/.sitelens/；引擎完整能力见项目主页。`);
}
