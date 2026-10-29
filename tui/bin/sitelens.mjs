#!/usr/bin/env node
// sitelens 命令入口（命令表驱动）。
//
//   sitelens                     交互式 TUI（选功能 → 扫描 / 审计 / 诊断 / 历史）
//   sitelens <命令> [参数...]    见 sitelens --help
//   sitelens --version | help
//
// 命令清单的唯一事实源在 src/commands.mjs —— help 文本也由它生成，
// 不在这里另写一份（两处维护必然漂移）。
//
// 退出码一律用 process.exitCode 而非 process.exit()：强制退出会打断 Node
// 的 libuv 清理，Windows 上会抛 "Assertion failed: !(handle->flags &
// UV_HANDLE_CLOSING)"（0xC0000409）——表现为进程中止、退出码全丢。
import { COMMAND_MAP, renderHelp } from "../src/commands.mjs";

const argv = process.argv.slice(2);
const cmd = argv[0];

if (cmd === "--version" || cmd === "-v") {
  const v = (await import("../package.json", { with: { type: "json" } })).default.version;
  console.log(`sitelens-cli v${v}`);
  process.exitCode = 0;
} else if (cmd === "help" || cmd === "--help" || cmd === "-h") {
  console.log(renderHelp());
  process.exitCode = 0;
} else if (cmd === undefined) {
  // 无子命令：TTY 下进交互式 TUI；管道/CI 下打 help（不做无意义的扫描）
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(renderHelp());
    process.exitCode = 2;
  } else {
    const { runTUI } = await import("../dist/app.mjs");
    const action = await runTUI();
    if (!action) {
      process.exitCode = 0;
    } else {
      const def = COMMAND_MAP.get(action.cmd);
      if (!def) {
        console.error(`未知命令：${action.cmd}`);
        console.log(renderHelp());
        process.exitCode = 2;
      } else {
        process.exitCode = await def.run(action.args ?? []);
      }
    }
  }
} else {
  const def = COMMAND_MAP.get(cmd);
  if (!def) {
    console.error(`未知命令：${cmd}`);
    console.log(renderHelp());
    process.exitCode = 2;
  } else {
    process.exitCode = await def.run(argv.slice(1));
  }
}
