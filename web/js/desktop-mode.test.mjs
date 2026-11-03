// 回归守卫（5.2.3）：桌面形态判定不得再只依赖 Electron UA。
//
// 事故：settings.html 用 `/Electron/i.test(navigator.userAgent)` 判定「桌面版」，
// 而正式桌面壳已切到 Wails（WebView2），UA 不含 "Electron" → 桌面版也显示
// 「浏览器模式」，用户以为装的是浏览器版。正确判据是壳桥可用性
// （window.sitelens.available，由 web/js/bridge.js 在壳内设为 true）。
//
// 本用例是源码级守卫（settings.html 的内联脚本无法在 node 里直接跑 DOM），
// 防止后人把判定改回 UA-only。
import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../settings.html", import.meta.url), "utf8");

test("桌面形态判定必须以壳桥可用性为准（不是 Electron UA）", () => {
  const m = html.match(/var isDesktop = [^\n]*/);
  assert.ok(m, "settings.html 应保留 isDesktop 判定（verKind 显示依赖它）");
  const line = m[0];
  assert.ok(
    /window\.sitelens\s*&&\s*window\.sitelens\.available|window\.sitelens\.available/.test(line),
    `isDesktop 必须包含壳桥可用性判据，实际：${line}`
  );
  // 反向：不允许再出现「只看 Electron UA」的旧写法
  assert.ok(
    !/var isDesktop = \/Electron\/i\.test\(navigator\.userAgent\);\s*$/.test(line),
    "不得退回 Electron UA-only 判定（Wails 壳 UA 不含 Electron）"
  );
});
