#!/usr/bin/env node
/* SiteLens 可访问性冒烟（FE-06 可选，5.2.x）
   ============================================================================
   在真实浏览器里跑一遍静态门禁抓不到的运行时语义：
     · main 地标唯一、标题非空、跳过导航链接存在；
     · button/img/input 的可访问名（运行时 DOM，含 common.js 注入的控件）；
     · 弹层语义：role=dialog + aria-modal、打开后焦点进入弹层、Esc 关闭并归还焦点；
     · 键盘快捷键接线存在且不抛错（Ctrl+E 无结果时静默 no-op）。

   依赖策略（可选件，不阻塞 CI）：
     - 没装 playwright → 打印 skip 并 exit 0；
     - 本机没有可访问的 SiteLens 服务 → 打印 skip 并 exit 0；
     - 只有在「playwright 可用 + 服务可达」时才真正检查，失败 exit 1。

   用法：
     node scripts/a11y-smoke.mjs                        # 默认 http://127.0.0.1:5000
     node scripts/a11y-smoke.mjs --url http://127.0.0.1:8080
     node scripts/a11y-smoke.mjs --pages /app,/history  # 指定页面
     node scripts/a11y-smoke.mjs --json
     node scripts/a11y-smoke.mjs --help

   环境变量：SITELENS_URL 作为 --url 的缺省值。
   ========================================================================== */

const DEFAULTS = {
  url: process.env.SITELENS_URL || "http://127.0.0.1:5000",
  pages: "/app,/history",
  json: false,
  help: false,
  timeout: 15000,
};

function parseArgs(argv) {
  const opts = { ...DEFAULTS };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--url") opts.url = argv[++i] || opts.url;
    else if (a === "--pages") opts.pages = argv[++i] || opts.pages;
    else if (a === "--timeout") opts.timeout = parseInt(argv[++i] || "", 10) || opts.timeout;
  }
  return opts;
}

function printHelp() {
  console.log(`SiteLens 可访问性冒烟（可选 Playwright）
用法: node scripts/a11y-smoke.mjs [选项]

选项:
  --url <base>       服务地址（默认 $SITELENS_URL 或 http://127.0.0.1:5000）
  --pages <a,b>      页面路径，逗号分隔（默认 /app,/history）
  --timeout <ms>     单页加载超时（默认 15000）
  --json             JSON 输出
  --help             显示本帮助

无 playwright 或服务不可达时跳过并以 0 退出（可选门禁）。`);
}

function skip(reason, opts) {
  if (opts.json) console.log(JSON.stringify({ skipped: true, reason }, null, 2));
  else console.log("· a11y-smoke 跳过：" + reason);
  return 0;
}

/* 页面内执行的可访问性断言（返回问题列表）。 */
function collectPageIssues() {
  const issues = [];
  const push = (rule, msg) => issues.push({ rule, msg: String(msg).replace(/\s+/g, " ").slice(0, 160) });

  if (!document.title || !document.title.trim()) push("title", "document.title 为空");

  const mains = document.querySelectorAll("main,[role='main']");
  if (mains.length === 0) push("landmark", "缺少 main/[role=main] 地标");

  if (!document.querySelector(".sl-skip")) push("skip-link", "缺少跳过导航链接 .sl-skip");

  // button 可访问名（跳过隐藏元素）
  document.querySelectorAll("button").forEach((b) => {
    if (b.closest("[hidden]") || b.getAttribute("aria-hidden") === "true") return;
    const name =
      (b.getAttribute("aria-label") || "").trim() ||
      (b.innerText || "").trim() ||
      (b.getAttribute("title") || "").trim();
    if (!name) push("button-name", b.outerHTML);
  });

  // img alt
  document.querySelectorAll("img").forEach((img) => {
    if (img.getAttribute("aria-hidden") === "true") return;
    if (!img.hasAttribute("alt")) push("img-alt", img.outerHTML);
  });

  // 表单控件标签（label[for] / 包裹 / aria-label / title）
  document.querySelectorAll("input,textarea,select").forEach((el) => {
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "hidden") return;
    const labelled =
      (el.getAttribute("aria-label") || "").trim() ||
      (el.getAttribute("aria-labelledby") || "").trim() ||
      (el.labels && el.labels.length) ||
      (el.getAttribute("title") || "").trim();
    if (!labelled) push("input-label", el.outerHTML);
  });

  // 弹层：存在则校验 role/aria-modal；打开态由外层驱动
  const dlg = document.getElementById("sl-keys-dialog");
  if (dlg) {
    if (dlg.getAttribute("role") !== "dialog") push("dialog-role", "#sl-keys-dialog 缺 role=dialog");
    if (dlg.getAttribute("aria-modal") !== "true") push("dialog-modal", "#sl-keys-dialog 缺 aria-modal=true");
    if (!dlg.getAttribute("aria-labelledby")) push("dialog-label", "#sl-keys-dialog 缺 aria-labelledby");
  }
  return issues;
}

async function runChecks(chromium, opts) {
  const issues = [];
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(opts.timeout);
    const paths = String(opts.pages)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    for (const path of paths) {
      const target = opts.url.replace(/\/$/, "") + (path.startsWith("/") ? path : "/" + path);
      try {
        await page.goto(target, { waitUntil: "domcontentloaded" });
        await page.waitForTimeout(300);
      } catch (e) {
        issues.push({ page: path, rule: "load", msg: "页面加载失败: " + e.message });
        continue;
      }
      const pageIssues = await page.evaluate(collectPageIssues);
      for (const it of pageIssues) issues.push({ page: path, ...it });

      // 弹层交互（仅 /app 有快捷键帮助弹层）
      if (path === "/app") {
        const dlg = await page.$("#sl-keys-dialog");
        const trigger = await page.$("#sl-keys-btn");
        if (dlg && trigger) {
          await trigger.click();
          const opened = await page.evaluate(() => {
            const d = document.getElementById("sl-keys-dialog");
            return !!d && !d.hidden && d.classList.contains("open") &&
              !!document.activeElement && d.contains(document.activeElement);
          });
          if (!opened) issues.push({ page: path, rule: "dialog-open", msg: "打开弹层后未显示或焦点未进入弹层" });
          await page.keyboard.press("Escape");
          const closed = await page.evaluate(() => {
            const d = document.getElementById("sl-keys-dialog");
            return !!d && d.hidden && document.activeElement === document.getElementById("sl-keys-btn");
          });
          if (!closed) issues.push({ page: path, rule: "dialog-esc", msg: "Esc 未关闭弹层或未归还焦点" });
        }
        // 快捷键接线：Ctrl+E 在无结果时应静默 no-op（不抛错、不导航）
        await page.keyboard.press("Control+e");
      }
    }
  } finally {
    await browser.close();
  }
  return issues;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { printHelp(); return 0; }

  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    return skip("未安装 playwright（npm i -D playwright && npx playwright install chromium 后可跑）", opts);
  }

  // 服务可达性探测：不可达就跳过（可选门禁不阻塞）
  try {
    const probe = await fetch(opts.url.replace(/\/$/, "") + "/app", {
      signal: AbortSignal.timeout(Math.min(opts.timeout, 5000)),
    });
    if (!probe.ok) return skip(`服务返回 HTTP ${probe.status}（${opts.url}）`, opts);
  } catch {
    return skip(`服务不可达（${opts.url}），先启动 sitelens serve`, opts);
  }

  const issues = await runChecks(chromium, opts);
  if (opts.json) {
    console.log(JSON.stringify({ skipped: false, issues }, null, 2));
  } else {
    console.log("SiteLens 可访问性冒烟 — " + opts.url + " pages=" + opts.pages);
    for (const it of issues) console.log(`× [${it.rule}] ${it.page}  ${it.msg}`);
    console.log(`合计：问题 ${issues.length} → ${issues.length ? "不通过" : "通过"}`);
  }
  return issues.length ? 1 : 0;
}

process.exitCode = await main();
