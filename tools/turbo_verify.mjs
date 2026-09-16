// Turbo + 双区布局验证：
//  A) 顶栏四个被动页（设置/情报库/历史/攻击链）：点击 → Turbo 换页（标记存活=未整页重载）
//  B) 工作台五个模式（综合扫描/网络层检测/登录爆破/源码审计/批量扫描）：
//     点击左栏模式行 → 控制面板 + 画布面板联动
// 用法: node tools/turbo_verify.mjs [port]
const port = process.argv[2] || "9223";
const base = "http://127.0.0.1:" + port;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getPageWs() {
  for (let i = 0; i < 20; i++) {
    try {
      const list = await (await fetch(base + "/json/list")).json();
      const page = list.find((t) => t.type === "page" && /^http:\/\/127\.0\.0\.1/.test(t.url));
      if (page) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(500);
  }
  throw new Error("no CDP page target");
}

let seq = 0;
const pending = new Map();
let ws;
const exceptions = [];

function send(method, params = {}) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const main = async () => {
  const wsUrl = await getPageWs();
  ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    } else if (msg.method === "Runtime.exceptionThrown") {
      exceptions.push(JSON.stringify({
        text: msg.params?.exceptionDetails?.text,
        desc: (msg.params?.exceptionDetails?.exception?.description || "").slice(0, 200),
      }));
    }
  };
  await send("Runtime.enable");

  async function evalJs(expr) {
    const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error("eval: " + JSON.stringify(r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result.value;
  }

  // 等应用就绪（顶栏；工作台模式行待导航回 /app 后再验）
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try {
      if (await evalJs(`!!(window.Turbo && document.querySelector('.top-nav a[data-key="history"]') && document.querySelector('.tw-modes .tab[data-tab="scan"]'))`)) {
        ready = true; break;
      }
    } catch {}
    await sleep(500);
  }
  if (!ready) throw new Error("app not ready");
  // 稳定判定：就绪后 1s 仍在（启动期可能有会话恢复式被动导航）
  await sleep(1000);
  if (!(await evalJs(`!!(window.Turbo && document.querySelector('.top-nav a[data-key="history"]') && document.querySelector('.tw-modes .tab[data-tab="scan"]'))`))) {
    throw new Error("app not stable");
  }
  await sleep(300);
  await evalJs("window.__slMarker = 42");

  const results = [];

  // A) 顶栏被动页
  for (const [key, wantPath] of [["intel", "/intel"], ["history", "/history"], ["chain", "/chain"], ["settings", "/settings"]]) {
    let clicked = 'no-link';
    for (let t = 0; t < 3; t++) {
      clicked = await evalJs(`(function(){
        var a = document.querySelector('.top-nav a[data-key="${key}"]');
        if (!a) return 'no-link'; a.click(); return 'clicked';
      })()`);
      if (clicked === 'clicked') break;
      await sleep(1000);
    }
    if (clicked !== "clicked") { results.push({ key, error: clicked }); continue; }
    let path = null;
    for (let i = 0; i < 20; i++) {
      await sleep(300);
      path = await evalJs("location.pathname");
      if (path === wantPath) break;
    }
    results.push({
      kind: "top", key, path, wantPath,
      marker: await evalJs("window.__slMarker ?? null"),
      topbar: await evalJs("document.querySelectorAll('.tw-toolbar').length"),
      active: await evalJs(`(document.querySelector('.top-nav a.active')||{}).getAttribute?.('data-key') || null`),
    });
  }

  // 回工作台（确定性：Turbo.visit 直达）
  await evalJs(`window.Turbo.visit("/app#scan")`);
  for (let i = 0; i < 20; i++) {
    await sleep(300);
    if (await evalJs("location.pathname") === "/app") break;
  }

  // B) 工作台五模式
  for (const mode of ["netsec", "loginbrute", "audit", "batch", "scan"]) {
    const clicked = await evalJs(`(function(){
      var b = document.querySelector('.tw-modes .tab[data-tab="${mode}"]');
      if (!b) return 'no-tab'; b.click(); return 'clicked';
    })()`);
    if (clicked !== "clicked") { results.push({ kind: "mode", key: mode, error: clicked }); continue; }
    let panel = false;
    for (let i = 0; i < 10; i++) {
      await sleep(300);
      panel = await evalJs(`document.getElementById('tab-${mode}').classList.contains('active')`);
      if (panel) break;
    }
    results.push({
      kind: "mode", key: mode,
      marker: await evalJs("window.__slMarker ?? null"),
      panel: panel,
      canvas: await evalJs(`document.querySelector('.tw-canvaspane[data-pane="${mode}"]').classList.contains('active')`),
      active: await evalJs(`(document.querySelector('.tw-modes .tab.active')||{}).getAttribute?.('data-tab') || null`),
    });
  }

  console.log(JSON.stringify({ results, exceptions: exceptions.slice(0, 5) }, null, 1));

  const ok = results.every((r) =>
    r.kind === "top"
      ? r.marker === 42 && r.topbar === 1 && r.path === r.wantPath && r.active === r.key
      : r.marker === 42 && r.panel === true && r.canvas === true && r.active === r.key);
  console.log(ok && exceptions.length === 0 ? "VERIFY-PASS" : "VERIFY-FAIL");
  process.exit(ok && exceptions.length === 0 ? 0 : 1);
};

main().catch((e) => { console.error("VERIFY-ERROR", e.message); process.exit(2); });
