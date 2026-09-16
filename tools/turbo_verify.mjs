// Turbo 接入验证：CDP 附加 WebView2，设标记→点侧栏→验标记存活（未整页重载）+ 各页渲染。
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

function send(method, params = {}, sessionId) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
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
      exceptions.push(msg.params?.exceptionDetails?.text || "exception");
    }
  };
  await send("Runtime.enable");

  async function evalJs(expr) {
    const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error("eval: " + JSON.stringify(r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result.value;
  }

  // 等引擎 UI 就绪：侧栏链接真的可点（启动期有重定向，等稳定的最终文档）
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try {
      if (await evalJs("!!(window.Turbo && document.querySelector('.side-nav a[data-key=\"history\"]') && document.querySelector('main.page'))")) {
        ready = true; break;
      }
    } catch {}
    await sleep(500);
  }
  if (!ready) throw new Error("app not ready");
  await sleep(500); // 首帧脚本全部落定

  await evalJs("window.__slMarker = 42; window.Turbo ? 'turbo-present' : 'turbo-missing'");

  const pages = [
    ["history", "/history"], ["settings", "/settings"], ["chain", "/chain"],
    ["batch", "/batch"], ["intel", "/intel"], ["audit", "/audit"], ["scan", "/app"],
  ];
  const results = [];
  for (const [key, wantPath] of pages) {
    const clicked = await evalJs(`(function(){
      var a = document.querySelector('.side-nav a[data-key="${key}"]');
      if (!a) return 'no-link';
      a.click(); return 'clicked';
    })()`);
    if (clicked !== "clicked") { results.push({ key, error: clicked }); continue; }
    // 轮询等 Turbo 完成换页（数据重的页面首取 > 900ms）
    let path = null;
    for (let i = 0; i < 20; i++) {
      await sleep(300);
      path = await evalJs("location.pathname");
      if (path === wantPath) break;
    }
    const state = await evalJs(`(function(){
      return {
        marker: window.__slMarker === undefined ? null : window.__slMarker,
        sidebar: document.querySelectorAll('.wb-side').length,
        main: !!document.querySelector('main.page'),
        active: (document.querySelector('.side-nav a.active')||{}).getAttribute?.('data-key') || null
      };
    })()`);
    results.push({ key, path, wantPath, ...state });
  }
  console.log(JSON.stringify({ results, exceptions: exceptions.slice(0, 5) }, null, 1));

  const allOk = results.every((r) =>
    r.marker === 42 && r.sidebar === 1 && r.main &&
    r.path === r.wantPath && r.active === r.key);
  console.log(allOk && exceptions.length === 0 ? "VERIFY-PASS" : "VERIFY-FAIL");
  process.exit(allOk && exceptions.length === 0 ? 0 : 1);
};

main().catch((e) => { console.error("VERIFY-ERROR", e.message); process.exit(2); });
