// 现场探针：看 DOM/报错现场
const port = process.argv[2] || "9223";
const base = "http://127.0.0.1:" + port;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const list = await (await fetch(base + "/json/list")).json();
const page = list.find((t) => t.type === "page" && /^http:\/\/127\.0\.0\.1/.test(t.url));
if (!page) { console.log("NO-TARGET", JSON.stringify(list.map(t=>({t:t.type,u:t.url})))); process.exit(2); }
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let seq = 0; const pending = new Map(); const errors = [];
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); p(m.result); }
  if (m.method === "Runtime.exceptionThrown") {
    errors.push(m.params?.exceptionDetails?.exception?.description || m.params?.exceptionDetails?.text);
  }
};
const send = (method, params = {}) => new Promise((res) => { const id = ++seq; pending.set(id, res); ws.send(JSON.stringify({ id, method, params })); });
await send("Runtime.enable");

const evalJs = async (expr) => {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true });
  return r.exceptionDetails ? ("ERR: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text)) : r.result.value;
};

console.log("url      :", await evalJs("location.href"));
console.log("turbo    :", await evalJs("typeof window.Turbo"));
console.log("bodyHead :", await evalJs("(document.body ? document.body.innerHTML : 'NO-BODY').slice(0, 400)"));
console.log("scripts  :", await evalJs("[...document.scripts].map(s=>s.src||'inline').join(' | ')"));
console.log("slCommon :", await evalJs("!!window.__slCommonLoaded"));
console.log("api      :", await evalJs("typeof window.api"));
console.log("slPoll   :", await evalJs("typeof window.slPoll"));
console.log("errors   :", JSON.stringify(errors.slice(0, 6), null, 1));
process.exit(0);
