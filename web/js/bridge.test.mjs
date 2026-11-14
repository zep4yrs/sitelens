// D-06 回归测试：web/js/bridge.js（window.sitelens）。
//
// 测的是**真实源码**（读取文件后用 fake window 求值，不是复制实现）：
//   1) 浏览器形态（无 Wails 运行时）：available=false，所有方法安全降级、绝不抛异常；
//   2) 壳内形态（有 window._wails.invoke）：
//      a. 壳静态信息经 URL fragment 注入（window.__slShellInfoB64）时，只读信息
//         直接从注入值 resolve，**不发任何 postMessage**（Wails beta.22 回包通道
//         在引擎页面不落地，生产路径就是这条）；
//      b. 无注入时保留前向兼容的回包协议 {sl:{id,method,args}}；
//   3) 单向动作（Set*/CheckUpdate/InstallUpdate/OpenDataDir）只发不等待；
//   4) 旧方法别名（设置页「桌面端」页签在用）字段/取值映射正确。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const src = readFileSync(new URL("./bridge.js", import.meta.url), "utf8");

/** 在 fake window 上求值 bridge.js，返回该 window（含 sitelens）。 */
function loadBridge(fakeWindow) {
  const win = fakeWindow || {};
  const moduleObj = { exports: {} };
  // eslint-disable-next-line no-new-func
  new Function("window", "module", src)(win, moduleObj);
  return win;
}

const b64url = (obj) => Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");

test("浏览器形态：available=false，方法全部安全降级且不抛异常", async () => {
  const win = loadBridge({});
  const api = win.sitelens;
  assert.equal(api.available, false);
  // 所有方法都必须存在且返回 Promise（不 reject）
  const names = ["GetInfo", "GetAutoStart", "SetAutoStart", "GetCloseAction",
    "SetCloseAction", "CheckUpdate", "InstallUpdate", "OpenDataDir",
    "desktopGetInfo", "desktopSetAutoStart", "desktopSetCloseAction",
    "desktopOpenDataDir", "checkUpdate", "installUpdate"];
  for (const n of names) {
    assert.equal(typeof api[n], "function", `缺少方法 ${n}`);
    const p = api[n](n.indexOf("Set") === 0 ? true : undefined);
    assert.ok(p instanceof Promise, `${n} 应返回 Promise`);
    await p; // 不得 reject
  }
  assert.equal(await api.GetInfo(), null);
  assert.equal(await api.GetAutoStart(), false);
  assert.equal(await api.SetAutoStart(true), false);
  assert.equal(await api.GetCloseAction(), "exit");
  assert.equal(await api.SetCloseAction("tray"), "exit");
  assert.equal(await api.desktopGetInfo(), null);
  assert.deepEqual(await api.checkUpdate(), { state: "error" });
  assert.equal(typeof api.onDownloaded(function () {}), "function");
});

/** 壳内形态：捕获 postMessage，返回 {win, sent}。 */
function loadShellBridge() {
  const sent = [];
  const win = loadBridge({
    _wails: { invoke: (s) => sent.push(JSON.parse(s)) },
  });
  return { win, sent, api: win.sitelens };
}

// ---- 生产路径：壳静态信息随 URL fragment 注入，不发 postMessage ----
test("注入形态：GetInfo/GetAutoStart/GetCloseAction 直接取注入值，零 postMessage", async () => {
  const sent = [];
  const win = loadBridge({
    _wails: { invoke: (s) => sent.push(JSON.parse(s)) },
    __slShellInfoB64: b64url({
      product_version: "5.2.3", engine_version: "5.2.3",
      install_dir: "C:\\Program Files\\SiteLens", data_dir: "C:\\Users\\u\\AppData\\Roaming\\SiteLens-Wails\\state",
      autostart: true, close_action: "tray",
    }),
  });
  const api = win.sitelens;
  assert.equal(api.available, true);
  assert.deepEqual(await api.GetInfo(), {
    product_version: "5.2.3", engine_version: "5.2.3",
    install_dir: "C:\\Program Files\\SiteLens",
    data_dir: "C:\\Users\\u\\AppData\\Roaming\\SiteLens-Wails\\state",
    autostart: true, close_action: "tray",
  });
  assert.equal(await api.GetAutoStart(), true);
  assert.equal(await api.GetCloseAction(), "tray");
  assert.equal((await api.desktopGetInfo()).installDir, "C:\\Program Files\\SiteLens");
  assert.equal(sent.length, 0, "注入路径不应发送任何 postMessage");
});

test("注入值损坏时安全降级（不抛异常，回落回包通道）", async () => {
  const win = loadBridge({ __slShellInfoB64: "!!!not-base64!!!" });
  const api = win.sitelens;
  assert.equal(await api.GetInfo(), null); // available=false → call 直接 null
});

test("跨页导航：localStorage 持久化的 si 也能取到", async () => {
  const si = b64url({
    product_version: "5.2.3", engine_version: "5.2.3",
    install_dir: "C:\\App", data_dir: "C:\\State",
    autostart: true, close_action: "exit",
  });
  const win = loadBridge({
    localStorage: { getItem: (k) => (k === "sl_shell_si" ? si : null) },
  });
  const info = await win.sitelens.GetInfo();
  assert.equal(info.product_version, "5.2.3");
  assert.equal(info.install_dir, "C:\\App");
  assert.equal(await win.sitelens.GetAutoStart(), true);
  assert.equal(await win.sitelens.GetCloseAction(), "exit");
});

// ---- 前向兼容：无注入时仍保留回包协议 ----
test("无注入且壳内：协议字段为 {sl:{id,method,args}}，回包 resolve", async () => {
  const { win, api, sent } = loadShellBridge();
  const p = api.GetInfo();
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0], { sl: { id: 1, method: "GetInfo", args: [] } });
  win.__slShellReply({ id: 1, ok: true, result: { product_version: "5.3.0" } });
  assert.deepEqual(await p, { product_version: "5.3.0" });
});

test("失败回包 resolve(null)（契约：绝不 reject）", async () => {
  const { win, api } = loadShellBridge();
  const p = api.GetInfo();
  win.__slShellReply({ id: 1, ok: false, error: "boom" });
  assert.equal(await p, null);
});

test("单向动作只发不等：SetAutoStart/SetCloseAction/检查更新", async () => {
  const { api, sent } = loadShellBridge();
  // 不等待回包即 resolve（避免 8s 超时把 UI 卡住）
  assert.equal(await api.SetAutoStart(true), true);
  assert.equal(await api.SetCloseAction("tray"), "tray");
  assert.equal((await api.CheckUpdate()).state, "sent");
  assert.equal((await api.checkUpdate()).state, "sent");
  assert.equal(await api.InstallUpdate(), true);
  assert.equal(await api.OpenDataDir(), true);
  assert.deepEqual(sent[0].sl, { id: 1, method: "SetAutoStart", args: [true] });
  assert.deepEqual(sent[1].sl, { id: 2, method: "SetCloseAction", args: ["tray"] });
  assert.deepEqual(sent[2].sl.method, "CheckUpdate");
  assert.deepEqual(sent[3].sl.method, "CheckUpdate");
  assert.deepEqual(sent[4].sl.method, "InstallUpdate");
  assert.deepEqual(sent[5].sl.method, "OpenDataDir");
});

test("旧方法别名：desktopSetCloseAction 值映射 + 无注入时 desktopGetInfo 回包映射", async () => {
  const { win, api, sent } = loadShellBridge();

  // Go "exit" ↔ 旧 UI "quit"
  assert.equal(await api.desktopSetCloseAction("quit"), "quit");
  assert.equal(await api.desktopSetCloseAction("tray"), "tray");

  const infoP = api.desktopGetInfo();
  // 前两个单向动作已占用 id 1/2，desktopGetInfo 的请求 id 从 3 起
  const last = sent[sent.length - 1].sl;
  win.__slShellReply({
    id: last.id, ok: true,
    result: {
      product_version: "5.3.0", engine_version: "5.3.0", install_dir: "C:\\App",
      data_dir: "C:\\Data", autostart: true, close_action: "tray",
    },
  });
  assert.deepEqual(await infoP, {
    version: "5.3.0", engineVersion: "5.3.0", installDir: "C:\\App",
    dataDir: "C:\\Data", autoStart: true, autoUpdate: true, closeAction: "tray",
  });
});

test("回包带未知 id / 非对象负载时忽略且不抛异常", () => {
  const { win } = loadShellBridge();
  assert.doesNotThrow(() => win.__slShellReply({ id: 999, ok: true, result: 1 }));
  assert.doesNotThrow(() => win.__slShellReply(null));
  assert.doesNotThrow(() => win.__slShellReply("x"));
});

test("无 setTimeout 的极端环境也不抛异常", async () => {
  // bridge.js 内部对 setTimeout 有 try/catch；这里只验证加载与调用不炸
  const win = loadBridge({ chrome: { webview: { postMessage: () => {} } } });
  assert.equal(win.sitelens.available, true);
  assert.doesNotThrow(() => win.sitelens.GetInfo());
  // 清掉未决调用的 8s 超时定时器
  win.__slShellReply({ id: 1, ok: true, result: null });
});
