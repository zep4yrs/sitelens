/* D-06：桌面壳桥（window.sitelens）。
 *
 * 传输：页面 postMessage → Wails Options.RawMessageHandler（Go 侧
 * desktop-wails/bridge.go）→ ExecJS 调 window.__slShellReply 回包。
 * 为什么不用 Wails 生成的 bindings：主窗加载的是引擎页面（http 源），拿不到
 * /wails/runtime.js 与生成代码；RawMessageHandler 是 Wails v3 官方留的自定义通道。
 *
 * 契约（Lead 定稿）：方法全部返回 Promise；浏览器形态下 available=false，
 * 所有方法安全降级（resolve(null)/false），**绝不 reject、绝不抛异常**。
 * 另附 Electron 壳时代的旧方法名（desktop* / checkUpdate / installUpdate /
 * onDownloaded）作为别名，让已存在的设置页「桌面端」页签零改动可用。
 */
(function (root, factory) {
  var api = factory(root);
  if (root) root.sitelens = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : null, function (root) {
  "use strict";

  var TIMEOUT_MS = 8000;
  var pending = {};
  var seq = 0;

  function postFn() {
    if (!root) return null;
    if (root._wails && typeof root._wails.invoke === "function") {
      return function (s) { root._wails.invoke(s); };
    }
    if (root.chrome && root.chrome.webview &&
        typeof root.chrome.webview.postMessage === "function") {
      return function (s) { root.chrome.webview.postMessage(s); };
    }
    return null;
  }

  // postFn() 每次调用时重算：Wails 运行时可能晚于本脚本注入（见下方 shellReady）
  var available = false;

  // 壳 → 页面的回包入口（Go 侧 ExecJS 调用）。
  if (root) {
    root.__slShellReply = function (payload) {
      if (!payload || typeof payload !== "object") return;
      var p = pending[payload.id];
      if (!p) return;
      delete pending[payload.id];
      if (p.timer) { try { clearTimeout(p.timer); } catch (e) {} }
      // 失败也 resolve(null)：契约要求"绝不抛异常"
      p.resolve(payload.ok ? (payload.result === undefined ? null : payload.result) : null);
    };
  }

  function call(method, args) {
    var p = postFn();
    if (!p) return Promise.resolve(null);
    var id = ++seq;
    return new Promise(function (resolve) {
      var timer = null;
      try {
        timer = setTimeout(function () { delete pending[id]; resolve(null); }, TIMEOUT_MS);
      } catch (e) { /* 无 setTimeout 环境：不加超时 */ }
      pending[id] = { resolve: resolve, timer: timer };
      try {
        p(JSON.stringify({ sl: { id: id, method: method, args: args || [] } }));
      } catch (e) {
        delete pending[id];
        if (timer) { try { clearTimeout(timer); } catch (e2) {} }
        resolve(null);
      }
    });
  }

  function asBool(v) { return v === true; }

  // 关闭行为：Go 侧值域 "exit"|"tray"；旧 UI 用 "quit"|"tray"。
  function toUIAction(v) { return v === "tray" ? "tray" : "quit"; }
  function toGoAction(v) { return v === "tray" ? "tray" : "exit"; }

  // ---- 壳静态信息（URL fragment #si=<base64url JSON>）----
  // 为什么不用回包：Wails v3 beta.22 在「URL 指向引擎页面」的窗口上 ExecJS 不落地
  // （实测连 `window.__x=1` 都不执行、且无错误日志），回包永远收不到。GetInfo 这类
  // 只读信息由壳随 URL 一次性注入；写动作走单向 postMessage（入站通道已验证可靠）。
  function injectedInfo() {
    if (!root) return null;
    var b64 = root.__slShellInfoB64;
    if (!b64) {
      // 跨页导航（/settings 等）是新文档，URL fragment 不会跟过去；
      // common.js 在首屏把 si 持久化到 localStorage，这里读回。
      try { b64 = root.localStorage && root.localStorage.getItem("sl_shell_si"); } catch (e) { b64 = null; }
    }
    if (!b64) return null;
    try {
      b64 = String(b64).replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      var bin = atob(b64);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      var json = (typeof TextDecoder !== "undefined")
        ? new TextDecoder("utf-8").decode(bytes) : bin;
      return JSON.parse(json);
    } catch (e) { return null; }
  }
  var info = injectedInfo();

  // 桌面形态判定（5.2.3 修复）：加载瞬间 window._wails 可能尚未注入（Wails 运行时
  // 晚于页面脚本执行），但 si 注入（壳静态信息）本身已证明当前在桌面壳内。
  // 因此以「si 已注入 或 桥当前可用」为准；浏览器形态两者皆无 → false。
  function shellReady() { return !!(info || postFn()); }
  available = shellReady();

  // send 单向动作：不等待回包（回包通道当前不可用，见上）。
  function send(method, args) {
    var p = postFn();
    if (!p) return false;
    try {
      p(JSON.stringify({ sl: { id: ++seq, method: method, args: args || [] } }));
      return true;
    } catch (e) { return false; }
  }

  // infoOr 只读信息：优先注入值，其次尝试（前向兼容的）回包通道。
  function infoOr(method, map, fallback) {
    var pick = function (v) {
      if (v === null || v === undefined) return fallback === undefined ? null : fallback;
      return map ? map(v) : v;
    };
    if (info) return Promise.resolve(pick(info));
    return call(method).then(pick);
  }

  var api = {
    available: shellReady(),

    // ---- Lead 定稿契约 ----
    GetInfo: function () { return infoOr("GetInfo"); },
    GetAutoStart: function () {
      return infoOr("GetAutoStart", function (i) { return i.autostart === true; }, false).then(asBool);
    },
    SetAutoStart: function (on) {
      if (!shellReady()) return Promise.resolve(false);
      send("SetAutoStart", [!!on]);
      return Promise.resolve(!!on);
    },
    GetCloseAction: function () {
      return infoOr("GetCloseAction", function (i) { return i.close_action || "exit"; }, "exit");
    },
    SetCloseAction: function (a) {
      if (!shellReady()) return Promise.resolve("exit");
      var v = toGoAction(a);
      send("SetCloseAction", [v]);
      return Promise.resolve(v);
    },
    // 更新检查是长动作：壳收到即轮询更新源并把结果写 shell.log / 托盘通知；
    // 页面拿不到回包，返回 "sent" 让 UI 显示"已发起"而不是误报失败。
    CheckUpdate: function () {
      if (!shellReady()) return Promise.resolve({ state: "error" });
      send("CheckUpdate", []);
      return Promise.resolve({ state: "sent" });
    },
    InstallUpdate: function () {
      if (!shellReady()) return Promise.resolve(false);
      send("InstallUpdate", []);
      return Promise.resolve(true);
    },
    OpenDataDir: function () {
      if (!shellReady()) return Promise.resolve(false);
      send("OpenDataDir", []);
      return Promise.resolve(true);
    },

    // ---- 旧方法别名（设置页「桌面端」页签在用，保持兼容）----
    desktopGetInfo: function () {
      return infoOr("GetInfo").then(function (i) {
        if (!i) return null;
        return {
          version: i.product_version,
          engineVersion: i.engine_version,
          installDir: i.install_dir || "",
          dataDir: i.data_dir,
          autoStart: i.autostart === true,
          closeAction: toUIAction(i.close_action)
        };
      });
    },
    desktopSetAutoStart: function (on) {
      if (!shellReady()) return Promise.resolve(false);
      send("SetAutoStart", [!!on]);
      return Promise.resolve(!!on);
    },
    desktopSetCloseAction: function (v) {
      if (!shellReady()) return Promise.resolve("quit");
      var go = toGoAction(v);
      send("SetCloseAction", [go]);
      return Promise.resolve(toUIAction(go));
    },
    desktopOpenDataDir: function () {
      if (!shellReady()) return Promise.resolve(false);
      send("OpenDataDir", []);
      return Promise.resolve(true);
    },
    // 旧 UI 期望 {state, current, latest, feed}；回包不可用时返回 "sent"。
    checkUpdate: function () {
      if (!shellReady()) return Promise.resolve({ state: "error" });
      send("CheckUpdate", []);
      return Promise.resolve({ state: "sent" });
    },
    installUpdate: function () {
      if (!shellReady()) return Promise.resolve(false);
      send("InstallUpdate", []);
      return Promise.resolve(true);
    },
    // 壳侧更新是「确认 → 下载 → 校验 → 安装 → 退出」一次完成，没有"已下载待重启"
    // 中间态；保留空实现只为兼容旧 UI 的调用（不会回调）。
    onDownloaded: function () { return function () {}; }
  };
  return api;
});
