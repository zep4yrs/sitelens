// 透明启动页（无底板）：logo 弹性浮现 + "sitelens" 描边逐笔画字，
// 没有窗口框、没有底色——像一枚浮在桌面上的品牌挂件。
// 引擎冷启动（加载全量情报与模板索引）期间它就是唯一的可见面：
// 状态文字报告进度；失败时显示错误再淡出，由主窗口接管错误页。
//
// 时序（与 TODO.md 设计一致）：
//   0s    logo 从 scale(.6)+opacity(0) 弹性放大
//   0.3s  描边文字逐笔画出轮廓（stroke-dashoffset）
//   1.8s  轮廓画完，文字从空心过渡到实色
//   2.4s  状态文字「正在启动引擎…」淡入
"use strict";
const { BrowserWindow } = require('electron');

let splashWin = null;

function buildPage(logoTag) {
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><style>' +
    '*{box-sizing:border-box;margin:0}' +
    'body{height:100vh;display:flex;flex-direction:column;justify-content:center;' +
    'align-items:center;background:transparent;overflow:hidden;user-select:none;' +
    'transition:opacity .45s ease}' +
    'body.out{opacity:0}' +
    '@keyframes pop{from{opacity:0;transform:scale(.6)}' +
    '60%{transform:scale(1.06)}to{opacity:1;transform:scale(1)}}' +
    '@keyframes draw{to{stroke-dashoffset:0}}' +
    '@keyframes solid{to{fill:#f1f5f9}}' +
    '@keyframes bar{0%{left:-40%}100%{left:100%}}' +
    '.logo{width:76px;height:76px;animation:pop .8s cubic-bezier(.22,1,.36,1) both}' +
    '.word{margin-top:12px}' +
    '.word text{font-family:Consolas,ui-monospace,monospace;font-weight:700;font-size:40px;' +
    'letter-spacing:3px;fill:transparent;stroke:#f1f5f9;stroke-width:.8;' +
    'stroke-dasharray:900;stroke-dashoffset:900;' +
    'animation:draw 1.4s cubic-bezier(.4,0,.2,1) .3s forwards,' +
    'solid .5s ease 1.8s forwards}' +
    '.bar{margin-top:16px;width:130px;height:2px;border-radius:99px;' +
    'background:rgba(255,255,255,.10);overflow:hidden;position:relative}' +
    '.bar i{position:absolute;height:100%;width:40%;border-radius:99px;' +
    'background:#22c55e;animation:bar 1.2s ease-in-out infinite}' +
    '.status{margin-top:14px;font-size:12px;color:#94a3b8;opacity:0;' +
    'animation:st_in .5s ease 2.4s forwards;font-family:' +
    '"LXGW WenKai","Noto Sans SC","Microsoft YaHei",sans-serif}' +
    '.status.err{color:#f87171;animation:st_in .3s ease forwards}' +
    '@keyframes st_in{to{opacity:1}}' +
    '</style></head><body>' +
    logoTag +
    '<div class="word"><svg viewBox="0 0 320 60" width="310" height="58">' +
    '<text x="160" y="44" text-anchor="middle" fill="transparent" stroke="#f1f5f9" ' +
    'stroke-width="0.8" stroke-dasharray="900" stroke-dashoffset="900" ' +
    'font-family="Consolas,ui-monospace,monospace" font-weight="700" font-size="40" ' +
    'letter-spacing="3">sitelens</text></svg></div>' +
    '<div class="bar"><i></i></div>' +
    '<div class="status" id="st">正在启动引擎…</div>' +
    '<script>function setStatus(t){var e=document.getElementById("st");' +
    'e.className="status";e.textContent=t}' +
    'function setError(t){var e=document.getElementById("st");' +
    'e.className="status err";e.textContent=t}' +
    'function fadeOut(){document.body.classList.add("out")}<\/script>' +
    '</body></html>';
}

// showSplash 显示启动页；logoDataUrl 为 logo 的 data:image/png;base64 URL
//（可空：空时只保留描边文字动画）。
function showSplash(logoDataUrl) {
  if (splashWin && !splashWin.isDestroyed()) return;
  splashWin = new BrowserWindow({
    width: 400,
    height: 280,
    transparent: true,
    frame: false,
    resizable: false,
    movable: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    hasShadow: false,
    show: false,
    center: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true }
  });
  var logoTag = logoDataUrl
    ? '<img class="logo" src="' + logoDataUrl + '" alt="">'
    : '';
  splashWin.loadURL('data:text/html;charset=utf-8,' +
    encodeURIComponent(buildPage(logoTag)));
  splashWin.once('ready-to-show', function () {
    if (splashWin && !splashWin.isDestroyed()) splashWin.show();
  });
  // 兜底：透明窗个别 GPU 环境不触发 ready-to-show
  setTimeout(function () {
    if (splashWin && !splashWin.isDestroyed() && !splashWin.isVisible()) {
      splashWin.show();
    }
  }, 3000);
}

// setStatus 更新状态文字（引擎阶段提示，如「首次启动需加载全量情报…」）。
function setStatus(text) {
  if (!splashWin || splashWin.isDestroyed()) return;
  splashWin.webContents.executeJavaScript(
    'setStatus(' + JSON.stringify(String(text || '')) + ')').catch(function () {});
}

// splashFail 显示错误 3.5 秒后淡出关闭（主窗口随后接管错误页）。
function splashFail(text) {
  if (!splashWin || splashWin.isDestroyed()) return;
  var w = splashWin;
  w.webContents.executeJavaScript(
    'setError(' + JSON.stringify(String(text || '启动失败')) + ')').catch(function () {});
  setTimeout(function () { fadeAndClose(w); }, 3500);
}

// closeSplash 淡出并关闭（引擎就绪，主窗口即将淡入）。
function closeSplash() {
  var w = splashWin;
  splashWin = null;
  if (!w || w.isDestroyed()) return;
  w.webContents.executeJavaScript('fadeOut()').catch(function () {});
  setTimeout(function () {
    if (!w.isDestroyed()) w.destroy(); // destroy：跳过 close 事件链，动画已自理
  }, 500);
}

function fadeAndClose(w) {
  if (splashWin === w) splashWin = null;
  if (w.isDestroyed()) return;
  w.webContents.executeJavaScript('fadeOut()').catch(function () {});
  setTimeout(function () {
    if (!w.isDestroyed()) w.destroy();
  }, 500);
}

module.exports = { showSplash, setStatus, splashFail, closeSplash };
