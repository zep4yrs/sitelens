// 透明启动页 v2「对焦」（2026-09-18 motion-web 升级）：
// 视觉契约（用户拍板 2026-09-18）= 透明无底板挂件（v1 语言）：浅色字/绿进度线，
// 容器只承载动画不加视觉。动效：logo 克制落位 → 细描边准星环绕画出+四刻度落定
// （透视锁定隐喻）→ sitelens 描边逐笔画出转实色 → 状态行/进度发丝线。
//
// ★ 同源双宿主：本文件与 desktop-wails/assets/splash.html（wails HTML 选项注入）
//   共享同一设计与时序——改任何一边必须同步另一边。
// 时序（Corporate --ease cubic-bezier(.2,0,0,1) 家族）：
//   0ms 底板 400ms / 100ms logo 450ms / 250ms 准星环 700ms（950ms 刻度）
//   350ms 描边字 900ms（1300ms 转实色 400ms）/ 600ms 状态行 / 350ms 起进度线循环
// 退场 fadeOut()：内容 150ms（transition）→ 整板 300ms（显式动画 plateOut——
//   撤 animation 与 transition 同帧不触发过渡，实测瞬跳，故退场走动画通道）。
// prefers-reduced-motion：全部直接终态，进度线静止。
"use strict";
const { BrowserWindow, app } = require('electron');

let splashWin = null;

function buildPage(logoTag, ver) {
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><style>' +
    ':root{--ease:cubic-bezier(.2,0,0,1);--fg:#f1f5f9;--muted:#94a3b8;--faint:#94a3b8;' +
    '--ok:#22c55e;--danger:#f87171;--track:rgba(255,255,255,.10)}' +
    '*{box-sizing:border-box;margin:0}' +
    'html,body{height:100%}' +
    'body{background:transparent;display:flex;align-items:center;justify-content:center;' +
    'overflow:hidden;user-select:none;font-family:"Noto Sans SC","Microsoft YaHei",sans-serif}' +
    '.plate{display:flex;align-items:center;justify-content:center;position:relative;' +
    'opacity:1;transform:none;animation:plateIn 400ms var(--ease) both;' +
    'transition:opacity 300ms var(--ease),transform 300ms var(--ease)}' +
    '@keyframes plateIn{from{opacity:0;transform:scale(.96)}}' +
    '.inner{display:flex;flex-direction:column;align-items:center;transition:opacity 150ms var(--ease)}' +
    '.mark{position:relative;width:76px;height:76px;margin-bottom:14px}' +
    '.mark .logo{width:76px;height:76px;opacity:1;animation:logoIn 450ms var(--ease) 100ms both}' +
    '@keyframes logoIn{from{opacity:0;transform:scale(1.05)}}' +
    '.reticle{position:absolute;inset:-26px;width:128px;height:128px;pointer-events:none}' +
    '.reticle .ring{fill:none;stroke:rgba(241,245,249,.55);stroke-width:1.5;' +
    'stroke-dasharray:340;stroke-dashoffset:340;animation:ringDraw 700ms var(--ease) 250ms forwards}' +
    '@keyframes ringDraw{to{stroke-dashoffset:0}}' +
    '.reticle .tick{stroke:var(--fg);stroke-width:1.5;opacity:0;' +
    'animation:tickIn 150ms var(--ease) 950ms forwards}' +
    '@keyframes tickIn{to{opacity:.45}}' +
    '.word{margin-top:2px}' +
    '.word text{font-family:Consolas,ui-monospace,monospace;font-weight:700;font-size:40px;' +
    'letter-spacing:3px;fill:transparent;stroke:var(--fg);stroke-width:.8;' +
    'stroke-dasharray:900;stroke-dashoffset:900;' +
    'animation:wordDraw 900ms var(--ease) 350ms forwards,' +
    'wordSolid 400ms var(--ease) 1300ms forwards}' +
    '@keyframes wordDraw{to{stroke-dashoffset:0}}' +
    '@keyframes wordSolid{to{fill:var(--fg)}}' +
    '.bar{margin-top:18px;width:150px;height:2px;border-radius:99px;background:var(--track);' +
    'overflow:hidden;position:relative;opacity:0;animation:fadeIn 250ms var(--ease) 350ms forwards}' +
    '.bar i{position:absolute;top:0;height:100%;width:34%;border-radius:99px;background:var(--ok);' +
    'animation:barSweep 1.15s var(--ease) infinite}' +
    '@keyframes barSweep{0%{left:-34%}100%{left:100%}}' +
    '@keyframes fadeIn{to{opacity:1}}' +
    '.status{margin-top:14px;font-size:12px;color:var(--muted);opacity:0;' +
    'animation:fadeIn 250ms var(--ease) 600ms forwards;' +
    'transition:opacity 150ms var(--ease),color 150ms var(--ease)}' +
    '.ver{position:absolute;right:16px;bottom:12px;font-family:Consolas,ui-monospace,monospace;' +
    'font-size:10.5px;color:var(--faint);opacity:0;animation:fadeIn 250ms var(--ease) 900ms forwards}' +
    'body.err .reticle .ring{stroke:var(--danger)}' +
    'body.err .reticle .tick{stroke:var(--danger);animation:tickIn 150ms var(--ease) forwards}' +
    'body.err .bar i{background:var(--danger);opacity:.85}' +
    'body.err .status{color:var(--danger);opacity:1;animation:none}' +
    'body.out .inner{opacity:0}' +
    'body.out .plate{animation:plateOut 300ms var(--ease) forwards}' +
    '@keyframes plateOut{to{opacity:0;transform:scale(.97)}}' +
    '@media (prefers-reduced-motion: reduce){' +
    '.plate,.mark .logo{opacity:1;transform:none;animation:none}' +
    '.reticle .ring{stroke-dashoffset:0;animation:none}' +
    '.reticle .tick{opacity:.45;animation:none}' +
    '.word text{stroke-dashoffset:0;fill:var(--fg);animation:none}' +
    '.bar{opacity:1;animation:none}.bar i{animation:none;left:33%}' +
    '.status,.ver{opacity:1;animation:none}' +
    '.plate,body.out .plate{transition:none;animation:none}' +
    'body.out .plate{opacity:0}' +
    '}' +
    '</style></head><body>' +
    '<div class="plate"><div class="inner">' +
    '<div class="mark">' +
    '<svg class="reticle" viewBox="0 0 128 128" aria-hidden="true">' +
    '<circle class="ring" cx="64" cy="64" r="54"></circle>' +
    '<line class="tick" x1="64" y1="2" x2="64" y2="10"></line>' +
    '<line class="tick" x1="126" y1="64" x2="118" y2="64"></line>' +
    '<line class="tick" x1="64" y1="126" x2="64" y2="118"></line>' +
    '<line class="tick" x1="2" y1="64" x2="10" y2="64"></line></svg>' +
    logoTag +
    '</div>' +
    '<div class="word"><svg viewBox="0 0 320 60" width="300" height="56" aria-label="sitelens">' +
    '<text x="160" y="44" text-anchor="middle">sitelens</text></svg></div>' +
    '<div class="bar"><i></i></div>' +
    '<div class="status" id="st">正在启动引擎…</div>' +
    '</div>' +
    (ver ? '<div class="ver">' + String(ver).replace(/[<>&]/g, '') + '</div>' : '') +
    '</div>' +
    '<script>function setStatus(t){swap(t,false)}' +
    'function setError(t){document.body.classList.add("err");swap(t,true)}' +
    'function swap(t,force){var e=document.getElementById("st");' +
    'e.style.opacity="0";' +
    'setTimeout(function(){e.textContent=String(t||"");e.style.opacity=force?"1":""},150)}' +
    'function fadeOut(){document.body.classList.add("out")}<\/script>' +
    '</body></html>';
}

// showSplash 显示启动页；logoTag 为 logo 的 data:image/png URL（可空=无 logo 降级隐藏品牌标）。
function showSplash(logoTag) {
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
    hasShadow: false, // 阴影由底板 CSS 自绘（透明窗 OS 阴影不可靠）
    show: false,
    center: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true }
  });
  var tag = logoTag
    ? '<img class="logo" alt="SiteLens" src="' + logoTag + '">'
    : '<img class="logo" alt="" style="display:none">';
  var ver = '';
  try { ver = app.getVersion() || ''; } catch (e) {}
  splashWin.loadURL('data:text/html;charset=utf-8,' +
    encodeURIComponent(buildPage(tag, ver)));
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

// setStatus 更新状态文字（150ms 交叉淡切，如「首次启动需加载全量情报…」）。
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
