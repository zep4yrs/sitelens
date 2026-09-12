// SiteLens 桌面版主进程（Electron 壳）。
//
// 架构约束：引擎与全部页面逻辑在 Go 单二进制里（sitelens serve +
// go:embed 前端），本进程只负责窗口/托盘/生命周期/自动更新——
// 引擎代码零改动。引擎子进程管理（拉起/端口/就绪探测/日志）在
// engine.js。引擎工作目录指向自带 data 载荷，数据写入依赖 NSIS
// 按用户安装（%LOCALAPPDATA%\Programs\SiteLens，用户可写）。
//
// 自动更新：electron-updater generic 多源轮询（CNB 主源 → Gitee → GitHub
// 镜像，哪个通就用哪个并粘住），引擎二进制随安装包整体更新；数据与模板
// 更新仍走引擎既有 update-* 渠道，不在此重复实现。
// 设置页「检查更新」按钮经 IPC（preload.js 暴露 window.sitelens）直连
// 本文件的更新器，真实检查、实时反馈、可直接重启升级。
const { app, BrowserWindow, Tray, Menu, dialog, nativeImage, shell, ipcMain } = require('electron');
const { autoUpdater } = require('electron-updater');
const fs = require('fs');
const path = require('path');
const engine = require('./engine');

const isDev = !app.isPackaged;
const RELEASES_URL = 'https://cnb.cool/feng-qiao/sitelens/releases';
// 更新源轮询顺序：CNB 主源（国内直连）→ Gitee 镜像 → GitHub 镜像。
// 三个源的 desktop-stable release 须放同一套三件套（exe/blockmap/latest.yml）。
const FEEDS = [
  { name: 'CNB', url: 'https://cnb.cool/feng-qiao/sitelens/-/releases/download/desktop-stable/' },
  { name: 'Gitee', url: 'https://gitee.com/map1ebridge/sitelens/releases/download/desktop-stable/' },
  { name: 'GitHub', url: 'https://github.com/zep4yrs/sitelens/releases/download/desktop-stable/' }
];
const ICON_PATH = isDev ? path.join(__dirname, 'build', 'icon.png')
  : path.join(process.resourcesPath, 'icon.png');

let win = null;
let tray = null;
let hideHintShown = false;
let quittingByUser = false;

// 桌面壳自身日志（userData/desktop.log）：启动里程碑与异常全落盘，
// 窗口不出现时用户拿得到证据，而不是静默无窗。
function bootLog(msg) {
  try {
    const file = path.join(app.getPath('userData'), 'desktop.log');
    const line = new Date().toISOString() + ' ' + msg + '\n';
    fs.appendFileSync(file, line);
  } catch (_) { /* 日志失败不影响主流程 */ }
}
process.on('uncaughtException', (err) => {
  bootLog('uncaughtException: ' + (err && err.stack || err));
});
process.on('unhandledRejection', (err) => {
  bootLog('unhandledRejection: ' + (err && err.stack || err));
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
}

// ---- 窗口与托盘 ----

// ---- 桌面端偏好（userData/desktop-prefs.json）：窗口边界 + 关闭按钮行为 ----
let deskPrefs = { closeAction: 'tray', bounds: null };

function loadDeskPrefs() {
  try {
    var raw = fs.readFileSync(path.join(app.getPath('userData'), 'desktop-prefs.json'), 'utf8');
    var p = JSON.parse(raw) || {};
    if (p.closeAction === 'quit' || p.closeAction === 'tray') deskPrefs.closeAction = p.closeAction;
    if (p.bounds && p.bounds.width >= 900 && p.bounds.height >= 600) deskPrefs.bounds = p.bounds;
  } catch (_) { /* 首次无偏好文件 */ }
}

function saveDeskPrefs() {
  try {
    fs.writeFileSync(path.join(app.getPath('userData'), 'desktop-prefs.json'),
      JSON.stringify(deskPrefs, null, 2));
  } catch (_) { /* 写失败不影响主流程 */ }
}

var boundsTimer = null;
function scheduleSaveBounds() {
  clearTimeout(boundsTimer);
  boundsTimer = setTimeout(function () {
    if (win && !win.isDestroyed() && !win.isMinimized() && win.isVisible()) {
      deskPrefs.bounds = win.getBounds();
      saveDeskPrefs();
    }
  }, 800);
}

function createWindow() {
  loadDeskPrefs();
  var opts = {
    width: 1380,
    height: 920,
    minWidth: 1080,
    minHeight: 700,
    title: 'SiteLens 站点透视',
    icon: ICON_PATH,
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true, // 渲染进程沙箱：纵深防御
      spellcheck: false,
      preload: path.join(__dirname, 'preload.js'), // 设置页经 window.sitelens 检查更新
    },
  };
  // 窗口大小与位置记忆：有有效存档则原样恢复
  if (deskPrefs.bounds) {
    opts.x = deskPrefs.bounds.x;
    opts.y = deskPrefs.bounds.y;
    opts.width = deskPrefs.bounds.width;
    opts.height = deskPrefs.bounds.height;
  }
  win = new BrowserWindow(opts);
  Menu.setApplicationMenu(null); // 页面导航/刷新快捷键交给页面自身
  win.on('resize', scheduleSaveBounds);
  win.on('move', scheduleSaveBounds);
  loadShellPage('正在启动引擎，全量情报与模板索引加载约需数秒…');
  const showNow = () => {
    if (win && !win.isDestroyed()) {
      win.show();
      bootLog('window shown');
    }
  };
  win.once('ready-to-show', showNow);
  // 兜底：ready-to-show 个别环境（GPU/驱动）不触发，8 秒后强制显示
  setTimeout(() => {
    if (win && !win.isVisible()) {
      bootLog('ready-to-show 超时，强制显示');
      showNow();
    }
  }, 8000);
  // 关闭按钮行为可配（设置 · 桌面端）：默认收进托盘（后台引擎继续跑扫描），
  // 也可选「直接退出」
  win.on('close', (e) => {
    if (quittingByUser) return;
    if (deskPrefs.closeAction === 'quit') {
      quittingByUser = true;
      app.quit();
      return;
    }
    e.preventDefault();
    win.hide();
    if (!hideHintShown) {
      hideHintShown = true;
      tray.displayBalloon({
        iconType: 'info',
        title: 'SiteLens 仍在运行',
        content: '扫描在后台继续。退出请用托盘图标右键菜单，或在设置 · 桌面端修改关闭行为。',
      });
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (sameOrigin(url)) return { action: 'allow' };
    shell.openExternal(url); // 外链交给系统浏览器
    return { action: 'deny' };
  });
}

// loadShellPage 壳内页（启动页 / 错误页）：不依赖引擎的本地内容。
function loadShellPage(title, detail) {
  if (!win || win.isDestroyed()) return;
  var html = '<!DOCTYPE html><html><head><meta charset="utf-8">' +
    '<style>body{margin:0;height:100vh;display:grid;place-items:center;' +
    'background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif}' +
    '.b{font-family:ui-monospace,Consolas,monospace;font-size:40px;' +
    'letter-spacing:.02em}.d{margin-top:16px;opacity:.75;font-size:14px;' +
    'max-width:560px;line-height:1.8;text-align:center}</style></head><body>' +
    '<div style="text-align:center"><div class="b">sitelens</div>' +
    '<div class="d">' + title + '</div>' +
    (detail ? '<div class="d" style="opacity:.5">' + detail + '</div>' : '') +
    '</div></body></html>';
  win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html))
    .catch(function () {});
}

// loadApp 引擎就绪后切换到工作台（带首连竞态重试与失败自愈）。
function loadApp() {
  if (!win || win.isDestroyed()) return;
  win.loadURL(engine.url).then(() => bootLog('loadApp ok')).catch((err) => {
    bootLog('loadApp failed: ' + err);
    setTimeout(() => {
      win.loadURL(engine.url).catch((e2) => bootLog('loadApp retry failed: ' + e2));
    }, 1200);
  });
  win.webContents.on('did-fail-load', (_e, code, desc, url) => {
    // 子资源失败也会进这里；只对主框架报警并重试
    if (!sameOrigin(url)) return;
    bootLog('did-fail-load: ' + code + ' ' + desc);
    setTimeout(() => win.loadURL(engine.url).catch(() => {}), 1500);
  });
}

// sameOrigin 严格同源判断（前缀匹配会被 127.0.0.1:5087.evil.com 绕过）。
function sameOrigin(url) {
  try {
    return new URL(url).origin === new URL(engine.url).origin;
  } catch (_) {
    return false;
  }
}

function showWindow() {
  if (win && !win.isDestroyed()) {
    win.show();
    win.focus();
  }
}

function createTray() {
  tray = new Tray(nativeImage.createFromPath(ICON_PATH));
  tray.setToolTip('SiteLens 站点透视');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'SiteLens v' + app.getVersion(), enabled: false },
    { type: 'separator' },
    { label: '显示主界面', click: showWindow },
    { label: '检查更新', click: () => checkUpdates(true) },
    { label: '打开数据目录', click: () => shell.openPath(app.getPath('userData')) },
    { type: 'separator' },
    {
      label: '开机自启',
      type: 'checkbox',
      checked: app.getLoginItemSettings().openAtLogin,
      click: (item) => app.setLoginItemSettings({ openAtLogin: item.checked }),
    },
    {
      label: '退出 SiteLens',
      click: () => {
        quittingByUser = true;
        app.quit();
      },
    },
  ]));
  tray.on('double-click', showWindow);
}

// ---- 自动更新 ----

let feedIdx = 0;          // 上次成功的更新源（粘住，减少来回试）
let checking = false;     // 并发检查合并：托盘/设置页/周期检查共用一次
let checkPromise = null;

// runUpdateCheck 全源采样执行一次检查：逐源读 latest.yml（只查不下载），
// 取 releaseDate 最新的源作为事实源再触发下载。手工同步的镜像可能滞后，
// 只看「版本号相等」就报已是最新，会把滞后的镜像当真相（静默漏更）。
// 返回 { state: latest|available|dev|error, current, latest, feed, error }。
async function runUpdateCheck() {
  var current = app.getVersion();
  if (isDev) return { state: 'dev', current };
  if (checking) return checkPromise;
  checking = true;
  checkPromise = (async function () {
    var samples = [];
    for (var i = 0; i < FEEDS.length; i++) {
      var feed = FEEDS[i];
      try {
        autoUpdater.setFeedURL({ provider: 'generic', url: feed.url });
        var r = await autoUpdater.checkForUpdates(); // autoDownload=false：只查
        var info = r && r.updateInfo ? r.updateInfo : null;
        if (info && info.version) {
          samples.push({
            feed: feed, version: info.version,
            date: Date.parse(info.releaseDate) || 0
          });
          bootLog('update sample via ' + feed.name + ': v' + info.version);
        }
      } catch (err) {
        bootLog('update check failed via ' + feed.name + ': ' + (err && err.message || err));
      }
    }
    if (!samples.length) {
      return { state: 'error', current: current, error: '所有更新源均不可达' };
    }
    // releaseDate 最新者为事实源；同刻并列时保持 FEEDS 优先级顺序
    var best = samples[0];
    for (var j = 1; j < samples.length; j++) {
      if (samples[j].date > best.date) best = samples[j];
    }
    feedIdx = FEEDS.indexOf(best.feed);
    if (best.version === current) {
      bootLog('update: up to date (v' + current + ', source ' + best.feed.name + ')');
      return { state: 'latest', current: current, latest: best.version, feed: best.feed.name };
    }
    // 从最新源触发下载；完成走 update-downloaded 事件
    bootLog('update available: v' + best.version + ' via ' + best.feed.name + ', downloading…');
    await autoUpdater.downloadUpdate();
    return { state: 'available', current: current, latest: best.version, feed: best.feed.name };
  }());
  try {
    return await checkPromise;
  } finally {
    checking = false;
    checkPromise = null;
  }
}

// checkUpdates 托盘/周期入口：静默执行，manual 时以弹窗汇报结论。
function checkUpdates(manual) {
  runUpdateCheck().then(function (r) {
    if (!manual || r.state === 'dev') return;
    if (r.state === 'latest') {
      dialog.showMessageBox({ type: 'info', message: '已是最新版本 v' + r.current + '。' });
    } else if (r.state === 'available') {
      dialog.showMessageBox({
        type: 'info',
        message: '发现新版本 v' + r.latest + '',
        detail: '正在后台下载（更新源：' + r.feed + '），完成后会提示你重启升级。'
      });
    } else {
      dialog.showMessageBox({ type: 'info', message: '检查更新失败：所有更新源均不可达。' });
    }
  });
}

function setupUpdater() {
  // 下载改为「全源采样选最新」后显式触发（downloadUpdate），不再自动随检查启动
  autoUpdater.autoDownload = false;
  var notifiedVer = "";   // 已气泡提醒过的版本：同一版本不重复打扰
  var dialogedVer = "";   // 已弹过「立即重启」的版本：用户选「稍后」后只轻提醒
  autoUpdater.on('update-available', (info) => {
    if (info && info.version === notifiedVer) return;
    notifiedVer = info && info.version;
    bootLog('update available: v' + notifiedVer + ', downloading…');
    tray.displayBalloon({
      iconType: 'info',
      title: '发现新版本',
      content: '正在后台下载 SiteLens 更新…',
    });
  });
  autoUpdater.on('update-downloaded', (info) => {
    var ver = info && info.version ? info.version : '';
    bootLog('update downloaded: v' + ver);
    // 广播给全部窗口：设置页「关于与更新」实时更新状态并提供重启按钮
    BrowserWindow.getAllWindows().forEach(function (w) {
      if (!w.isDestroyed()) w.webContents.send('update:downloaded', ver);
    });
    // E2E 测试钩子：设置 SITLENS_E2E_UPDATE 时自动安装（真机全链路验证用）
    if (process.env.SITLENS_E2E_UPDATE) {
      bootLog('e2e: auto quitAndInstall');
      quittingByUser = true;
      setTimeout(() => autoUpdater.quitAndInstall(), 3000);
      return;
    }
    var label = ver ? 'v' + ver : '';
    if (ver && ver === dialogedVer) {
      // 选过「稍后」的同一版本：托盘轻提醒即可
      tray.displayBalloon({
        iconType: 'info',
        title: 'SiteLens ' + label + ' 已就绪',
        content: '重启应用即完成更新。',
      });
      return;
    }
    dialogedVer = ver;
    dialog.showMessageBox({
      type: 'info',
      buttons: ['立即重启', '稍后'],
      defaultId: 0,
      message: 'SiteLens ' + label + ' 已就绪',
      detail: '重启应用即完成更新（后台引擎一并升级）。',
    }).then(({ response }) => {
      if (response === 0) {
        quittingByUser = true;
        autoUpdater.quitAndInstall();
      }
    });
  });
  autoUpdater.on('error', (err) => {
    bootLog('updater error: ' + (err && err.message || err));
  });
}

// IPC：设置页（渲染进程）经 preload 暴露的 window.sitelens 调用
function setupIpc() {
  ipcMain.handle('update:check', function () { return runUpdateCheck(); });
  ipcMain.handle('update:install', function () {
    quittingByUser = true;
    autoUpdater.quitAndInstall();
  });
  ipcMain.handle('update:openReleases', function () {
    shell.openExternal(RELEASES_URL);
  });
  // 桌面端信息与偏好（设置 · 桌面端页签）
  ipcMain.handle('desktop:getInfo', function () {
    return {
      version: app.getVersion(),
      installDir: path.dirname(app.getPath('exe')),
      dataDir: app.getPath('userData'),
      autoStart: app.getLoginItemSettings().openAtLogin,
      closeAction: deskPrefs.closeAction,
      isDev: isDev
    };
  });
  ipcMain.handle('desktop:setAutoStart', function (_e, on) {
    app.setLoginItemSettings({ openAtLogin: !!on });
    return app.getLoginItemSettings().openAtLogin;
  });
  ipcMain.handle('desktop:setCloseAction', function (_e, v) {
    if (v === 'quit' || v === 'tray') {
      deskPrefs.closeAction = v;
      saveDeskPrefs();
    }
    return deskPrefs.closeAction;
  });
  ipcMain.handle('desktop:openDataDir', function () {
    shell.openPath(app.getPath('userData'));
  });
}

// 启动静默检查一次；此后每 6 小时复查（长驻进程也能收到新版本）。
// 周期性检查失败/无更新完全静默。
function startUpdateLoop() {
  checkUpdates(false);
  setInterval(function () { checkUpdates(false); }, 6 * 60 * 60 * 1000);
}

// ---- 生命周期 ----

// 引擎崩溃自愈：5 分钟窗口内最多自动重启 3 次（指数退避 1s/2s/4s），
// 超限弹窗示警不再硬重试（真故障反复拉起只会掩盖问题）。
let restartTimes = [];

async function handleEngineCrash(code) {
  bootLog('engine exited (code ' + code + ')');
  if (quittingByUser) return;
  const now = Date.now();
  restartTimes = restartTimes.filter((t) => now - t < 5 * 60 * 1000);
  if (restartTimes.length >= 3) {
    bootLog('engine restart limit reached');
    dialog.showErrorBox('SiteLens 引擎反复退出',
      '引擎 5 分钟内已崩溃 3 次，已停止自动重启。\n日志：' +
      path.join(app.getPath('userData'), 'engine.log'));
    return;
  }
  restartTimes.push(now);
  const ok = await engine.restart();
  bootLog('engine auto-restart ' + (ok ? 'ok' : 'failed') +
    ' at ' + engine.url);
  if (ok) {
    if (win && !win.isDestroyed()) win.loadURL(engine.url).catch(() => {});
    tray.displayBalloon({
      iconType: 'info',
      title: 'SiteLens 引擎已自动恢复',
      content: '后台引擎重启完成，扫描可继续。',
    });
  } else {
    dialog.showErrorBox('SiteLens 引擎已退出',
      '自动重启失败。\n日志：' + path.join(app.getPath('userData'), 'engine.log'));
  }
}

app.on('second-instance', showWindow);

app.whenReady().then(async () => {
  bootLog('app v' + app.getVersion() + ' ready, engine dir: ' + engine.ENGINE_DIR);
  loadDeskPrefs();
  createTray();
  // 窗口先行：品牌启动页立即可见，引擎冷启动（全量情报加载）不产生空白期
  createWindow();
  engine.onCrash = (code) => {
    handleEngineCrash(code);
  };
  try {
    await engine.start();
    bootLog('engine ready at ' + engine.url);
  } catch (err) {
    bootLog('engine failed: ' + err);
    // 启动失败在窗口内呈现（含日志位置），比一闪而过的系统弹窗有用
    loadShellPage('引擎启动失败', String(err.message || err) +
      '<br>日志：' + app.getPath('userData') + '\\engine.log');
    return;
  }
  loadApp();
  setupUpdater();
  setupIpc();
  startUpdateLoop(); // 启动静默检查 + 每 6 小时复查
});

// 退出等待引擎真正回收（taskkill 树杀是异步的，直接放行会留孤儿进程）
let engineStopHandled = false;
app.on('before-quit', (e) => {
  if (engineStopHandled) return;
  engineStopHandled = true;
  e.preventDefault();
  engine.stop().then(() => app.exit(0));
});

app.on('window-all-closed', () => {
  // 关窗即收托盘，不退出；真正退出只走托盘菜单（quittingByUser）
  if (quittingByUser) app.quit();
});
