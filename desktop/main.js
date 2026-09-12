// SiteLens 桌面版主进程（Electron 壳）。
//
// 架构约束：引擎与全部页面逻辑在 Go 单二进制里（sitelens serve +
// go:embed 前端），本进程只负责窗口/托盘/生命周期/自动更新——
// 引擎代码零改动。引擎子进程管理（拉起/端口/就绪探测/日志）在
// engine.js。引擎工作目录指向自带 data 载荷，数据写入依赖 NSIS
// 按用户安装（%LOCALAPPDATA%\Programs\SiteLens，用户可写）。
//
// 自动更新：electron-updater generic 源（feed 目录见 package.json
// build.publish），引擎二进制随安装包整体更新；数据与模板更新仍走
// 引擎既有 update-* 渠道，不在此重复实现。
const { app, BrowserWindow, Tray, Menu, dialog, nativeImage, shell } = require('electron');
const { autoUpdater } = require('electron-updater');
const fs = require('fs');
const path = require('path');
const engine = require('./engine');

const isDev = !app.isPackaged;
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

function createWindow() {
  win = new BrowserWindow({
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
      spellcheck: false,
    },
  });
  Menu.setApplicationMenu(null); // 页面导航/刷新快捷键交给页面自身
  bootLog('createWindow: loadURL ' + engine.url);
  win.loadURL(engine.url).then(() => bootLog('loadURL ok')).catch((err) => {
    bootLog('loadURL failed: ' + err);
    // 本地引擎偶发首连竞态（监听已就绪但连接被拒）：重试一次
    setTimeout(() => {
      bootLog('loadURL retry');
      win.loadURL(engine.url).catch((e2) => bootLog('loadURL retry failed: ' + e2));
    }, 1200);
  });
  win.webContents.on('did-fail-load', (_e, code, desc, url) => {
    // 子资源失败也会进这里；只对主框架报警并重试
    if (!url.startsWith(engine.url)) return;
    bootLog('did-fail-load: ' + code + ' ' + desc);
    setTimeout(() => win.loadURL(engine.url).catch(() => {}), 1500);
  });
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
  // 关闭 = 收进托盘（后台引擎继续跑扫描），退出走托盘菜单
  win.on('close', (e) => {
    if (quittingByUser) return;
    e.preventDefault();
    win.hide();
    if (!hideHintShown) {
      hideHintShown = true;
      tray.displayBalloon({
        iconType: 'info',
        title: 'SiteLens 仍在运行',
        content: '扫描在后台继续。退出请用托盘图标右键菜单。',
      });
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith(engine.url)) return { action: 'allow' };
    shell.openExternal(url); // 外链交给系统浏览器
    return { action: 'deny' };
  });
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

function checkUpdates(manual) {
  if (isDev) {
    if (manual) dialog.showMessageBox({ type: 'info', message: '开发模式下不检查更新。' });
    return;
  }
  autoUpdater.checkForUpdates().catch(() => {
    if (manual) {
      dialog.showMessageBox({ type: 'info', message: '检查更新失败：无法连接更新源。' });
    }
  });
}

function setupUpdater() {
  autoUpdater.autoDownload = true;
  autoUpdater.on('update-available', () => {
    bootLog('update available, downloading…');
    tray.displayBalloon({
      iconType: 'info',
      title: '发现新版本',
      content: '正在后台下载 SiteLens 更新…',
    });
  });
  autoUpdater.on('update-downloaded', (info) => {
    bootLog('update downloaded: v' + (info && info.version));
    // E2E 测试钩子：设置 SITLENS_E2E_UPDATE 时自动安装（真机全链路验证用）
    if (process.env.SITLENS_E2E_UPDATE) {
      bootLog('e2e: auto quitAndInstall');
      quittingByUser = true;
      setTimeout(() => autoUpdater.quitAndInstall(), 3000);
      return;
    }
    dialog.showMessageBox({
      type: 'info',
      buttons: ['立即重启', '稍后'],
      defaultId: 0,
      message: 'SiteLens ' + (info && info.version ? 'v' + info.version : '') + ' 已就绪',
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
  createTray();
  engine.onCrash = (code) => {
    handleEngineCrash(code);
  };
  try {
    await engine.start();
    bootLog('engine ready at ' + engine.url);
  } catch (err) {
    bootLog('engine failed: ' + err);
    dialog.showErrorBox('SiteLens 启动失败', String(err.message || err));
    app.quit();
    return;
  }
  createWindow();
  setupUpdater();
  checkUpdates(false); // 启动后静默检查
});

app.on('before-quit', () => {
  engine.stop();
});

app.on('window-all-closed', () => {
  // 关窗即收托盘，不退出；真正退出只走托盘菜单（quittingByUser）
  if (quittingByUser) app.quit();
});
