// 预加载脚本：以 contextBridge 向设置页暴露最小更新接口。
// 渲染进程 nodeIntegration=false / contextIsolation=true，
// 页面只能经此桥调用主进程的更新器，无法触碰 Node 能力。
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sitelens', {
  // 执行一次多源轮询检查：CNB → Gitee → GitHub。
  // 返回 { state: 'latest'|'available'|'dev'|'error', current, latest, feed, error }
  checkUpdate: function () { return ipcRenderer.invoke('update:check'); },
  // 下载完成后调用：退出并静默安装更新（引擎一并升级）
  installUpdate: function () { return ipcRenderer.invoke('update:install'); },
  // 浏览器模式下的发布页兜底
  openReleases: function () { return ipcRenderer.invoke('update:openReleases'); },
  // 订阅「更新包已下载」事件（参数为版本号字符串）
  onDownloaded: function (cb) {
    ipcRenderer.on('update:downloaded', function (_e, ver) { cb(ver); });
  }
});
