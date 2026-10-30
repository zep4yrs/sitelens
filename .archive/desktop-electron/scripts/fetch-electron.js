// 手动触发 Electron 二进制下载。
// 用途：npm 的 install-scripts 审批门禁可能拦截 electron 的 postinstall
//（其作用就是把平台二进制从镜像下载到 node_modules/electron/dist）。
// 本脚本等价于该 postinstall：走 @electron/get，镜像源由 .npmrc 的
// electron_mirror 或环境变量 ELECTRON_MIRROR 提供（默认 npmmirror）。
// 用法：node scripts/fetch-electron.js
process.env.ELECTRON_MIRROR = process.env.ELECTRON_MIRROR ||
  'https://npmmirror.com/mirrors/electron/';
require('../node_modules/electron/install.js');
