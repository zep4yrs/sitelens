// 引擎子进程管理（供桌面壳 main.js 调用）。
//
// 职责：选定空闲端口 → 写端口覆盖配置 → 拉起 Go 引擎单二进制 →
// 就绪探测。引擎与页面逻辑全在 sitelens serve 里，这里只管进程。
//
// 子进程安全约定：spawn 首参为纯字面量（相对引擎工作目录解析），
// argv 全部内联字面量；不提供环境变量或配置选择可执行程序的通道。
const { app } = require('electron');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const util = require('util');

const isDev = !app.isPackaged;
const ENGINE_DIR = isDev
  ? path.join(__dirname, '..')
  : path.join(process.resourcesPath, 'engine');
const READY_TIMEOUT_MS = 30000;

let engine = null;
let engineURL = '';
let onCrash = null; // 引擎意外退出的回调（主进程弹窗用）

// log 输出落盘（userData/engine.log，1MB 截断），排障用。
function log(chunk) {
  try {
    const file = path.join(app.getPath('userData'), 'engine.log');
    let prev = '';
    try {
      const st = fs.statSync(file);
      if (st.size > 1024 * 1024) prev = '';
      else prev = fs.readFileSync(file, 'utf8');
    } catch (_) { /* 首次无日志 */ }
    fs.writeFileSync(file, (prev + chunk).slice(-1024 * 1024));
  } catch (_) { /* 日志失败不影响主流程 */ }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

// probe 一次就绪探测：引擎根路径返回任意响应即视为已监听。
function probe(url) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: 1500 }, (res) => {
      res.resume();
      resolve(true);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitReady(url) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await probe(url)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

// writeListenConfig 端口覆盖配置：引擎配置为「默认值 + yml 部分覆盖」
// 语义，只写监听地址一段即可。文件落在引擎目录（引擎按自身 CWD 解析
// 相对路径）；YAML 值不用引号包裹——双引号内反斜杠转义是已知坑。
function writeListenConfig(port) {
  const line = util.format('web:\n  listen: 127.0.0.1:%d\n', port);
  fs.writeFileSync(path.join(ENGINE_DIR, 'desktop-listen.yml'), line);
}

// start 拉起引擎并等就绪；resolve 引擎根 URL。
async function start() {
  const exists = fs.existsSync(path.join(ENGINE_DIR, process.platform === 'win32' ? 'sitelens.exe' : 'sitelens'));
  if (!exists) {
    throw new Error('引擎程序缺失：' + ENGINE_DIR);
  }
  const port = await freePort();
  engineURL = 'http://127.0.0.1:' + port;
  writeListenConfig(port);

  // spawn 首参用纯字面量（相对引擎工作目录解析）：Windows 直接命中
  // 同目录二进制；POSIX 需要 ./ 前缀才会搜索当前目录。
  if (process.platform === 'win32') {
    engine = spawn('sitelens.exe', ['-config', 'desktop-listen.yml', 'serve'], {
      cwd: ENGINE_DIR, // data/ 载荷与覆盖配置随引擎目录解析
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'], // stdout/stderr 都要接日志，不能 ignore
    });
  } else {
    engine = spawn('./sitelens', ['-config', 'desktop-listen.yml', 'serve'], {
      cwd: ENGINE_DIR,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }
  engine.stdout.on('data', log);
  engine.stderr.on('data', log);
  engine.on('exit', (code) => {
    engine = null;
    if (onCrash) onCrash(code);
  });

  if (!(await waitReady(engineURL))) {
    throw new Error('引擎在 ' + READY_TIMEOUT_MS / 1000 + ' 秒内未就绪（端口 ' + port + '）');
  }
  return engineURL;
}

function stop() {
  if (engine) {
    try {
      engine.kill();
    } catch (_) { /* 已退出 */ }
    engine = null;
  }
}

module.exports = {
  ENGINE_DIR,
  start,
  stop,
  set onCrash(fn) {
    onCrash = fn;
  },
  get url() {
    return engineURL;
  },
};
