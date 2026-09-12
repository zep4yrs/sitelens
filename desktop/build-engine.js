// 构建并暂存引擎载荷：Go 单二进制 + lite 数据集（与 CI lite 版同一清单）。
// 产物落 desktop/engine/，electron-builder 经 extraResources 整体打包。
// 用法：cd desktop && npm run engine
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(__dirname, 'engine');
const LDFLAGS = '-s -w';

function rm(p) {
  fs.rmSync(p, { recursive: true, force: true });
}

rm(OUT);
fs.mkdirSync(path.join(OUT, 'data'), { recursive: true });

// 1) 引擎单二进制（与 CI 同参数；参数数组直传，不经 shell 拼接）
execFileSync('go', ['build', '-ldflags', LDFLAGS, '-o', path.join(OUT, 'sitelens.exe'), './cmd/sitelens'], {
  cwd: ROOT,
  stdio: 'inherit',
});

// 2) lite 数据清单（与 .cnb.yml lite 阶段一致；模板池不随包，update-nuclei 在线补）
function cp(src, dest) {
  const d = path.join(OUT, dest);
  fs.mkdirSync(path.dirname(d), { recursive: true });
  fs.cpSync(path.join(ROOT, src), d, { recursive: true });
}
cp('data/go', 'data/go');
cp('data/wordlists', 'data/wordlists');
cp('data/affected_ranges.json', 'data/affected_ranges.json');
cp('README.md', 'README.md');

// 3) 体量报告
let files = 0;
let bytes = 0;
(function walk(p) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    const f = path.join(p, e.name);
    if (e.isDirectory()) walk(f);
    else {
      files++;
      bytes += fs.statSync(f).size;
    }
  }
}(OUT));
console.log(`engine 载荷暂存完成：${files} 个文件，共 ${(bytes / 1024 / 1024).toFixed(1)} MB -> ${OUT}`);
