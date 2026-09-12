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

// 2) 数据载荷：只读资产全量内置（含 NVD/情报库种子，首开即完整体验）；
//    模板池（719MB）不随包，update-nuclei 在线拉取到用户数据区。
//    可选种子缺失只警告不中断（例如新 clone 未拉 NVD 大文件时仍可出包，
//    只是首开无 NVD 通道）。
function cp(src, dest) {
  const d = path.join(OUT, dest);
  fs.mkdirSync(path.dirname(d), { recursive: true });
  fs.cpSync(path.join(ROOT, src), d, { recursive: true });
}
function cpOptional(src, dest) {
  if (!fs.existsSync(path.join(ROOT, src))) {
    console.warn(`[engine] 可选种子缺失，跳过：${src}（update-nvd 可在线补）`);
    return;
  }
  cp(src, dest);
}
cp('data/go', 'data/go');
cp('data/wordlists', 'data/wordlists');
cp('data/affected_ranges.json', 'data/affected_ranges.json');
cp('data/intel_dump.json.gz', 'data/intel_dump.json.gz');
cp('data/tpl_intel.json.gz', 'data/tpl_intel.json.gz');
cpOptional('data/nvd_cves.json.gz', 'data/nvd_cves.json.gz');
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
