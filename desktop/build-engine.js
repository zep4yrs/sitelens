// 构建并暂存引擎载荷：Go 单二进制 + lite 数据集（与 CI lite 版同一清单）。
// 产物落 desktop/engine/，electron-builder 经 extraResources 整体打包。
// 用法：cd desktop && npm run engine
//
// 平台约束（v3.0.1 修正）：引擎**必须**是 Windows PE。曾出过真实事故——
// CI 在 Linux 上执行不带 GOOS 的 go build，产出的「sitelens.exe」实为 ELF
// 二进制，打进 Windows 安装包后引擎永远起不来（还被壳的配置写入错误掩盖）。
// 故此处：① 显式 GOOS/GOARCH；② 构建后校验 PE 魔数，非 PE 直接失败。
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(__dirname, 'engine');
const LDFLAGS = '-s -w';
const EXE = path.join(OUT, 'sitelens.exe');

function rm(p) {
  fs.rmSync(p, { recursive: true, force: true });
}

rm(OUT);
fs.mkdirSync(path.join(OUT, 'data'), { recursive: true });

// 1) 引擎单二进制。显式目标平台（参数数组直传，不经 shell 拼接）。
//    CGO：桌面交付产物不含 AST（astx 有 //go:build cgo 的纯 Go 兜底），
//    所以关闭 cgo 以便跨平台构建确定性；启用 AST 需 Windows C 工具链（P10 议题）。
execFileSync('go', ['build', '-ldflags', LDFLAGS, '-o', EXE, './cmd/sitelens'], {
  cwd: ROOT,
  stdio: 'inherit',
  env: Object.assign({}, process.env, {
    GOOS: 'windows',
    GOARCH: 'amd64',
    CGO_ENABLED: '0'
  })
});

// 产物平台校验：Windows PE 以 "MZ"(0x4D5A) 开头；ELF 则不是。
// 这一步是防「错平台二进制静默进包」的硬闸——胜事后排查。
(function verifyPE() {
  const head = fs.readFileSync(EXE).subarray(0, 2).toString('latin1');
  if (head !== 'MZ') {
    throw new Error(
      '引擎产物不是 Windows PE（文件头 ' + JSON.stringify(head) + '）。' +
      '检查构建平台与 GOOS：跨平台构建 Windows PE 必须 GOOS=windows GOARCH=amd64。'
    );
  }
})();

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
