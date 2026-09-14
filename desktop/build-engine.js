// 构建并暂存引擎载荷：Go 单二进制 + lite 数据集（与 CI lite 版同一清单）。
// 产物落 desktop/engine/，electron-builder 经 extraResources 整体打包。
// 用法：cd desktop && npm run engine
//
// 平台约束（v3.0.1 修正）：引擎**必须**是 Windows PE。曾出过真实事故——
// CI 在 Linux 上执行不带 GOOS 的 go build，产出的「sitelens.exe」实为 ELF
// 二进制，打进 Windows 安装包后引擎永远起不来（还被壳的配置写入错误掩盖）。
// 故此处：① 显式 GOOS/GOARCH；② 构建后校验 PE 魔数，非 PE 直接失败。
//
// 白盒 AST（4.0 P10）：`internal/astx` 依赖 tree-sitter（CGO）。桌面产物**应带
// AST**，否则源码审计降级为规则级。带 CGO 的 Windows PE 需要目标平台 C 工具链：
//   - Windows 本机装了 gcc（MSYS2/mingw）→ 直接 CGO_ENABLED=1 原生构建；
//   - 否则若有 WSL（含 mingw-w64 交叉工具链）→ 走 WSL 交叉编译（见下）；
//   - 两者皆无 → 回退 CGO_ENABLED=0 纯 Go 构建（AST 自动降级，不报错），
//     并在日志中**明确告警**（不静默丢失能力）。
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

// hasCmd 判断 PATH 中是否有某命令。
function hasCmd(name) {
  try {
    execFileSync(name, ['--version'], { stdio: 'ignore' });
    return true;
  } catch (_) {
    return false;
  }
}

// buildCGO 尝试「带 CGO（含 AST）」构建；成功返回 true。
// 策略见文件头注释。
function buildCGO() {
  // (a) 本机可原生 CGO（Windows 有 gcc）：直接构建。
  if (process.platform === 'win32' && hasCmd('gcc')) {
    try {
      execFileSync('go', ['build', '-ldflags', LDFLAGS, '-o', EXE, './cmd/sitelens'], {
        cwd: ROOT, stdio: 'inherit',
        env: Object.assign({}, process.env, {
          GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '1'
        })
      });
      console.log('[engine] CGO 构建成功（本机 gcc）——含白盒 AST');
      return true;
    } catch (e) {
      console.warn('[engine] 本机 CGO 构建失败，尝试 WSL 交叉编译：' + e.message);
    }
  }
  // (b) WSL + mingw-w64 交叉编译（本项目当前主力路径）。
  if (!hasCmd('wsl.exe') && !hasCmd('wsl')) return false;
  const script = [
    'cd "$(wslpath -u ' + JSON.stringify(ROOT) + ')" 2>/dev/null || cd ' + JSON.stringify(toWSLPath(ROOT)),
    'GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=windows GOARCH=amd64 ' +
      'CC=x86_64-w64-mingw32-gcc GOFLAGS=-mod=vendor ' +
      'go build -ldflags ' + JSON.stringify(LDFLAGS) + ' -o ' + JSON.stringify(toWSLPath(EXE)) + ' ./cmd/sitelens'
  ].join(' && ');
  try {
    execFileSync('wsl.exe', ['-d', process.env.SITLENS_WSL_DISTRO || 'archlinux',
      '--', 'bash', '-lc', script], { stdio: 'inherit' });
    if (fs.existsSync(EXE)) {
      console.log('[engine] CGO 构建成功（WSL + mingw 交叉编译）——含白盒 AST');
      return true;
    }
  } catch (e) {
    console.warn('[engine] WSL 交叉编译失败：' + e.message);
  }
  return false;
}

// toWSLPath Windows 路径 → WSL 挂载路径（D:\a\b → /mnt/d/a/b）。
function toWSLPath(p) {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(p);
  if (!m) return p.replace(/\\/g, '/');
  return '/mnt/' + m[1].toLowerCase() + '/' + m[2].replace(/\\/g, '/');
}

rm(OUT);
fs.mkdirSync(path.join(OUT, 'data'), { recursive: true });

// 1) 引擎单二进制：优先带 CGO（含 AST），失败回退纯 Go（AST 降级并告警）。
if (!buildCGO()) {
  console.warn('[engine] ⚠ 未找到 C 工具链（本机 gcc 或 WSL+mingw）：' +
    '回退纯 Go 构建，桌面版**源码审计将降级为规则级（无 AST 数据流）**。' +
    '如需完整白盒能力，请安装 mingw-w64 或 WSL 交叉工具链后重跑。');
  execFileSync('go', ['build', '-ldflags', LDFLAGS, '-o', EXE, './cmd/sitelens'], {
    cwd: ROOT,
    stdio: 'inherit',
    env: Object.assign({}, process.env, {
      GOOS: 'windows',
      GOARCH: 'amd64',
      CGO_ENABLED: '0'
    })
  });
}

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
