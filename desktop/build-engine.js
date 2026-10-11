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
//
// 方案 Aa（5.0 桌面全量内嵌）：CGO 构建带 `-tags onnx`（sev-prior v3.1
// ONNX 推理），ML 资产（models/go/ml_assets → 装箱为 data/go/ml_assets）与
// onnxruntime.dll 随包进
// engine/data；桌面壳默认配置 ml.sev_onnx: true。纯 Go 回退构建**不带**
// onnx 标签（yalue/onnxruntime_go 依赖 cgo，CGO_ENABLED=0 编不过），
// 该形态 sev_onnx 自动回退 NVD 先验。
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
  const buildArgs = ['build', '-tags', 'onnx', '-ldflags', LDFLAGS, '-o', EXE, './cmd/sitelens'];
  // (a) 本机可原生 CGO（Windows 有 gcc）：直接构建。
  if (process.platform === 'win32' && hasCmd('gcc')) {
    try {
      execFileSync('go', buildArgs, {
        cwd: ROOT, stdio: 'inherit',
        env: Object.assign({}, process.env, {
          GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '1'
        })
      });
      console.log('[engine] CGO 构建成功（本机 gcc）——含白盒 AST + sev ONNX');
      return true;
    } catch (e) {
      console.warn('[engine] 本机 CGO 构建失败，尝试 WSL 交叉编译：' + e.message);
    }
  }
  // (a2) Linux/macOS + mingw-w64 交叉编译：与 WSL 分支同一个 CC，只是不经
  //      wsl.exe（容器里没有 WSL）。CI/发版容器装了 mingw-w64 即走这条，
  //      产物与 Windows 本机构建同为 PE、同带 AST + onnx 标签。
  if (process.platform !== 'win32' && hasCmd('x86_64-w64-mingw32-gcc')) {
    try {
      execFileSync('go', buildArgs, {
        cwd: ROOT, stdio: 'inherit',
        env: Object.assign({}, process.env, {
          GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '1',
          CC: 'x86_64-w64-mingw32-gcc'
        })
      });
      console.log('[engine] CGO 构建成功（' + process.platform + ' + mingw 交叉编译）——含白盒 AST + sev ONNX');
      return true;
    } catch (e) {
      console.warn('[engine] mingw 交叉编译失败，尝试 WSL：' + e.message);
    }
  }
  // (b) WSL + mingw-w64 交叉编译（Windows 上的常规路径）。
  if (!hasCmd('wsl.exe') && !hasCmd('wsl')) return false;
  const script = [
    'cd "$(wslpath -u ' + JSON.stringify(ROOT) + ')" 2>/dev/null || cd ' + JSON.stringify(toWSLPath(ROOT)),
    'GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=windows GOARCH=amd64 ' +
      'CC=x86_64-w64-mingw32-gcc GOFLAGS=-mod=vendor ' +
      'go build -tags onnx -ldflags ' + JSON.stringify(LDFLAGS) + ' -o ' + JSON.stringify(toWSLPath(EXE)) + ' ./cmd/sitelens'
  ].join(' && ');
  try {
    execFileSync('wsl.exe', ['-d', process.env.SITLENS_WSL_DISTRO || 'archlinux',
      '--', 'bash', '-lc', script], { stdio: 'inherit' });
    if (fs.existsSync(EXE)) {
      console.log('[engine] CGO 构建成功（WSL + mingw 交叉编译）——含白盒 AST + sev ONNX');
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

// 2.5) ML 资产与 ONNX Runtime（方案 Aa：桌面全量内嵌，sev_onnx 桌面默认开）。
//      资产源位置：模型自「模型进仓库本体」（2026-09-29）迁移到 models/go/ml_assets/
//      （data/ 下只剩指纹库，且 data/ 被 .gitignore 忽略——干净 clone 里没有）。
//      本脚本曾硬编码读 data/go/ml_assets，迁移后未跟改：**5.0.0 之后的干净仓库
//      出包必然在此炸**（5.1.0 迟迟发不出的直接原因）。现按「models/ 优先、
//      data/ 兼容旧布局」取源，与引擎运行时候选表（ml.LocateAssetsDir）同序。
//
//      装箱目标仍是 staging 的 data/go/ml_assets/：桌面引擎 cwd=engine 目录，
//      默认 ml.assets_dir=data/go/ml_assets 恰好命中（包内布局保持不变，不改
//      引擎默认路径）。
//
//      硬闸而非静默跳过：方案 Aa 承诺「带 onnx 标签 + 模型随包」，资产缺失出
//      残包只会把降级藏到用户机器上（引擎静默回退 NVD 先验），必须在打包现场拦下。
//      onnxruntime.dll 不在 ml_assets 内，须显式装箱：引擎按 ml.onnxrt_dll
//      （桌面默认 data/onnxruntime/onnxruntime.dll，相对引擎 cwd）加载共享库，
//      缺库等同 sev_onnx 永远不生效。
// v3.1 部署形态 = 双种子 fp32 对（a/b，各约 268MB，引擎双 session 取平均）；
// 兼容旧单文件资产布局（sev-prior-v3.1.onnx）。
function pickMLAssetsDir() {
  for (const rel of ['models/go/ml_assets', 'data/go/ml_assets']) {
    const d = path.join(ROOT, rel);
    // 与 internal/ml.LocateAssetsDir 同判据：关键文件齐全才算有效资产目录。
    const ok = ['cve-tech.meta.json', 'cve-tech.coef.f32',
      'cwe-type.meta.json', 'cwe-type.coef.f32']
      .every((f) => fs.existsSync(path.join(d, f)));
    if (ok) return d;
  }
  return '';
}
const ML_SRC = pickMLAssetsDir();
if (!ML_SRC) {
  throw new Error('ML 资产缺失：models/go/ml_assets 与 data/go/ml_assets 均无全套' +
    '模型资产（cve-tech/cwe-type 的 meta+coef）。方案 Aa 要求桌面版全量内嵌 ML 资产，' +
    '请先补齐 models/go/ml_assets（克隆即得；LFS 大文件需 git lfs pull）。');
}
const STAGED_SEV_DIR = path.join(OUT, 'data', 'go', 'ml_assets');
const SEV_PAIR = ['sev-prior-v3.1-a.onnx', 'sev-prior-v3.1-b.onnx']
  .map((f) => path.join(ML_SRC, f));
const SEV_SINGLE = path.join(ML_SRC, 'sev-prior-v3.1.onnx');
const sevOk = SEV_PAIR.every((f) => fs.existsSync(f))
  || fs.existsSync(SEV_SINGLE);
if (!sevOk) {
  throw new Error('ML 资产缺失：' + ML_SRC + ' 缺 sev-prior 双种子对' +
    '（sev-prior-v3.1-a/b.onnx）或旧单文件 sev-prior-v3.1.onnx。' +
    '方案 Aa 要求桌面版全量内嵌 ML 资产（sev-prior v3.1 / 线性模型 / 词表 / fixtures）。');
}
const sevBig = SEV_PAIR.filter(fs.existsSync);
for (const f of (sevBig.length ? sevBig : [SEV_SINGLE])) {
  if (fs.statSync(f).size < 200 * 1024 * 1024) {
    throw new Error('ML 资产残缺：' + f + ' 小于 200MB（fp32 模型应约 268MB），疑似截断。'
      + 'LFS 指针文件（几百字节）也会命中此闸——先 git lfs pull 再出包。');
  }
}
// 资产整目录进箱到 staging 的 data/go/ml_assets（保持包内布局与引擎默认路径一致）。
fs.mkdirSync(path.dirname(STAGED_SEV_DIR), { recursive: true });
fs.cpSync(ML_SRC, STAGED_SEV_DIR, { recursive: true });
console.log('[engine] ML 资产已装箱：' + ML_SRC + ' → data/go/ml_assets');

// onnxruntime.dll 源位置同样双候选（models/ 随仓库分发，data/ 兼容旧布局）。
const ORT_DLL_SRC = ['models/onnxruntime/onnxruntime.dll',
  'data/onnxruntime/onnxruntime.dll']
  .map((r) => path.join(ROOT, r))
  .find((p) => fs.existsSync(p));
if (!ORT_DLL_SRC) {
  throw new Error('缺少 onnxruntime.dll（models/onnxruntime/ 与 data/onnxruntime/ 均无）：'
    + 'sev_onnx 运行时库未就位，缺库等同该通道永不生效。');
}
fs.mkdirSync(path.join(OUT, 'data', 'onnxruntime'), { recursive: true });
fs.copyFileSync(ORT_DLL_SRC, path.join(OUT, 'data', 'onnxruntime', 'onnxruntime.dll'));
console.log('[engine] onnxruntime.dll 已装箱：' + ORT_DLL_SRC);

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
