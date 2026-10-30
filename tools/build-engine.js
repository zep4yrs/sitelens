// 构建并暂存引擎载荷：Go 单二进制 + lite 数据集（与 CI lite 版同一清单）。
// 产物落 build/engine/（.gitignore 已忽略），由 tools/wails_build.sh 拷进安装包 staging。
// 用法：node tools/build-engine.js                        （CLI 目标，npm 线用）
//       node tools/build-engine.js --target=engine        （引擎目标，桌面 Wails 线用）
//
// 5.2 起引擎与 CLI 拆成两个二进制：
//   - target=cli    → ./cmd/sitelens        → sitelens.exe          （控制台子系统，scan/audit/update-*）
//   - target=engine → ./cmd/sitelens-engine → sitelens-engine.exe  （控制台子系统，serve/update-seed）
// 两者共用同一套资产装箱与硬闸；**引擎不加 -H windowsgui**——引擎侧仍需
// 写日志与输出 update-seed 报告，"不弹控制台窗口"由桌面壳拉起时用
// CREATE_NO_WINDOW 实现（desktop-wails/main.go），不能靠改二进制子系统
// （那会连带打死 CLI 的 stdout 输出）。
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
// 方案 Aa（5.0 桌面全量内嵌）→ 5.2 阶段 1 起改为「默认不带 ONNX」：
//   - 默认：CGO 构建（含白盒 AST，若工具链可用）但**不加 -tags onnx**，
//     ML 资产只装 cve-tech/cwe-type/sev-linear 线性模型（约 105MB），
//     不装 sev-prior*.onnx 与 onnxruntime.dll；严重度默认走
//     「NVD/情报行查表 → sev-linear 线性回归兜底」（见 internal/engine/ml.go）。
//   - 可选高级包：SITLENS_BUNDLE_ONNX=1 恢复旧形态（-tags onnx +
//     onnxruntime.dll + 双种子 fp32 ONNX），需 CGO 工具链；桌面设置页
//     把 ml.sev_onnx 打开即启用（默认关）。
//   纯 Go 回退构建不带 onnx 标签（yalue/onnxruntime_go 依赖 cgo，
//   CGO_ENABLED=0 编不过）——该形态下 sev_onnx 配置不生效，自动回退线性/NVD。
//   仓库瘦身（5.2）：ONNX 资产与 onnxruntime.dll 已不再入库（默认分发不带）；
//   要出可选高级包，先把它们手动放入 models/go/ml_assets/ 与 models/onnxruntime/
//   （见 docs/release-5.2.0/仓库瘦身-5.2.0.md），否则本脚本的 ONNX 硬闸会拦下。
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'build', 'engine');
const LDFLAGS = '-s -w';
// 可选高级包开关：1 = 带 ONNX（-tags onnx + onnxruntime.dll + sev-prior 模型）。
const BUNDLE_ONNX = process.env.SITLENS_BUNDLE_ONNX === '1';
const BUILD_TAGS = BUNDLE_ONNX ? ['-tags', 'onnx'] : [];

// --target=cli|engine：构建哪个入口、产出什么文件名。
// 默认 cli —— npm 线（tui/scripts/build-engines.mjs 另建）用 CLI 二进制
//（需要 stdout 输出 scan --json 结果）；旧 Electron 线已退役（见 .archive/）。
const targetArg = process.argv.find((a) => a.startsWith('--target='));
const TARGET = targetArg ? targetArg.slice('--target='.length) : 'cli';
if (TARGET !== 'cli' && TARGET !== 'engine') {
  throw new Error('--target 只接受 cli|engine，实际：' + TARGET);
}
const MAIN_PKG = TARGET === 'engine' ? './cmd/sitelens-engine' : './cmd/sitelens';
const EXE_NAME = TARGET === 'engine' ? 'sitelens-engine.exe' : 'sitelens.exe';
const EXE = path.join(OUT, EXE_NAME);
console.log(`[engine] 构建目标：${TARGET}（${MAIN_PKG} → ${EXE_NAME}）`);

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
  const buildArgs = ['build', ...BUILD_TAGS, '-ldflags', LDFLAGS, '-o', EXE, MAIN_PKG];
  // (a) 本机可原生 CGO（Windows 有 gcc）：直接构建。
  if (process.platform === 'win32' && hasCmd('gcc')) {
    try {
      execFileSync('go', buildArgs, {
        cwd: ROOT, stdio: 'inherit',
        env: Object.assign({}, process.env, {
          GOOS: 'windows', GOARCH: 'amd64', CGO_ENABLED: '1'
        })
      });
      console.log('[engine] CGO 构建成功（本机 gcc）——含白盒 AST' +
        (BUNDLE_ONNX ? ' + sev ONNX' : '（默认不带 ONNX）'));
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
      console.log('[engine] CGO 构建成功（' + process.platform + ' + mingw 交叉编译）——含白盒 AST' +
        (BUNDLE_ONNX ? ' + sev ONNX' : '（默认不带 ONNX）'));
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
      'go build ' + (BUNDLE_ONNX ? '-tags onnx ' : '') + '-ldflags ' +
      JSON.stringify(LDFLAGS) + ' -o ' + JSON.stringify(toWSLPath(EXE)) + ' ' + MAIN_PKG
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
  if (BUNDLE_ONNX) {
    throw new Error('SITLENS_BUNDLE_ONNX=1 需要 CGO 工具链（本机 gcc 或 WSL+mingw）：' +
      'ONNX 高级包依赖 onnxruntime_go（cgo），纯 Go 构建无法包含 ONNX 推理。');
  }
  console.warn('[engine] ⚠ 未找到 C 工具链（本机 gcc 或 WSL+mingw）：' +
    '回退纯 Go 构建，桌面版**源码审计将降级为规则级（无 AST 数据流）**。' +
    '如需完整白盒能力，请安装 mingw-w64 或 WSL 交叉工具链后重跑。');
  execFileSync('go', ['build', ...BUILD_TAGS, '-ldflags', LDFLAGS, '-o', EXE, MAIN_PKG], {
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

// 2.5) ML 资产（5.2 阶段 1：默认不带 ONNX）。
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
//      默认随包（约 105MB）：cve-tech / cwe-type 线性模型 + sev-linear 线性
//      严重度回归（约 0.7MB）+ 词表/夹具。**不装** sev-prior*.onnx（643MB）
//      与 onnxruntime.dll（16MB）——严重度默认走「NVD/情报行查表 →
//      sev-linear 兜底」，精度代价实测 MAE +0.11 分（1.19 vs 1.08）。
//      硬闸：线性资产缺失一律拦下（残包会把降级藏到用户机器上）。
//
//      可选高级包：SITLENS_BUNDLE_ONNX=1 时恢复旧契约——-tags onnx 构建 +
//      双种子 fp32 ONNX（a/b，各约 268MB，引擎双 session 取平均）+ 
//      onnxruntime.dll 随包；用户需在设置页把 ml.sev_onnx 打开（默认关）。
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
    '模型资产（cve-tech/cwe-type 的 meta+coef）。桌面包要求线性模型资产随包，' +
    '请先补齐 models/go/ml_assets（线性模型随仓库分发，克隆即得）。');
}
const STAGED_SEV_DIR = path.join(OUT, 'data', 'go', 'ml_assets');

// 5.2 阶段 1 必备：sev-linear 线性严重度回归四件（训练脚本 ml/train_sev_linear.py）。
const SEV_LINEAR_FILES = ['meta.json', 'vocab.txt', 'idf.f32', 'coef.f32']
  .map((ext) => 'sev-linear.' + ext);
const missLinear = SEV_LINEAR_FILES.filter((f) => !fs.existsSync(path.join(ML_SRC, f)));
if (missLinear.length) {
  throw new Error('ML 资产缺失：' + ML_SRC + ' 缺 sev-linear 线性严重度资产（' +
    missLinear.join(', ') + '）。5.2 阶段 1 默认严重度后端是 NVD 查表 + sev-linear 兜底；' +
    '请先运行 python ml/train_sev_linear.py 生成（约 0.7MB，CPU 一分钟内）。');
}

// 可选：ONNX 高级包硬闸（只在 SITLENS_BUNDLE_ONNX=1 时检查与装箱）。
// 5.2 仓库瘦身起 ONNX 资产不再入库：出高级包前需手动放入
// models/go/ml_assets/（见 docs/release-5.2.0/仓库瘦身-5.2.0.md）。
const SEV_PAIR = ['sev-prior-v3.1-a.onnx', 'sev-prior-v3.1-b.onnx']
  .map((f) => path.join(ML_SRC, f));
const SEV_SINGLE = path.join(ML_SRC, 'sev-prior-v3.1.onnx');
if (BUNDLE_ONNX) {
  const sevOk = SEV_PAIR.every((f) => fs.existsSync(f)) || fs.existsSync(SEV_SINGLE);
  if (!sevOk) {
    throw new Error('SITLENS_BUNDLE_ONNX=1 但 ML 资产缺 sev-prior 双种子对' +
      '（sev-prior-v3.1-a/b.onnx）或旧单文件 sev-prior-v3.1.onnx。' +
      '这些资产自 5.2 仓库瘦身起不再入库，需手动放入 models/go/ml_assets/。');
  }
  const sevBig = SEV_PAIR.filter(fs.existsSync);
  for (const f of (sevBig.length ? sevBig : [SEV_SINGLE])) {
    if (fs.statSync(f).size < 200 * 1024 * 1024) {
      throw new Error('ML 资产残缺：' + f + ' 小于 200MB（fp32 模型应约 268MB），疑似截断。'
        + '请确认是从备份/高级包渠道完整拷入 models/go/ml_assets/ 的。');
    }
  }
}
// 资产进箱：默认过滤 sev-prior*.onnx（ONNX 高级包才随包）。
fs.mkdirSync(path.dirname(STAGED_SEV_DIR), { recursive: true });
fs.cpSync(ML_SRC, STAGED_SEV_DIR, {
  recursive: true,
  // 默认包把 ONNX 专用文件全部剔掉（模型/词表/ONNX 夹具）；高级包原样装箱。
  filter: (src) => BUNDLE_ONNX || !/sev-prior[^\\/]*$/i.test(src)
});
console.log('[engine] ML 资产已装箱：' + ML_SRC + ' → data/go/ml_assets' +
  (BUNDLE_ONNX ? '（含 ONNX 模型）' : '（不含 ONNX 模型，5.2 默认）'));

// onnxruntime.dll 仅在 ONNX 高级包中随包（默认不装）。
if (BUNDLE_ONNX) {
  const ORT_DLL_SRC = ['models/onnxruntime/onnxruntime.dll',
    'data/onnxruntime/onnxruntime.dll']
    .map((r) => path.join(ROOT, r))
    .find((p) => fs.existsSync(p));
  if (!ORT_DLL_SRC) {
    throw new Error('SITLENS_BUNDLE_ONNX=1 但缺少 onnxruntime.dll（models/onnxruntime/ 与 ' +
      'data/onnxruntime/ 均无）：ONNX 高级包需要该共享库。');
  }
  fs.mkdirSync(path.join(OUT, 'data', 'onnxruntime'), { recursive: true });
  fs.copyFileSync(ORT_DLL_SRC, path.join(OUT, 'data', 'onnxruntime', 'onnxruntime.dll'));
  console.log('[engine] onnxruntime.dll 已装箱：' + ORT_DLL_SRC);
} else {
  console.log('[engine] 跳过 onnxruntime.dll（默认包不带 ONNX；高级包用 SITLENS_BUNDLE_ONNX=1）');
}

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
