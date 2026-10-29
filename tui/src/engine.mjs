// engine.mjs —— 包内引擎二进制解析 + serve 进程托管 + 命令直通。
//
// 解析顺序：SITELENS_ENGINE 环境变量 → 随包平台包（optionalDependencies
// 安装时按 os/cpu 自动落位）→ PATH 中的 sitelens。
// 二进制文件名遵循发版约定 SiteLens_<平台>_engine_<版本>（平台 token：
// win64 / linux64 / linux-arm64 / mac64 / mac-arm64）。
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const EXE = process.platform === "win32" ? ".exe" : "";

function selfVersion() {
  return JSON.parse(
    fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"),
  ).version;
}

// 平台 → 二进制文件名 token（发版约定 SiteLens_<平台>_engine_<版本>）
function platToken(platform, arch) {
  if (platform === "win32") return "win64";
  if (platform === "linux") return arch === "arm64" ? "linux-arm64" : "linux64";
  if (platform === "darwin") return arch === "arm64" ? "mac-arm64" : "mac64";
  return `${platform}-${arch}`;
}

function enginePkgName() {
  return `@fengqiao666/sitelens-${process.platform}-${process.arch}-engine`;
}

export function resolveEngine() {
  const errs = [];
  const envBin = (process.env.SITELENS_ENGINE || "").trim();
  if (envBin) {
    if (fs.existsSync(envBin)) return { bin: envBin, from: "SITELENS_ENGINE" };
    errs.push(`SITELENS_ENGINE 指向的文件不存在：${envBin}`);
  }
  let pkgDir = null;
  try {
    const req = createRequire(import.meta.url);
    pkgDir = path.dirname(req.resolve(`${enginePkgName()}/package.json`));
    const bin = path.join(pkgDir, `SiteLens_${platToken(process.platform, process.arch)}_engine_${selfVersion()}${EXE}`);
    if (fs.existsSync(bin)) return { bin, from: enginePkgName(), pkgDir };
    errs.push(`平台包已装但二进制缺失：${bin}`);
  } catch (e) {
    errs.push(`平台包未安装（${enginePkgName()}）`);
  }
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    const cand = path.join(dir, `sitelens${EXE}`);
    if (fs.existsSync(cand)) return { bin: cand, from: "PATH", pkgDir };
  }
  throw new Error(
    `未找到 SiteLens 引擎二进制。\n${errs.map((e) => "  - " + e).join("\n")}\n` +
      `可设 SITELENS_ENGINE=<引擎路径>，或重装本包（npm i @fengqiao666/sitelens-cli）补齐平台包。`,
  );
}

/* =======================================================================
   用户区（npm 线）
   -----------------------------------------------------------------------
   npm 线没有安装目录可写，所有"可再生数据"与状态都落在 ~/.sitelens/：
     ~/.sitelens/config.yml      TUI 管理的配置（数据路径段）
     ~/.sitelens/data/           数据资产（指纹库 / 情报 / 模板池 / 字典 / ML）
     ~/.sitelens/data/state/     扫描历史（store.data_dir）
   与桌面版（%APPDATA%\SiteLens-Wails）互不相干。
   ======================================================================= */

export function userRoot() {
  return path.join(os.homedir(), ".sitelens");
}

export function userDataDir() {
  return path.join(userRoot(), "data");
}

export function userConfigPath() {
  return path.join(userRoot(), "config.yml");
}

const posix = (p) => p.replace(/\\/g, "/");

/**
 * 生成用户区配置文本。
 *
 * 分段规则（关键）：**只在这里写 web/target 段**——canonical 配置与 serve 的
 * 每端口配置都由本函数产出，所以两者拼起来不会出现 YAML 重复键（yaml.v3 遇
 * 重复键直接报错）。canonical 不含 web/target，serve 的配置是 canonical
 * 全文 + web 段。
 */
function configText({ listen, allowPrivate, mlAssets } = {}) {
  const data = userDataDir();
  const lines = [
    "store:",
    `  data_dir: ${posix(data)}/state`,
    "intel:",
    `  dump_path: ${posix(data)}/intel_dump.json.gz`,
    `  ranges_path: ${posix(data)}/affected_ranges.json`,
    `  nvd_path: ${posix(data)}/nvd_cves.json.gz`,
    `  tpl_intel_path: ${posix(data)}/tpl_intel.json.gz`,
    `  technologies_path: ${posix(data)}/go/technologies.json`,
    `  overrides_path: ${posix(data)}/intel_overrides.json`,
    "checks:",
    `  nuclei_dir: ${posix(data)}/nuclei`,
    "active:",
    `  wordlist_dir: ${posix(data)}/wordlists`,
  ];
  if (listen) lines.push("web:", `  listen: 127.0.0.1:${listen}`);
  if (allowPrivate) lines.push("target:", "  allow_private: true");
  if (mlAssets) lines.push("ml:", `  assets_dir: ${posix(mlAssets)}`, "  predict: true");
  return lines.join("\n") + "\n";
}

/**
 * 确保用户区配置存在，返回其路径。
 *
 * 该文件由 TUI 管理（幂等重写）：npm 线没有别的地方可放配置，用户改了会在
 * 下次命令时被覆盖——需要长期自定义请改用环境变量或桌面版配置文件。
 */
export function ensureUserConfig() {
  const root = userRoot();
  fs.mkdirSync(path.join(root, "data", "go"), { recursive: true });
  fs.mkdirSync(path.join(root, "data", "state"), { recursive: true });
  const cfgPath = userConfigPath();
  const mlDir = (process.env.SITELENS_ML_ASSETS || "").trim();
  const mlAssets = mlDir && fs.existsSync(mlDir) ? mlDir : "";
  fs.writeFileSync(cfgPath, configText({ mlAssets }));
  return cfgPath;
}

/**
 * 平台包里的只读种子目录（含指纹库 data/go/technologies.json）。
 * 平台包未安装时返回 ""（调用方跳过种子交付）。
 */
export function packageSeedDir() {
  const { pkgDir } = resolveEngine();
  const d = pkgDir ? path.join(pkgDir, "data") : "";
  return d && fs.existsSync(d) ? d : "";
}

/**
 * 首次运行时把平台包里的指纹库交付到用户区。
 *
 * 复用引擎自带的 update-seed（按引擎版本收敛：版本变化才覆盖，同版本 no-op），
 * 与桌面版的"随包只读种子 → 用户数据区"是同一套机制。种子落到
 * <userDir>/data，正好是用户区配置指向的位置。
 */
export async function ensureSeeds(log = () => {}) {
  const seedDir = packageSeedDir();
  if (!seedDir) return false;
  const { bin: binRaw } = resolveEngine();
  const bin = path.resolve(binRaw);
  const root = userRoot();
  fs.mkdirSync(root, { recursive: true });
  const out = await new Promise((resolve) => {
    const child = spawn(bin, ["update-seed", "--seed-dir", seedDir, "--user-dir", root], {
      cwd: path.dirname(bin),
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let buf = "";
    child.stdout.on("data", (d) => (buf += d.toString()));
    child.stderr.on("data", (d) => (buf += d.toString()));
    child.on("exit", (code) => resolve({ code, buf }));
    child.on("error", () => resolve({ code: 1, buf: "" }));
  });
  if (out.code === 0) log("已交付平台包内置指纹库到用户区");
  return out.code === 0;
}

/**
 * 直通引擎二进制执行原生命令：stdio 直通、退出码透传。
 *
 * 用于 audit / correlate / graph-read / regression / migrate-pg / update-*。
 * 用户在 TUI 里看到的输出就是引擎的原始输出，不做二次包装。
 */
export async function passthrough(argv) {
  const { bin: binRaw } = resolveEngine();
  const bin = path.resolve(binRaw);
  const cfg = ensureUserConfig();
  const child = spawn(bin, ["-config", cfg, ...argv], {
    cwd: process.cwd(),
    stdio: "inherit",
    windowsHide: true,
  });
  return await new Promise((resolve) => {
    child.on("exit", (code) => resolve(code ?? 0));
    child.on("error", (e) => {
      console.error("引擎启动失败：" + e.message);
      resolve(1);
    });
  });
}

// sitelens serve 直通：参数原样传递给引擎
export async function passthroughServe(args) {
  const { bin: binRaw } = resolveEngine();
  const bin = path.resolve(binRaw);
  const cfg = ensureUserConfig();
  const child = spawn(bin, ["-config", cfg, "serve", ...args], {
    cwd: process.cwd(),
    stdio: "inherit",
    windowsHide: true,
  });
  return await new Promise((code) => child.on("exit", code));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

// startServe 起一次私有 serve：独立端口 + 用户级 profile（~/.sitelens，
// 历史落 ~/.sitelens/data/state，跨次运行保留）。工作目录指到引擎二进制所在
// 目录——平台包内捆绑的 data/go/technologies.json（指纹库）按引擎默认
// 相对路径就地生效。情报库/NVD/ML 资产不随 npm 分发，serve 按引擎既有
// 语义降级（相应功能跳过），不影响指纹/验证型 check/DAST 主流程。
// 注意：-config 是顶层 flag，必须放在 serve 子命令之前。
// allowPrivate=true 时配置 target.allow_private（本机靶场/授权内网）；
// gov.cn 目标的硬保护在引擎侧，不受此开关影响。
export async function startServe(log = () => {}, { allowPrivate = false } = {}) {
  const { bin: binRaw, from } = resolveEngine();
  // 规范成原生绝对路径：Windows 上正斜杠形式的 cwd 会让引擎静默不启动
  //（不报错、不监听），spawn 前必须 resolve
  const bin = path.resolve(binRaw);
  // 首次运行（或引擎版本变化后）把平台包内置的指纹库交付到用户区——
  // 引擎的 update-seed 按版本收敛，同版本二次启动是 no-op（代价约 100ms）。
  await ensureSeeds(log);
  const port = await freePort();
  const profile = userRoot();
  const dataDir = path.join(profile, "data");
  fs.mkdirSync(path.join(dataDir, "state"), { recursive: true });
  fs.mkdirSync(path.join(dataDir, "go"), { recursive: true });
  const cfgPath = path.join(profile, `tui-${port}.yml`);
  // ML 模型资产就位时自动启用 5.0 融合（cve-tech 先验提权 + 预测富化）；
  // 未设置则引擎按既有语义静默跳过，主流程零影响。
  // env 一律 trim：cmd 的 `set VAR=v &&` 链会把尾随空格塞进值里
  const mlDir = (process.env.SITELENS_ML_ASSETS || "").trim();
  const mlAssets = mlDir && fs.existsSync(mlDir) ? mlDir : "";
  fs.writeFileSync(
    cfgPath,
    configText({ listen: port, allowPrivate, mlAssets }),
  );
  // SITELENS_DEBUG=1：落一份 serve 装配现场（引擎路径 + 生效配置），
  // 排查"ML 没挂/allow_private 没生效"类问题的第一现场
  if ((process.env.SITELENS_DEBUG || "").trim() === "1") {
    try {
      fs.writeFileSync(
        path.join(profile, "last-serve-debug.txt"),
        [`# ${new Date().toISOString()}`, `engine: ${bin} (${from})`, `cfg: ${cfgPath}`, fs.readFileSync(cfgPath, "utf8")].join("\n"),
      );
    } catch {}
  }
  const child = spawn(bin, ["-config", cfgPath, "serve"], {
    cwd: process.cwd(),
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true,
  });
  let errTail = "";
  child.stderr.on("data", (d) => {
    errTail = (errTail + d.toString()).slice(-2000);
  });
  // spawn 本身失败（ENOENT/权限/AV 拦截）：不接 error 事件会静默超时
  let spawnErr = null;
  child.on("error", (e) => {
    spawnErr = e;
  });
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  let stopped = false;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/api/version`);
      if (r.ok) {
        return {
          baseUrl: base,
          engineFrom: from,
          // 等子进程真正退出（Windows 上 kill 是异步的，立即 exit 进程
          // 会撞 uv async 断言）
          async stop() {
            if (stopped) return;
            stopped = true;
            try {
              child.kill();
            } catch {}
            // 立刻释放 stderr 管道句柄：Node 退出时若该句柄仍处于 CLOSING
            // 状态，libuv 会抛 "Assertion failed: !(handle->flags &
            // UV_HANDLE_CLOSING)"（Windows 必现）——表现为进程以
            // 0xC0000409 中止，退出码全丢。
            try {
              child.stderr?.destroy();
            } catch {}
            // 等 'close'（进程已退且所有 stdio 流已关闭）而不是 'exit'
            await Promise.race([
              new Promise((r) => child.once("close", r)),
              new Promise((r) => setTimeout(r, 2000)),
            ]);
            try {
              child.unref();
            } catch {}
            try {
              fs.rmSync(cfgPath, { force: true });
            } catch {}
          },
        };
      }
    } catch {}
    if (child.exitCode !== null || spawnErr) {
      throw new Error(
        `引擎 serve 启动失败${spawnErr ? `（${spawnErr.message}）` : `（退出码 ${child.exitCode}）`}：\n${errTail}`,
      );
    }
    await new Promise((r) => setTimeout(r, 120));
  }
  try {
    child.kill();
  } catch {}
  throw new Error(`引擎 serve 启动超时：\n${errTail}`);
}
