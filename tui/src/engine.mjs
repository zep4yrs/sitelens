// engine.mjs —— 包内引擎二进制解析 + serve 进程托管。
//
// 解析顺序：SITLENS_ENGINE 环境变量 → 随包平台包（optionalDependencies
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
  const envBin = (process.env.SITLENS_ENGINE || "").trim();
  if (envBin) {
    if (fs.existsSync(envBin)) return { bin: envBin, from: "SITLENS_ENGINE" };
    errs.push(`SITLENS_ENGINE 指向的文件不存在：${envBin}`);
  }
  try {
    const req = createRequire(import.meta.url);
    const dir = path.dirname(req.resolve(`${enginePkgName()}/package.json`));
    const bin = path.join(dir, `SiteLens_${platToken(process.platform, process.arch)}_engine_${selfVersion()}${EXE}`);
    if (fs.existsSync(bin)) return { bin, from: enginePkgName() };
    errs.push(`平台包已装但二进制缺失：${bin}`);
  } catch (e) {
    errs.push(`平台包未安装（${enginePkgName()}）`);
  }
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    const cand = path.join(dir, `sitelens${EXE}`);
    if (fs.existsSync(cand)) return { bin: cand, from: "PATH" };
  }
  throw new Error(
    `未找到 SiteLens 引擎二进制。\n${errs.map((e) => "  - " + e).join("\n")}\n` +
      `可设 SITLENS_ENGINE=<引擎路径>，或重装本包（npm i @fengqiao666/sitelens-cli）补齐平台包。`,
  );
}

// sitelens serve 直通：参数原样传递给引擎
export async function passthroughServe(args) {
  const { bin } = resolveEngine();
  const child = spawn(bin, ["serve", ...args], { stdio: "inherit" });
  return new Promise((code) => child.on("exit", code));
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
// 历史落 ~/.sitelens/data，跨次运行保留）。工作目录指到引擎二进制所在
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
  const port = await freePort();
  const profile = path.join(os.homedir(), ".sitelens");
  const dataDir = path.join(profile, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const cfgPath = path.join(profile, `tui-${port}.yml`);
  const lines = ["web:", `  listen: 127.0.0.1:${port}`, "store:", `  data_dir: ${dataDir.replace(/\\/g, "/")}`];
  if (allowPrivate) lines.push("target:", "  allow_private: true");
  // ML 模型资产就位时自动启用 5.0 融合（cve-tech 先验提权 + 预测富化）；
  // 未设置则引擎按既有语义静默跳过，主流程零影响。
  // env 一律 trim：cmd 的 `set VAR=v &&` 链会把尾随空格塞进值里
  const mlDir = (process.env.SITLENS_ML_ASSETS || "").trim();
  if (mlDir && fs.existsSync(mlDir)) {
    lines.push("ml:", `  assets_dir: ${mlDir.replace(/\\/g, "/")}`, "  predict: true");
  }
  fs.writeFileSync(cfgPath, lines.join("\n") + "\n");
  // SITLENS_DEBUG=1：落一份 serve 装配现场（引擎路径 + 生效配置），
  // 排查"ML 没挂/allow_private 没生效"类问题的第一现场
  if ((process.env.SITLENS_DEBUG || "").trim() === "1") {
    try {
      fs.writeFileSync(
        path.join(profile, "last-serve-debug.txt"),
        [`# ${new Date().toISOString()}`, `engine: ${bin} (${from})`, `cfg: ${cfgPath}`, fs.readFileSync(cfgPath, "utf8")].join("\n"),
      );
    } catch {}
  }
  const child = spawn(bin, ["-config", cfgPath, "serve"], {
    cwd: path.dirname(bin),
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
            try {
              child.kill();
            } catch {}
            await Promise.race([
              new Promise((r) => child.once("exit", r)),
              new Promise((r) => setTimeout(r, 1500)),
            ]);
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
