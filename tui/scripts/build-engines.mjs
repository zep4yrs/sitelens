#!/usr/bin/env node
// build-engines.mjs —— 五平台引擎交叉编译 + 打 @fengqiao666/sitelens-*-engine
// 平台包。二进制文件名遵循发版约定 SiteLens_<平台>_engine_<版本>。
// 用法：node scripts/build-engines.mjs [平台...]   （缺省=全部五平台）
// 平台 token：win32-x64 linux-x64 linux-arm64 darwin-x64 darwin-arm64
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const tuiDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoDir = path.join(tuiDir, "..");
const self = JSON.parse(fs.readFileSync(path.join(tuiDir, "package.json"), "utf8"));
const VERSION = self.version;

const TARGETS = {
  "win32-x64": { goos: "windows", goarch: "amd64", token: "win64" },
  "linux-x64": { goos: "linux", goarch: "amd64", token: "linux64" },
  "linux-arm64": { goos: "linux", goarch: "arm64", token: "linux-arm64" },
  "darwin-x64": { goos: "darwin", goarch: "amd64", token: "mac64" },
  "darwin-arm64": { goos: "darwin", goarch: "arm64", token: "mac-arm64" },
};

const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(TARGETS);
for (const t of wanted) {
  const cfg = TARGETS[t];
  if (!cfg) {
    console.error(`未知平台：${t}（可选：${Object.keys(TARGETS).join(" ")}）`);
    process.exit(2);
  }
  const pkgDir = path.join(tuiDir, "packages", `sitelens-${t}-engine`);
  fs.mkdirSync(pkgDir, { recursive: true });
  const exe = `SiteLens_${cfg.token}_engine_${VERSION}${cfg.goos === "windows" ? ".exe" : ""}`;

  process.stdout.write(`编译 ${t} → ${exe} … `);
  execSync(
    `go build -trimpath -ldflags "-s -w" -o "${path.join(pkgDir, exe)}" ./cmd/sitelens`,
    {
      cwd: repoDir,
      env: { ...process.env, CGO_ENABLED: "0", GOOS: cfg.goos, GOARCH: cfg.goarch },
      stdio: "inherit",
    },
  );

  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(
      {
        name: `@fengqiao666/sitelens-${t}-engine`,
        version: VERSION,
        description: `SiteLens 引擎（${cfg.goos}/${cfg.goarch}）—— @fengqiao666/sitelens-cli 平台二进制`,
        license: "GPL-3.0",
        os: [cfg.goos],
        cpu: [cfg.goarch],
        files: [exe, "data"],
        repository: self.repository,
      },
      null,
      2,
    ) + "\n",
  );
  // 指纹库随包（公开仓库内数据，引擎默认相对路径 data/go/ 就地生效）
  fs.mkdirSync(path.join(pkgDir, "data", "go"), { recursive: true });
  for (const f of ["technologies.json", "tech_cpe.json"]) {
    fs.copyFileSync(path.join(repoDir, "data", "go", f), path.join(pkgDir, "data", "go", f));
  }
  fs.writeFileSync(
    path.join(pkgDir, "README.md"),
    `# ${`@fengqiao666/sitelens-${t}-engine`}\n\nSiteLens 引擎平台二进制（${exe}），由 \`@fengqiao666/sitelens-cli\` 按平台自动安装，一般无需直接依赖。\n项目主页：https://cnb.cool/feng-qiao/sitelens\n`,
  );
  const mb = (fs.statSync(path.join(pkgDir, exe)).size / 1048576).toFixed(1);
  console.log(`ok（${mb} MB）`);
}
console.log(`\n平台包就绪（v${VERSION}）：tui/packages/`);
