// src/app.jsx
import React, { useState, useEffect, useMemo } from "react";
import { render, Box, Text, useApp, useInput } from "ink";
import TextInput from "ink-text-input";
import SelectInput from "ink-select-input";

// src/engine.mjs
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
var EXE = process.platform === "win32" ? ".exe" : "";
function selfVersion() {
  return JSON.parse(
    fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")
  ).version;
}
function platToken(platform, arch) {
  if (platform === "win32") return "win64";
  if (platform === "linux") return arch === "arm64" ? "linux-arm64" : "linux64";
  if (platform === "darwin") return arch === "arm64" ? "mac-arm64" : "mac64";
  return `${platform}-${arch}`;
}
function enginePkgName() {
  return `@fengqiao666/sitelens-${process.platform}-${process.arch}-engine`;
}
function resolveEngine() {
  const errs = [];
  const envBin = (process.env.SITLENS_ENGINE || "").trim();
  if (envBin) {
    if (fs.existsSync(envBin)) return { bin: envBin, from: "SITLENS_ENGINE" };
    errs.push(`SITLENS_ENGINE \u6307\u5411\u7684\u6587\u4EF6\u4E0D\u5B58\u5728\uFF1A${envBin}`);
  }
  try {
    const req = createRequire(import.meta.url);
    const dir = path.dirname(req.resolve(`${enginePkgName()}/package.json`));
    const bin = path.join(dir, `SiteLens_${platToken(process.platform, process.arch)}_engine_${selfVersion()}${EXE}`);
    if (fs.existsSync(bin)) return { bin, from: enginePkgName() };
    errs.push(`\u5E73\u53F0\u5305\u5DF2\u88C5\u4F46\u4E8C\u8FDB\u5236\u7F3A\u5931\uFF1A${bin}`);
  } catch (e) {
    errs.push(`\u5E73\u53F0\u5305\u672A\u5B89\u88C5\uFF08${enginePkgName()}\uFF09`);
  }
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    const cand = path.join(dir, `sitelens${EXE}`);
    if (fs.existsSync(cand)) return { bin: cand, from: "PATH" };
  }
  throw new Error(
    `\u672A\u627E\u5230 SiteLens \u5F15\u64CE\u4E8C\u8FDB\u5236\u3002
${errs.map((e) => "  - " + e).join("\n")}
\u53EF\u8BBE SITLENS_ENGINE=<\u5F15\u64CE\u8DEF\u5F84>\uFF0C\u6216\u91CD\u88C5\u672C\u5305\uFF08npm i @fengqiao666/sitelens-cli\uFF09\u8865\u9F50\u5E73\u53F0\u5305\u3002`
  );
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
async function startServe(log = () => {
}, { allowPrivate = false } = {}) {
  const { bin: binRaw, from } = resolveEngine();
  const bin = path.resolve(binRaw);
  const port = await freePort();
  const profile = path.join(os.homedir(), ".sitelens");
  const dataDir = path.join(profile, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const cfgPath = path.join(profile, `tui-${port}.yml`);
  const lines = ["web:", `  listen: 127.0.0.1:${port}`, "store:", `  data_dir: ${dataDir.replace(/\\/g, "/")}`];
  if (allowPrivate) lines.push("target:", "  allow_private: true");
  const mlDir = (process.env.SITLENS_ML_ASSETS || "").trim();
  if (mlDir && fs.existsSync(mlDir)) {
    lines.push("ml:", `  assets_dir: ${mlDir.replace(/\\/g, "/")}`, "  predict: true");
  }
  fs.writeFileSync(cfgPath, lines.join("\n") + "\n");
  if ((process.env.SITLENS_DEBUG || "").trim() === "1") {
    try {
      fs.writeFileSync(
        path.join(profile, "last-serve-debug.txt"),
        [`# ${(/* @__PURE__ */ new Date()).toISOString()}`, `engine: ${bin} (${from})`, `cfg: ${cfgPath}`, fs.readFileSync(cfgPath, "utf8")].join("\n")
      );
    } catch {
    }
  }
  const child = spawn(bin, ["-config", cfgPath, "serve"], {
    cwd: path.dirname(bin),
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true
  });
  let errTail = "";
  child.stderr.on("data", (d) => {
    errTail = (errTail + d.toString()).slice(-2e3);
  });
  let spawnErr = null;
  child.on("error", (e) => {
    spawnErr = e;
  });
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 2e4;
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
            } catch {
            }
            await Promise.race([
              new Promise((r2) => child.once("exit", r2)),
              new Promise((r2) => setTimeout(r2, 1500))
            ]);
            try {
              fs.rmSync(cfgPath, { force: true });
            } catch {
            }
          }
        };
      }
    } catch {
    }
    if (child.exitCode !== null || spawnErr) {
      throw new Error(
        `\u5F15\u64CE serve \u542F\u52A8\u5931\u8D25${spawnErr ? `\uFF08${spawnErr.message}\uFF09` : `\uFF08\u9000\u51FA\u7801 ${child.exitCode}\uFF09`}\uFF1A
${errTail}`
      );
    }
    await new Promise((r) => setTimeout(r, 120));
  }
  try {
    child.kill();
  } catch {
  }
  throw new Error(`\u5F15\u64CE serve \u542F\u52A8\u8D85\u65F6\uFF1A
${errTail}`);
}

// src/client.mjs
var POLL_MS = 500;
async function api(base, p, method = "GET", body) {
  const r = await fetch(base + p, {
    method,
    headers: body ? { "Content-Type": "application/json" } : void 0,
    body: body ? JSON.stringify(body) : void 0
  });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      const j = await r.json();
      if (j && j.error) msg = j.error;
    } catch {
    }
    throw new Error(`${p}: ${msg}`);
  }
  return r.json();
}
var LEVELS = ["quick", "standard", "deep", "full", "assets", "stealth", "apocalypse"];
async function scan(base, url, { level = "standard", timeoutSec = 1800, signal, onEvent, onProgress }) {
  const { job_id } = await api(base, "/api/scan", "POST", { url, level });
  const seenEvents = /* @__PURE__ */ new Set();
  const start = Date.now();
  let dead = 0;
  while (true) {
    if (signal?.aborted) {
      try {
        await api(base, `/api/job/${job_id}/cancel`, "POST");
      } catch {
      }
      throw new Error("\u5DF2\u53D6\u6D88");
    }
    if ((Date.now() - start) / 1e3 > timeoutSec) {
      throw new Error(`\u626B\u63CF\u8D85\u65F6\uFF08${timeoutSec}s\uFF09\u2014\u2014\u53EF\u7528 --timeout \u8C03\u5927`);
    }
    let j;
    try {
      j = await api(base, `/api/job/${job_id}`);
    } catch (e) {
      if (String(e).includes("\u4EFB\u52A1\u4E0D\u5B58\u5728")) throw e;
      if (/fetch failed|ECONNREFUSED|ECONNRESET/i.test(String(e))) {
        dead++;
        if (dead >= 6) throw new Error("\u5F15\u64CE serve \u5931\u8054\uFF08\u8FDB\u7A0B\u610F\u5916\u9000\u51FA\uFF09\u2014\u2014\u8BF7\u91CD\u8BD5\u5E76\u5C06\u6B64\u73B0\u8C61\u53CD\u9988\u5230\u9879\u76EE Issue");
      } else {
        dead = 0;
      }
      await new Promise((r) => setTimeout(r, POLL_MS));
      continue;
    }
    for (const ev of j.events || []) {
      const key = `${ev.ts ?? ""}|${ev.kind}|${ev.text}`;
      if (!seenEvents.has(key)) {
        seenEvents.add(key);
        onEvent?.(ev.kind, ev.text);
      }
    }
    onProgress?.(j.progress, j.message);
    if (j.status === "done" || j.status === "error" || j.status === "cancelled") {
      if (j.status === "error") throw new Error(j.message || "\u626B\u63CF\u5931\u8D25");
      if (j.status === "cancelled") throw new Error("\u5DF2\u53D6\u6D88");
      let results = null;
      if (j.scan_id) {
        try {
          const h = await api(base, `/api/history/${j.scan_id}`);
          results = h?.result ?? h;
        } catch {
        }
      }
      return { ...j, results };
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

// src/app.jsx
import { jsx, jsxs } from "react/jsx-runtime";
var SEV_COLOR = { critical: "redBright", high: "red", medium: "yellow", low: "cyan", info: "gray" };
var KIND_COLOR = { hit: "red", bypass: "yellow", auth: "cyan", ml: "magenta", budget: "yellow", graph: "gray" };
var LEVEL_DESC = {
  quick: "\u5FEB\u901F\u2014\u2014\u9996\u9875\u91C7\u96C6 + \u6307\u7EB9\uFF0C\u4E0D\u722C\u53D6",
  standard: "\u6807\u51C6\u2014\u2014\u540C\u57DF\u6D45\u722C\u53D6 + \u6307\u7EB9 + \u88AB\u52A8\u68C0\u6D4B",
  deep: "\u6DF1\u5EA6\u2014\u2014check \u6838\u5FC3\u96C6 + DAST \u53C2\u6570\u63A2\u6D4B",
  full: "\u5168\u9762\u2014\u2014\u76EE\u5F55/\u5B50\u57DF/WebShell/\u5168\u91CF check",
  assets: "\u8D44\u4EA7\u6D4B\u7ED8\u2014\u2014\u76EE\u5F55/\u5B50\u57DF/\u63A5\u7BA1/\u4E3B\u52A8\u6307\u7EB9",
  stealth: "\u9690\u533F\u2014\u2014\u6D4F\u89C8\u5668 UA + \u88AB\u52A8 + \u7F51\u7EDC\u5C42",
  apocalypse: "\u6BC1\u5929\u706D\u5730\u2014\u2014\u5168\u6A21\u5757 + \u5168\u91CF\u6A21\u677F\uFF08\u4EC5\u6388\u6743\u76EE\u6807\uFF09"
};
function runTUI() {
  return new Promise((resolve) => {
    const { waitUntilExit } = render(React.createElement(App), { exitOnCtrlC: false });
    waitUntilExit().then(resolve);
  });
}
function App() {
  const { exit } = useApp();
  const [phase, setPhase] = useState("input");
  const [url, setUrl] = useState("");
  const [serve, setServe] = useState(null);
  const [prog, setProg] = useState({ pct: 0, msg: "" });
  const [events, setEvents] = useState([]);
  const [result, setResult] = useState(null);
  const [errMsg, setErr] = useState("");
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setElapsed((e) => e + 1), 1e3);
    return () => clearInterval(t);
  }, []);
  useInput((input, key) => {
    if (input === "q" && phase === "scanning") {
      setErr("\u5DF2\u53D6\u6D88");
      setPhase("error");
      serve?.stop();
      exit();
    }
    if (key.ctrlC || key.escape) {
      serve?.stop();
      exit();
    }
  });
  const startScan = async (target, level) => {
    setPhase("scanning");
    try {
      const srv = await startServe({}, { allowPrivate: process.env.SITLENS_ALLOW_PRIVATE === "1" });
      setServe(srv);
      const job = await scan(srv.baseUrl, target, {
        level,
        onProgress: (pct, msg) => setProg({ pct, msg: msg ?? "" }),
        onEvent: (kind, text) => setEvents((evs) => [...evs.slice(-120), { kind, text, t: (/* @__PURE__ */ new Date()).toLocaleTimeString() }])
      });
      setResult(job.results ?? null);
      setPhase("summary");
      await srv.stop();
    } catch (e) {
      setErr(e.message || String(e));
      setPhase("error");
      await serve?.stop();
    }
  };
  if (phase === "input") {
    return /* @__PURE__ */ jsxs(Box, { flexDirection: "column", padding: 1, children: [
      /* @__PURE__ */ jsx(Text, { bold: true, color: "cyan", children: "SiteLens \u7AD9\u70B9\u900F\u89C6 \u2014\u2014 \u7EC8\u7AEF\u626B\u63CF\u53F0" }),
      /* @__PURE__ */ jsxs(Box, { marginTop: 1, children: [
        /* @__PURE__ */ jsx(Text, { color: "green", children: " \u76EE\u6807 URL > " }),
        /* @__PURE__ */ jsx(
          TextInput,
          {
            value: url,
            placeholder: "https://example.com",
            onChange: setUrl,
            onSubmit: (v) => {
              if (v.trim()) {
                setUrl(v.trim());
                setPhase("level");
              }
            }
          }
        )
      ] }),
      /* @__PURE__ */ jsx(Text, { dimColor: true, children: " \u56DE\u8F66\u63D0\u4EA4 \xB7 Ctrl+C \u9000\u51FA \xB7 \u6A21\u5F0F\u4E0B\u4E00 \u6B65\u9009\u62E9" })
    ] });
  }
  if (phase === "level") {
    return /* @__PURE__ */ jsxs(Box, { flexDirection: "column", padding: 1, children: [
      /* @__PURE__ */ jsxs(Text, { bold: true, children: [
        "\u76EE\u6807\uFF1A",
        url,
        " \u2014\u2014 \u9009\u62E9\u626B\u63CF\u6A21\u5F0F"
      ] }),
      /* @__PURE__ */ jsx(
        SelectInput,
        {
          items: LEVELS.map((l) => ({ label: `${l.padEnd(11)} ${LEVEL_DESC[l]}`, value: l })),
          onSelect: (item) => startScan(url, item.value)
        }
      )
    ] });
  }
  if (phase === "scanning") {
    const tail = events.slice(-8);
    return /* @__PURE__ */ jsxs(Box, { flexDirection: "column", padding: 1, children: [
      /* @__PURE__ */ jsxs(Text, { bold: true, children: [
        "\u626B\u63CF\u4E2D\uFF1A",
        url,
        "\uFF08",
        new Date(elapsed * 1e3).toISOString().substring(14, 19),
        "\uFF09"
      ] }),
      /* @__PURE__ */ jsx(Box, { width: 50, children: /* @__PURE__ */ jsx(ProgressBar, { pct: prog.pct }) }),
      /* @__PURE__ */ jsxs(Text, { dimColor: true, children: [
        String(prog.pct).padStart(3),
        "% ",
        prog.msg
      ] }),
      /* @__PURE__ */ jsx(Box, { flexDirection: "column", marginTop: 1, children: tail.map((ev, i) => /* @__PURE__ */ jsxs(Text, { color: KIND_COLOR[ev.kind] ?? "white", children: [
        "[",
        ev.t,
        "] ",
        ev.kind === "hit" ? ev.text : `${ev.kind} \xB7 ${ev.text}`
      ] }, i)) }),
      /* @__PURE__ */ jsx(Text, { dimColor: true, marginTop: 1, children: "q \u53D6\u6D88 \xB7 Ctrl+C \u9000\u51FA" })
    ] });
  }
  if (phase === "error") {
    return /* @__PURE__ */ jsx(Box, { flexDirection: "column", padding: 1, children: /* @__PURE__ */ jsx(Text, { color: "red", children: errMsg || "\u626B\u63CF\u5931\u8D25" }) });
  }
  const techs = result?.technologies?.length ?? 0;
  const verified = result?.verified ?? [];
  const vulns = result?.vulnerabilities?.length ?? 0;
  const ml = result?.extras?.ml_prior;
  return /* @__PURE__ */ jsxs(Box, { flexDirection: "column", padding: 1, children: [
    /* @__PURE__ */ jsxs(Text, { bold: true, color: "green", children: [
      "\u626B\u63CF\u5B8C\u6210\uFF1A",
      result?.url ?? url
    ] }),
    /* @__PURE__ */ jsxs(Text, { children: [
      techs,
      " \u9879\u6280\u672F \xB7 ",
      verified.length,
      " \u6761\u5DF2\u9A8C\u8BC1\u53D1\u73B0 \xB7 ",
      vulns,
      " \u6761\u6F0F\u6D1E\u60C5\u62A5 \xB7 \u5B89\u5168\u8BC4\u5206 ",
      result?.security?.grade ?? "-"
    ] }),
    ml ? /* @__PURE__ */ jsxs(Text, { color: "magenta", children: [
      "ML \u5148\u9A8C\uFF1A",
      ml.products?.[0]?.product,
      "\uFF08",
      ml.products?.[0]?.prob,
      "\uFF09\u63D0\u6743 ",
      ml.boosted,
      " \u9879",
      ml.promoted?.length ? `\u3001\u589E\u91CF\u7EB3\u5165 ${ml.promoted.length} \u9879` : ""
    ] }) : null,
    /* @__PURE__ */ jsxs(Box, { flexDirection: "column", marginTop: 1, children: [
      verified.slice(0, 15).map((v, i) => /* @__PURE__ */ jsxs(Text, { color: SEV_COLOR[v.severity] ?? "white", children: [
        "[",
        v.severity,
        "] ",
        v.title,
        " \u2014 ",
        v.url
      ] }, i)),
      verified.length > 15 ? /* @__PURE__ */ jsxs(Text, { dimColor: true, children: [
        "\u2026\u5176\u4F59 ",
        verified.length - 15,
        " \u6761\u89C1\u5386\u53F2\uFF08serve \u6570\u636E\u76EE\u5F55\uFF09"
      ] }) : null
    ] }),
    /* @__PURE__ */ jsx(Text, { dimColor: true, marginTop: 1, children: "\u626B\u63CF\u5386\u53F2\u4E0E\u5B8C\u6574 JSON \u843D ~/.sitelens/data \xB7 Ctrl+C \u9000\u51FA" })
  ] });
}
function ProgressBar({ pct }) {
  const w = 46;
  const fill = Math.round(Math.min(100, Math.max(0, pct)) / 100 * w);
  return /* @__PURE__ */ jsxs(Text, { children: [
    /* @__PURE__ */ jsx(Text, { color: "cyan", children: "\u2588".repeat(fill) }),
    /* @__PURE__ */ jsx(Text, { color: "gray", children: "\u2591".repeat(w - fill) })
  ] });
}
export {
  runTUI
};
