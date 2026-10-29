// app.jsx —— 交互式 TUI（Ink）。
//
// 首屏是**功能选择**（5.2 起）：扫描 / 源码审计 / 本机诊断 / 扫描历史。
// 扫描走完整交互流程（目标 → 模式 → 实时进度 → 摘要）；其余三项交回给
// 命令层执行（onAction），TUI 只做选择器——避免 Ink 渲染与子进程输出打架。
//
// 语义色与产品一致（无 emoji，纯文本 + 颜色）。
import React, { useState, useEffect } from "react";
import { render, Box, Text, useApp, useInput } from "ink";
import TextInput from "ink-text-input";
import SelectInput from "ink-select-input";
import { startServe } from "./engine.mjs";
import { scan, LEVELS } from "./client.mjs";

const SEV_COLOR = { critical: "redBright", high: "red", medium: "yellow", low: "cyan", info: "gray" };
const KIND_COLOR = { hit: "red", bypass: "yellow", auth: "cyan", ml: "magenta", budget: "yellow", graph: "gray" };

const LEVEL_DESC = {
  quick: "快速——首页采集 + 指纹，不爬取",
  standard: "标准——同域浅爬取 + 指纹 + 被动检测",
  deep: "深度——check 核心集 + DAST 参数探测",
  full: "全面——目录/子域/WebShell/全量 check",
  assets: "资产测绘——目录/子域/接管/主动指纹",
  stealth: "隐匿——浏览器 UA + 被动 + 网络层",
  apocalypse: "毁天灭地——全模块 + 全量模板（仅授权目标）",
};

const MENU = [
  { label: "扫描目标网站", value: "scan", hint: "指纹 / 爬取 / 验证型检测 / DAST" },
  { label: "源码静态审计", value: "audit", hint: "污点分析 + 规则匹配（本地目录）" },
  { label: "本机诊断", value: "doctor", hint: "资产就位 / 降级能力 / 最近失败" },
  { label: "扫描历史", value: "history", hint: "最近扫描与已验证发现汇总" },
  { label: "退出", value: "quit", hint: "" },
];

/**
 * runTUI 启动交互式 TUI，**返回一个动作**（而不是直接 exit）。
 *
 * 返回值：{cmd, args} —— 交由命令层（src/commands.mjs）执行；
 * 返回 null 表示用户退出。
 */
export function runTUI() {
  return new Promise((resolve) => {
    let unmount = null;
    let settled = false;
    const finish = (action) => {
      if (settled) return;
      settled = true;
      try {
        unmount?.();
      } catch {}
      resolve(action);
    };
    const r = render(React.createElement(App, { onAction: finish }), { exitOnCtrlC: false });
    unmount = r.unmount;
    r.waitUntilExit().then(() => finish(null));
  });
}

function App({ onAction }) {
  const { exit } = useApp();
  const [phase, setPhase] = useState("menu"); // menu | input | level | scanning | summary | error | auditdir
  const [url, setUrl] = useState("");
  const [dir, setDir] = useState("");
  const [serve, setServe] = useState(null);
  const [prog, setProg] = useState({ pct: 0, msg: "" });
  const [events, setEvents] = useState([]);
  const [result, setResult] = useState(null);
  const [errMsg, setErr] = useState("");
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(t);
  }, []);

  useInput((input, key) => {
    if (input === "q" && phase === "scanning") {
      setErr("已取消");
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
      const srv = await startServe({}, { allowPrivate: process.env.SITELENS_ALLOW_PRIVATE === "1" });
      setServe(srv);
      const job = await scan(srv.baseUrl, target, {
        level,
        onProgress: (pct, msg) => setProg({ pct, msg: msg ?? "" }),
        onEvent: (kind, text) =>
          setEvents((evs) => [...evs.slice(-120), { kind, text, t: new Date().toLocaleTimeString() }]),
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

  if (phase === "menu") {
    return (
      <Box flexDirection="column" padding={1}>
        <Text bold color="cyan">
          SiteLens 站点透视 —— 终端扫描台
        </Text>
        <Box marginTop={1} flexDirection="column">
          {MENU.map((m) => (
            <Text key={m.value} color={m.value === "quit" ? "gray" : "white"}>
              {"  " + m.label}
              {m.hint ? <Text dimColor>{"  —— " + m.hint}</Text> : null}
            </Text>
          ))}
        </Box>
        <Box marginTop={1}>
          <SelectInput
            items={MENU.map((m) => ({ label: m.label, value: m.value }))}
            onSelect={(item) => {
              if (item.value === "quit") {
                onAction(null);
                return;
              }
              if (item.value === "audit") {
                setPhase("auditdir");
                return;
              }
              if (item.value === "doctor") {
                onAction({ cmd: "doctor", args: [] });
                return;
              }
              if (item.value === "history") {
                onAction({ cmd: "history", args: [] });
                return;
              }
              setPhase("input");
            }}
          />
        </Box>
        <Text dimColor> ↑↓ 选择 · 回车确认 · Ctrl+C 退出</Text>
      </Box>
    );
  }

  if (phase === "auditdir") {
    return (
      <Box flexDirection="column" padding={1}>
        <Text bold>源码静态审计 —— 输入要审计的目录</Text>
        <Box marginTop={1}>
          <Text color="green">{" 目录 > "}</Text>
          <TextInput
            value={dir}
            placeholder="/path/to/source 或 ."
            onChange={setDir}
            onSubmit={(v) => {
              const d = v.trim();
              if (!d) return;
              onAction({ cmd: "audit", args: [d] });
            }}
          />
        </Box>
        <Text dimColor> 回车开始审计 · Ctrl+C 退出</Text>
      </Box>
    );
  }

  if (phase === "input") {
    return (
      <Box flexDirection="column" padding={1}>
        <Text bold color="cyan">
          SiteLens 站点透视 —— 终端扫描台
        </Text>
        <Box marginTop={1}>
          <Text color="green">{" 目标 URL > "}</Text>
          <TextInput
            value={url}
            placeholder="https://example.com"
            onChange={setUrl}
            onSubmit={(v) => {
              if (v.trim()) {
                setUrl(v.trim());
                setPhase("level");
              }
            }}
          />
        </Box>
        <Text dimColor> 回车提交 · Ctrl+C 退出 · 模式下一 步选择</Text>
      </Box>
    );
  }

  if (phase === "level") {
    return (
      <Box flexDirection="column" padding={1}>
        <Text bold>
          目标：{url} —— 选择扫描模式
        </Text>
        <SelectInput
          items={LEVELS.map((l) => ({ label: `${l.padEnd(11)} ${LEVEL_DESC[l]}`, value: l }))}
          onSelect={(item) => startScan(url, item.value)}
        />
      </Box>
    );
  }

  if (phase === "scanning") {
    const tail = events.slice(-8);
    return (
      <Box flexDirection="column" padding={1}>
        <Text bold>
          扫描中：{url}（{new Date(elapsed * 1000).toISOString().substring(14, 19)}）
        </Text>
        <Box width={50}>
          <ProgressBar pct={prog.pct} />
        </Box>
        <Text dimColor>
          {String(prog.pct).padStart(3)}% {prog.msg}
        </Text>
        <Box flexDirection="column" marginTop={1}>
          {tail.map((ev, i) => (
            <Text key={i} color={KIND_COLOR[ev.kind] ?? "white"}>
              [{ev.t}] {ev.kind === "hit" ? ev.text : `${ev.kind} · ${ev.text}`}
            </Text>
          ))}
        </Box>
        <Text dimColor marginTop={1}>
          q 取消 · Ctrl+C 退出
        </Text>
      </Box>
    );
  }

  if (phase === "error") {
    return (
      <Box flexDirection="column" padding={1}>
        <Text color="red">{errMsg || "扫描失败"}</Text>
      </Box>
    );
  }

  // summary
  const techs = result?.technologies?.length ?? 0;
  const verified = result?.verified ?? [];
  const vulns = result?.vulnerabilities?.length ?? 0;
  const ml = result?.extras?.ml_prior;
  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="green">
        扫描完成：{result?.url ?? url}
      </Text>
      <Text>
        {techs} 项技术 · {verified.length} 条已验证发现 · {vulns} 条漏洞情报 · 安全评分 {result?.security?.grade ?? "-"}
      </Text>
      {ml ? (
        <Text color="magenta">
          ML 先验：{ml.products?.[0]?.product}（{ml.products?.[0]?.prob}）提权 {ml.boosted} 项
          {ml.promoted?.length ? `、增量纳入 ${ml.promoted.length} 项` : ""}
        </Text>
      ) : null}
      <Box flexDirection="column" marginTop={1}>
        {verified.slice(0, 15).map((v, i) => (
          <Text key={i} color={SEV_COLOR[v.severity] ?? "white"}>
            [{v.severity}] {v.title} — {v.url}
          </Text>
        ))}
        {verified.length > 15 ? <Text dimColor>…其余 {verified.length - 15} 条见历史（sitelens history）</Text> : null}
      </Box>
      <Text dimColor marginTop={1}>
        扫描历史与完整 JSON 落 ~/.sitelens/data/state · Ctrl+C 退出
      </Text>
    </Box>
  );
}

function ProgressBar({ pct }) {
  const w = 46;
  const fill = Math.round((Math.min(100, Math.max(0, pct)) / 100) * w);
  return (
    <Text>
      <Text color="cyan">{"█".repeat(fill)}</Text>
      <Text color="gray">{"░".repeat(w - fill)}</Text>
    </Text>
  );
}
