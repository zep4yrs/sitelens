// client.mjs —— serve API 客户端：POST /api/scan → job 轮询（进度 +
// 事件环）→ /api/job/{id}/results。与桌面壳/前端同一套后端契约。
const POLL_MS = 500;

async function api(base, p, method = "GET", body) {
  const r = await fetch(base + p, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      const j = await r.json();
      if (j && j.error) msg = j.error;
    } catch {}
    throw new Error(`${p}: ${msg}`);
  }
  return r.json();
}

export const LEVELS = ["quick", "standard", "deep", "full", "assets", "stealth", "apocalypse"];

// scan 提交并轮询到终态。onEvent(kind, text) / onProgress(pct, message)
// 即时回调；返回 job 终态对象（含 results 摘要字段）。
export async function scan(base, url, { level = "standard", timeoutSec = 1800, signal, onEvent, onProgress }) {
  const { job_id } = await api(base, "/api/scan", "POST", { url, level });
  const seenEvents = new Set();
  const start = Date.now();
  let dead = 0; // serve 连续失联计数（进程意外退出时快速失败，不无限轮询）
  while (true) {
    if (signal?.aborted) {
      try {
        await api(base, `/api/job/${job_id}/cancel`, "POST");
      } catch {}
      throw new Error("已取消");
    }
    if ((Date.now() - start) / 1000 > timeoutSec) {
      throw new Error(`扫描超时（${timeoutSec}s）——可用 --timeout 调大`);
    }
    let j;
    try {
      j = await api(base, `/api/job/${job_id}`);
    } catch (e) {
      if (String(e).includes("任务不存在")) throw e;
      if (/fetch failed|ECONNREFUSED|ECONNRESET/i.test(String(e))) {
        dead++;
        if (dead >= 6) throw new Error("引擎 serve 失联（进程意外退出）——请重试并将此现象反馈到项目 Issue");
      } else {
        dead = 0;
      }
      await new Promise((r) => setTimeout(r, POLL_MS)); // serve 瞬断容忍
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
      if (j.status === "error") throw new Error(j.message || "扫描失败");
      if (j.status === "cancelled") throw new Error("已取消");
      // 完整结果按 scan_id 从历史接口取（job 只携带 scan_id；
      // 历史详情的扫描体在 result 键下）
      let results = null;
      if (j.scan_id) {
        try {
          const h = await api(base, `/api/history/${j.scan_id}`);
          results = h?.result ?? h;
        } catch {}
      }
      return { ...j, results };
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}
