/* 批量扫描：URL 列表（可选逐行档位）→ /api/batch → 进度 + 日志 + 队列 + CSV 导出 + 断点续跑。
   行语法：`https://example.com` 或 `https://example.com quick|standard|deep|full`（中文档位亦可）。
   工作台批量页签专用；ID 统一 batch- 前缀。 */
(function () {
  "use strict";
  var box = document.getElementById("batch-urls");
  if (!box) return;

  var LIMIT = 50;
  var LEVEL_ALIAS = {
    "快速": "quick", "标准": "standard", "深度": "deep", "完整": "full", "穷尽": "exhaustive",
    "quick": "quick", "standard": "standard", "deep": "deep", "full": "full"
  };
  var LEVEL_LABEL = { quick: "快速", standard: "标准", deep: "深度", full: "完整", exhaustive: "穷尽", assets: "资产", stealth: "隐匿", apocalypse: "穷尽" };
  var lastRows = [];
  var resumable = [];
  box.addEventListener("input", updateCount);

  // 上限随 batch.max_urls 配置（页面加载时拉取一次）
  try {
    api.get("/api/settings").then(function (c) {
      var m = c && c.batch && c.batch.max_urls;
      if (m > 0) { LIMIT = m; updateCount(); }
    });
  } catch (e) {}

  function parseEntries() {
    var lines = box.value.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
    var out = [];
    for (var i = 0; i < lines.length && out.length < LIMIT; i++) {
      var parts = lines[i].split(/\s+/);
      var level = "";
      if (parts.length >= 2) {
        var lv = LEVEL_ALIAS[parts[parts.length - 1].toLowerCase()] || LEVEL_ALIAS[parts[parts.length - 1]];
        if (lv) { level = lv; parts = parts.slice(0, -1); }
      }
      var url = parts.join(" ").trim();
      if (url) out.push({ url: url, level: level });
    }
    return out;
  }

  function updateCount() {
    var entries = parseEntries();
    var n = document.getElementById("batch-n");
    if (!n) return;
    var byLevel = {};
    entries.forEach(function (e) { if (e.level) byLevel[e.level] = (byLevel[e.level] || 0) + 1; });
    var lv = Object.keys(byLevel).map(function (k) { return (LEVEL_LABEL[k] || k) + " " + byLevel[k]; }).join(" · ");
    n.textContent = entries.length + " / " + LIMIT +
      (entries.length > LIMIT ? "（超出部分将被忽略）" : "") +
      (lv ? " · 档位：" + lv : "");
  }

  /* ---------------- 断点续跑：加载未完成批量 ---------------- */
  function loadResumable() {
    var wrap = document.getElementById("batch-resume-wrap");
    var hint = document.getElementById("batch-resume-hint");
    if (!wrap || !hint) return;
    api.get("/api/batch/jobs").then(function (r) {
      resumable = (r && r.jobs) || [];
      if (!resumable.length) { wrap.style.display = "none"; return; }
      var total = 0, pending = 0;
      resumable.forEach(function (j) {
        total++;
        (j.items || []).forEach(function (it) { if (it.status !== "done") pending++; });
      });
      hint.textContent = "发现 " + total + " 个未完成批量（待跑 " + pending + " 条），可断点续跑";
      wrap.style.display = "";
    }).catch(function () {});
  }
  window.loadResumable = loadResumable;

  window.resumeBatch = function () {
    if (!resumable.length) return;
    var job = resumable[0];
    var wrap = document.getElementById("batch-resume-wrap");
    if (wrap) wrap.style.display = "none";
    api.post("/api/batch/" + job.job_id + "/resume", {}).then(function (r) {
      startWatch(r.job_id, r.total || 1, "续跑");
    }).catch(function (e) {
      toast("续跑失败：" + e.message, "err");
      loadResumable();
    });
  };

  /* ---------------- 进度/队列/日志渲染（新任务与续跑共用） ---------------- */
  function startWatch(jobId, total, tag) {
    document.getElementById("batch-go").disabled = true;
    var cancelBtn = document.getElementById("batch-cancel");
    cancelBtn.disabled = false;
    cancelBtn.textContent = "取消";
    cancelBtn.style.display = "";
    document.getElementById("batch-pw").style.display = "block";
    document.getElementById("batch-log").style.display = "block";
    var logBox = document.getElementById("batch-log");
    logBox.innerHTML = "";
    var seen = {};
    lastRows = [];
    var exportBtn = document.getElementById("batch-export");
    if (exportBtn) exportBtn.style.display = "none";
    window.__batchJobId = jobId;

    function addLog(line) {
      if (!line || seen[line]) return;
      seen[line] = 1;
      var div = document.createElement("div");
      var isFail = line.indexOf("失败") >= 0;
      var isSkip = line.indexOf("跳过") >= 0;
      div.innerHTML = '<span class="' + (isFail ? "fail" : "ok") + '">' +
        (isFail ? "✕" : isSkip ? "⊘" : "✓") + "</span> " + esc(line);
      logBox.appendChild(div);
      logBox.scrollTop = logBox.scrollHeight;
    }

    var queueWrap = document.getElementById("batch-queue");
    var rowsEl = document.getElementById("batch-rows");
    if (queueWrap) queueWrap.style.display = "";
    function renderRows(rows) {
      if (!rows || !rowsEl) return;
      lastRows = rows;
      rowsEl.innerHTML = rows.map(function (rw) {
        var st = rw.status || "queued";
        var label = st === "done" ? "完成" : st === "failed" ? "失败" : st === "skipped" ? "跳过" : "扫描中";
        var elapsed = rw.elapsed_ms ? (rw.elapsed_ms / 1000).toFixed(1) + "s" : "—";
        var findings = st === "done" ? (rw.findings != null ? rw.findings : "—") : "—";
        if (st === "done" && (rw.new_findings != null || rw.fixed != null)) {
          findings += ' <span class="hint" style="font-size:11.5px">(+' + (rw.new_findings || 0) + " / -" + (rw.fixed || 0) + ")</span>";
        }
        var level = rw.level ? (LEVEL_LABEL[rw.level] || rw.level) : "默认";
        var attempts = rw.attempts > 1 ? "（重试 " + (rw.attempts - 1) + "）" : "";
        return "<tr><td><span class=\"badge " + (st === "done" ? "ok" : st === "failed" ? "danger" : "warn") + "\">" + label + "</span></td>" +
          '<td class="mono" style="word-break:break-all">' + esc(rw.url) + "</td>" +
          "<td>" + esc(level) + "</td>" +
          "<td>" + findings + "</td><td>" + elapsed + attempts + "</td></tr>";
      }).join("");
    }

    return new Promise(function (resolve, reject) {
      var handle = slPoll(function () {
        api.get("/api/job/" + jobId + "/results").then(function (job) {
          document.getElementById("batch-bar").style.width = (job.progress || 0) + "%";
          addLog(job.message);
          document.getElementById("batch-hint").textContent =
            (tag ? tag + " · " : "") + (job.done || 0) + " / " + (job.total || total) + " 已完成" +
            (job.status === "cancelling" ? "（取消中…）" : "");
          var rows = job.rows || (job.results && job.results.rows);
          if (rows) renderRows(rows);
          if (job.status === "done" || job.status === "cancelled") {
            handle.stop();
            resolve(job);
          }
        }).catch(function (e) { handle.stop(); reject(e); });
      }, 1200);
    }).then(function (job) {
      document.getElementById("batch-go").disabled = false;
      document.getElementById("batch-cancel").style.display = "none";
      if (job.status === "cancelled") {
        document.getElementById("batch-hint").textContent = "批量已取消（可断点续跑）";
        toast("批量已取消，可续跑", "err");
      } else {
        document.getElementById("batch-hint").innerHTML =
          '全部完成 · <a href="/history" style="color:var(--info)">→ 查看历史 / 导出宽表</a>';
        toast("批量扫描完成", "ok");
      }
      if (exportBtn && lastRows.length) exportBtn.style.display = "";
      loadResumable();
    }).catch(function (e) {
      document.getElementById("batch-go").disabled = false;
      document.getElementById("batch-cancel").style.display = "none";
      document.getElementById("batch-hint").textContent = "失败：" + e.message;
      loadResumable();
    });
  }

  /* D-09：提交期间禁止重复触发。旧实现直到 startWatch() 才 disable 按钮，
     网络/引擎慢时双击会发出两次 POST /api/batch（两个批量任务并发跑同一批目标）。 */
  var batchStarting = false;
  window.startBatch = function () {
    var entries = parseEntries();
    if (!entries.length) return;
    if (batchStarting) return;
    batchStarting = true;
    var goBtn = document.getElementById("batch-go");
    if (goBtn) goBtn.disabled = true;
    api.post("/api/batch", { entries: entries }).then(function (r) {
      batchStarting = false;
      startWatch(r.job_id, r.total || entries.length, "");
    }).catch(function (e) {
      batchStarting = false;
      if (goBtn) goBtn.disabled = false;
      toast("批量提交失败：" + e.message, "err");
    });
  };

  // 批量结果 CSV（Excel 友好：UTF-8 BOM；列：URL/状态/档位/发现/技术/尝试/耗时ms/错误）
  window.exportBatchCSV = function () {
    if (!lastRows.length) return;
    function cell(v) {
      var s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }
    var head = ["url", "status", "level", "findings", "techs", "attempts", "elapsed_ms", "error"];
    var lines = [head.join(",")];
    lastRows.forEach(function (r) {
      lines.push([r.url, r.status, r.level || "", r.findings, r.techs, r.attempts, r.elapsed_ms, r.error || ""]
        .map(cell).join(","));
    });
    var blob = new Blob(["\ufeff" + lines.join("\n")], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sitelens-batch-" + (window.__batchJobId || Date.now()) + ".csv";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  };

  window.cancelBatch = function () {
    var btn = document.getElementById("batch-cancel");
    btn.disabled = true;
    btn.textContent = "取消中…";
    api.post("/api/job/" + window.__batchJobId + "/cancel", {})
      .catch(function (e) { window.slReportError(e); });
  };

  /* ---------------- 定时批量（BT-03） ---------------- */

  /* D-03（DOM XSS）：schedule.id 来自服务端存储、而 POST /api/batch/schedules 的
     id 由客户端可写，因此 id 是不可信输入。旧实现把它拼进内联 onclick 的 JS
     字符串（onclick="runSchedule('ID')"）——esc() 只保证 HTML 属性不被闭合，
     浏览器会先做实体解码再把属性值交给 JS 解析，形如 x&#39;);alert(1)// 仍能逃逸。
     现在：id 只经 data-* 属性传递（HTML 属性上下文，esc 足够），点击行为由容器
     上的一次性事件委托处理，任何 id 都不会进入可执行上下文。 */
  function bindScheduleActions() {
    var box = document.getElementById("batch-sched-list");
    if (!box || box.__slSchedBound) return;
    box.__slSchedBound = true;
    box.addEventListener("click", function (ev) {
      var btn = ev.target && ev.target.closest ? ev.target.closest("button[data-sched-act]") : null;
      if (!btn || !box.contains(btn)) return;
      var id = btn.getAttribute("data-sched-id") || "";
      if (!id) return;
      var act = btn.getAttribute("data-sched-act");
      if (act === "run") window.runSchedule(id);
      else if (act === "del") window.deleteSchedule(id);
    });
  }

  function renderSchedules(list) {
    var box = document.getElementById("batch-sched-list");
    if (!box) return;
    if (!list || !list.length) { box.textContent = "暂无定时任务"; return; }
    box.innerHTML = list.map(function (sc) {
      var next = sc.next_run_at ? new Date(sc.next_run_at).toLocaleString() : "—";
      return '<div style="display:flex;gap:8px;align-items:center;margin:4px 0;font-size:12.5px">' +
        '<span class="mono">' + esc(sc.id) + "</span>" +
        "<span>每 " + (sc.every_minutes || "?") + " 分钟</span>" +
        "<span>目标 " + ((sc.entries || []).length) + "</span>" +
        '<span class="hint">下次 ' + esc(next) + "</span>" +
        '<button class="btn ghost small" type="button" data-sched-act="run" data-sched-id="' +
        esc(sc.id) + '">立即跑</button>' +
        '<button class="btn ghost small" type="button" data-sched-act="del" data-sched-id="' +
        esc(sc.id) + '">删除</button>' +
        "</div>";
    }).join("");
    bindScheduleActions();
  }
  function loadSchedules() {
    api.get("/api/batch/schedules").then(function (r) { renderSchedules((r && r.schedules) || []); })
      .catch(function () {});
  }
  window.loadSchedules = loadSchedules;
  window.saveSchedule = function () {
    var entries = parseEntries();
    if (!entries.length) { toast("先填 URL 列表", "err"); return; }
    var every = parseInt((document.getElementById("batch-sched-every") || {}).value, 10) || 60;
    api.post("/api/batch/schedules", { every_minutes: every, entries: entries, enabled: true })
      .then(function () { toast("定时任务已保存（每 " + every + " 分钟）", "ok"); loadSchedules(); })
      .catch(function (e) { toast("保存失败：" + e.message, "err"); });
  };
  window.runSchedule = function (id) {
    // id 是不可信输入（见上方 D-03 注释）：拼进 URL 路径前必须编码，
    // 否则带 "/" "?" "#" 的 id 能改变请求路径。
    api.post("/api/batch/schedules/" + encodeURIComponent(id) + "/run", {}).then(function (r) {
      startWatch(r.job_id, r.total || 1, "定时任务");
      loadSchedules();
    }).catch(function (e) { toast("执行失败：" + e.message, "err"); });
  };
  window.deleteSchedule = function (id) {
    api.del("/api/batch/schedules/" + encodeURIComponent(id)).then(function () { loadSchedules(); })
      .catch(function (e) { toast("删除失败：" + e.message, "err"); });
  };

  loadResumable();
  loadSchedules();
})();
