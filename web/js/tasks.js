/* =========================================================================
   XC-01 任务中心（工作台右上角抽屉）
   -------------------------------------------------------------------------
   数据源：GET /api/tasks（后端任务中心接口；契约按「宽松解析」实现，兼容
   数组或 {tasks|items|jobs:[]} 包装，字段见 normalizeTasks）。
   行为：
     - 仅工作台（存在 .tw-app）挂载「任务」按钮 + 右侧抽屉；
     - 抽屉打开时每 2.5s 轮询 /api/tasks；关闭即停止（不后台空转）；
     - 状态徽章 / 进度条 / 相对时间；有 scan_id 的任务给「查看结果」链接
       （/history?id=N，历史页支持深链）；
     - 无接口（404/网络错误）静默降级：不再轮询，抽屉内显示接口未就绪，
       不弹错误、不影响工作台。
   依赖：window.api（common.js）、window.esc（common.js）；均做存在性判断。
   ========================================================================= */
(function () {
  "use strict";

  var POLL_MS = 2500;
  var EXTRA_WAIT_MS = 600;

  var state = {
    open: false,
    timer: null,
    available: true, // 接口是否可用（首次失败后不再轮询）
    tasks: [],
    lastAt: 0,
    inFlight: false
  };

  var ESC = (typeof window.esc === "function")
    ? window.esc
    : function (s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
          return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
      };

  /* ---------------- 纯逻辑（可在 node 中单测） ---------------- */

  function scanIdOf(t) {
    var cand = [
      t && t.scan_id, t && t.scanId,
      t && t.result && t.result.scan_id, t && t.result && t.result.scanId,
      t && t.result_scan_id
    ];
    for (var i = 0; i < cand.length; i++) {
      var n = Number(cand[i]);
      if (isFinite(n) && n > 0) return n;
    }
    return null;
  }

  function progressPct(t) {
    var raw = t.progress != null ? t.progress
      : t.percent != null ? t.percent
        : t.progress_pct != null ? t.progress_pct : null;
    if (raw == null) {
      if (t.done != null && t.total != null && Number(t.total) > 0) {
        raw = (Number(t.done) / Number(t.total)) * 100;
      } else {
        return null;
      }
    }
    var n = Number(raw);
    if (!isFinite(n)) return null;
    // 兼容 0~1 的比例（后端现阶段应返回 0~100；有小数点才按比例换算，避免把 1% 当 100%）
    if (n > 0 && n <= 1 && String(raw).indexOf(".") >= 0) n *= 100;
    return Math.max(0, Math.min(100, Math.round(n)));
  }

  function normalizeTasks(payload) {
    var arr = [];
    if (Array.isArray(payload)) arr = payload;
    else if (payload && Array.isArray(payload.tasks)) arr = payload.tasks;
    else if (payload && Array.isArray(payload.items)) arr = payload.items;
    else if (payload && Array.isArray(payload.jobs)) arr = payload.jobs;
    return arr.map(function (t, i) {
      t = t || {};
      var id = t.id != null ? t.id
        : t.job_id != null ? t.job_id
          : t.task_id != null ? t.task_id : "task-" + i;
      return {
        id: String(id),
        kind: String(t.kind || t.type || t.name || t.mode || "任务"),
        status: String(t.status || t.state || "unknown").toLowerCase(),
        progress: progressPct(t),
        message: String(t.message || t.msg || t.title || ""),
        url: String(t.url || t.target || t.host || ""),
        time: String(t.created_at || t.started_at || t.updated_at || t.time || ""),
        scanId: scanIdOf(t)
      };
    });
  }

  function statusMeta(s) {
    switch (String(s || "").toLowerCase()) {
      case "running": case "in_progress": return { cls: "info", label: "运行中" };
      case "queued": case "pending": case "waiting": return { cls: "", label: "排队中" };
      case "done": case "success": case "succeeded": case "completed": case "ok":
        return { cls: "ok", label: "完成" };
      case "partial": return { cls: "warn", label: "已中断" };
      case "failed": case "error": case "failure": return { cls: "danger", label: "失败" };
      case "cancelled": case "canceled": return { cls: "", label: "已取消" };
      case "paused": case "blocked": return { cls: "warn", label: "已暂停" };
      default: return { cls: "", label: String(s || "未知") };
    }
  }

  function relTime(v, now) {
    var raw = String(v == null ? "" : v).trim();
    if (!raw) return "";
    var t = Date.parse(raw.replace(" ", "T"));
    if (!isFinite(t)) return raw;
    var diff = Math.max(0, (now || Date.now()) - t);
    if (diff < 60000) return "刚刚";
    if (diff < 3600000) return Math.floor(diff / 60000) + " 分钟前";
    if (diff < 86400000) return Math.floor(diff / 3600000) + " 小时前";
    return Math.floor(diff / 86400000) + " 天前";
  }

  function rowHTML(t) {
    var m = statusMeta(t.status);
    var pct = t.progress;
    var badge = '<span class="badge ' + (m.cls || "") + '">' + ESC(m.label) + "</span>";
    var prog = pct == null ? "" :
      '<div class="progressbar tasks-prog" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
      pct + '" aria-label="任务进度"><i style="width:' + pct + '%"></i></div>' +
      '<span class="hint" style="margin:0">' + pct + "%</span>";
    var link = t.scanId
      ? '<a class="btn ghost small" href="/history?id=' + t.scanId + '">查看结果</a>'
      : "";
    return '<div class="tasks-row" data-task-id="' + ESC(t.id) + '">' +
      '<div class="tasks-row-top">' + badge +
      '<b class="tasks-kind">' + ESC(t.kind) + "</b>" +
      '<span class="tasks-time mono">' + ESC(relTime(t.time)) + "</span>" +
      '<span class="tasks-actions">' + link + "</span></div>" +
      (t.url ? '<div class="tasks-url mono">' + ESC(t.url) + "</div>" : "") +
      (t.message ? '<div class="tasks-msg">' + ESC(t.message) + "</div>" : "") +
      (pct == null ? "" : '<div class="tasks-progwrap">' + prog + "</div>") +
      "</div>";
  }

  /* ---------------- DOM 装配 ---------------- */

  function mount() {
    if (document.getElementById("tasks-btn")) return;
    if (!document.querySelector(".tw-app")) return; // 仅工作台
    var host = document.querySelector(".top-right") || document.getElementById("tw-topslot");
    if (!host) return;

    var btn = document.createElement("button");
    btn.type = "button";
    btn.id = "tasks-btn";
    btn.className = "theme-btn tasks-btn";
    btn.title = "任务中心（任务列表 / 进度）";
    btn.setAttribute("aria-label", "任务中心");
    btn.setAttribute("aria-haspopup", "dialog");
    btn.setAttribute("aria-expanded", "false");
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' +
      '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.5" cy="6" r="1.2"/><circle cx="3.5" cy="12" r="1.2"/>' +
      '<circle cx="3.5" cy="18" r="1.2"/></svg>';
    btn.addEventListener("click", toggle);
    host.insertBefore(btn, host.firstChild);

    var wrap = document.createElement("div");
    wrap.id = "tasks-ui";
    wrap.innerHTML =
      '<div class="tasks-backdrop" id="tasks-backdrop" hidden></div>' +
      '<aside class="tasks-drawer" id="tasks-drawer" role="dialog" aria-modal="true" ' +
      'aria-labelledby="tasks-title" hidden>' +
      '<div class="tasks-head"><b id="tasks-title">任务中心</b>' +
      '<span class="hint" id="tasks-meta" style="margin:0"></span>' +
      '<button type="button" class="btn ghost small" id="tasks-refresh">刷新</button>' +
      '<button type="button" class="theme-btn" id="tasks-close" aria-label="关闭任务中心">✕</button></div>' +
      '<div class="tasks-body" id="tasks-body"></div>' +
      '<p class="tasks-foot hint">每 2.5 秒自动刷新；点任务上的「查看结果」跳到对应历史记录。</p>' +
      "</aside>";
    document.body.appendChild(wrap);

    var backdrop = document.getElementById("tasks-backdrop");
    var close = document.getElementById("tasks-close");
    var refresh = document.getElementById("tasks-refresh");
    if (backdrop) backdrop.addEventListener("click", closeDrawer);
    if (close) close.addEventListener("click", closeDrawer);
    if (refresh) refresh.addEventListener("click", function () { fetchTasks(true); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && state.open) { e.preventDefault(); closeDrawer(); }
    });
  }

  function drawerEls() {
    return {
      drawer: document.getElementById("tasks-drawer"),
      backdrop: document.getElementById("tasks-backdrop"),
      body: document.getElementById("tasks-body"),
      meta: document.getElementById("tasks-meta"),
      btn: document.getElementById("tasks-btn")
    };
  }

  function openDrawer() {
    var els = drawerEls();
    if (!els.drawer || !els.backdrop) return;
    state.open = true;
    els.backdrop.hidden = false;
    els.drawer.hidden = false;
    els.drawer.classList.add("open");
    if (els.btn) els.btn.setAttribute("aria-expanded", "true");
    fetchTasks(true);
    startPolling();
    var first = els.drawer.querySelector(".tasks-row a, .tasks-row button");
    if (first) { try { first.focus(); } catch (e) { /* ignore */ } }
  }

  function closeDrawer() {
    var els = drawerEls();
    state.open = false;
    stopPolling();
    if (els.drawer) {
      els.drawer.classList.remove("open");
      els.drawer.hidden = true;
    }
    if (els.backdrop) els.backdrop.hidden = true;
    if (els.btn) {
      els.btn.setAttribute("aria-expanded", "false");
      try { els.btn.focus(); } catch (e) { /* ignore */ }
    }
  }

  function toggle() {
    if (state.open) closeDrawer(); else openDrawer();
  }

  function startPolling() {
    stopPolling();
    state.timer = setInterval(function () {
      if (!state.open) { stopPolling(); return; }
      if (!state.available) return; // 接口不可用：不再空转
      fetchTasks(false);
    }, POLL_MS);
  }

  function stopPolling() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
  }

  function emptyHTML(text) {
    return '<div class="tasks-empty"><span class="big" aria-hidden="true">▤</span><p>' +
      ESC(text) + "</p></div>";
  }

  function render() {
    var els = drawerEls();
    if (!els.body) return;
    if (!state.available) {
      els.body.innerHTML = emptyHTML("任务中心接口未就绪（引擎版本不支持 /api/tasks），已静默降级。");
      if (els.meta) els.meta.textContent = "";
      return;
    }
    if (!state.tasks.length) {
      els.body.innerHTML = emptyHTML("暂无任务。扫描 / 批量 / 审计 / 爆破任务会出现在这里。");
    } else {
      els.body.innerHTML = state.tasks.map(rowHTML).join("");
    }
    if (els.meta) {
      els.meta.textContent = state.tasks.length + " 个任务 · " + relTime(new Date(state.lastAt).toISOString());
    }
  }

  function fetchTasks(force) {
    if (!state.available) {
      if (force) { state.available = true; } // 手动刷新给一次重试机会
    }
    if (state.inFlight) return;
    state.inFlight = true;
    var done = function () { state.inFlight = false; };
    var req;
    try {
      req = window.api.get("/api/tasks");
    } catch (e) {
      state.available = false;
      state.inFlight = false;
      render();
      return;
    }
    req.then(function (payload) {
      done();
      state.available = true;
      state.tasks = normalizeTasks(payload);
      state.lastAt = Date.now();
      render();
    }).catch(function () {
      done();
      // 静默降级：接口未接（旧引擎）/ 网络异常都不弹错，只停止轮询
      state.available = false;
      stopPolling();
      render();
    });
  }

  /* ---------------- 启动 ---------------- */

  function boot() {
    mount();
    // common.js 的壳渲染/i18n 可能在 DOMContentLoaded 后重渲染顶栏，补挂一次
    setTimeout(function () { mount(); }, EXTRA_WAIT_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.slTasks = {
    open: openDrawer,
    close: closeDrawer,
    toggle: toggle,
    refresh: function () { fetchTasks(true); },
    // 内部工具：供自测/排障（不参与 UI 逻辑）
    _internal: {
      normalizeTasks: normalizeTasks,
      statusMeta: statusMeta,
      progressPct: progressPct,
      scanIdOf: scanIdOf,
      relTime: relTime,
      rowHTML: rowHTML
    }
  };
})();
