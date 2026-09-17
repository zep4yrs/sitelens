/* 批量扫描：URL 列表 → /api/batch → 进度 + 日志流。工作台批量页签专用；ID 统一 batch- 前缀。 */
(function () {
  "use strict";
  var box = document.getElementById("batch-urls");
  if (!box) return;

  var LIMIT = 50;
  box.addEventListener("input", updateCount);

  // 上限随 batch.max_urls 配置（页面加载时拉取一次）
  try {
    api.get("/api/settings").then(function (c) {
      var m = c && c.batch && c.batch.max_urls;
      if (m > 0) { LIMIT = m; updateCount(); }
    });
  } catch (e) {}

  function updateCount() {
    var urls = box.value.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
    var n = document.getElementById("batch-n");
    if (n) n.textContent = urls.length + " / " + LIMIT + (urls.length > LIMIT ? "（超出部分将被忽略）" : "");
  }

  window.startBatch = function () {
    var urls = box.value.split("\n").map(function (s) { return s.trim(); }).filter(Boolean).slice(0, LIMIT);
    if (!urls.length) return;
    document.getElementById("batch-go").disabled = true;
    document.getElementById("batch-cancel").style.display = "";
    document.getElementById("batch-pw").style.display = "block";
    document.getElementById("batch-log").style.display = "block";
    var logBox = document.getElementById("batch-log");
    logBox.innerHTML = "";
    var seen = {};

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

    api.post("/api/batch", { urls: urls }).then(function (r) {
      var jobId = r.job_id;
      window.__batchJobId = jobId;
      // 25B-B1：任务队列表格
      var queueWrap = document.getElementById("batch-queue");
      var rowsEl = document.getElementById("batch-rows");
      if (queueWrap) queueWrap.style.display = "";
      var seenStatus = {};
      function renderRows(rows) {
        if (!rows || !rowsEl) return;
        rowsEl.innerHTML = rows.map(function (rw) {
          var st = rw.status || "queued";
          var cls = st === "done" ? "ok" : st === "failed" ? "danger" : st === "skipped" ? "muted" : "warn";
          var label = st === "done" ? "完成" : st === "failed" ? "失败" : st === "skipped" ? "跳过" : "扫描中";
          var elapsed = rw.elapsed_ms ? (rw.elapsed_ms / 1000).toFixed(1) + "s" : "—";
          var findings = st === "done" ? (rw.findings != null ? rw.findings : "—") : "—";
          return "<tr><td><span class=\"badge " + (st === "done" ? "ok" : st === "failed" ? "danger" : "warn") + "\">" + label + "</span></td>" +
            '<td class="mono" style="word-break:break-all">' + esc(rw.url) + "</td>" +
            "<td>" + findings + "</td><td>" + elapsed + "</td></tr>";
        }).join("");
      }
      return new Promise(function (resolve, reject) {
        // slPoll 句柄：必须用 handle.stop() 停止（clearInterval 对句柄无效）
        var handle = slPoll(function () {
          api.get("/api/job/" + jobId + "/results").then(function (job) {
            document.getElementById("batch-bar").style.width = (job.progress || 0) + "%";
            addLog(job.message);
            document.getElementById("batch-hint").textContent =
              (job.done || 0) + " / " + (job.total || urls.length) + " 已完成" +
              (job.status === "cancelling" ? "（取消中…）" : "");
            var rows = job.rows || (job.results && job.results.rows);
            if (rows) renderRows(rows);
            if (job.status === "done" || job.status === "cancelled") {
              handle.stop();
              resolve(job);
            }
          }).catch(function (e) { handle.stop(); reject(e); });
        }, 1200);
      });
    }).then(function (job) {
      document.getElementById("batch-go").disabled = false;
      document.getElementById("batch-cancel").style.display = "none";
      if (job.status === "cancelled") {
        document.getElementById("batch-hint").textContent = "批量已取消（未开始的 URL 已跳过）";
        toast("批量已取消", "err");
      } else {
        document.getElementById("batch-hint").innerHTML =
          '全部完成 · <a href="/history" style="color:var(--info)">→ 查看历史 / 导出宽表</a>';
        toast("批量扫描完成", "ok");
      }
    }).catch(function (e) {
      document.getElementById("batch-go").disabled = false;
      document.getElementById("batch-cancel").style.display = "none";
      document.getElementById("batch-hint").textContent = "失败：" + e.message;
    });
  };

  window.cancelBatch = function () {
    var btn = document.getElementById("batch-cancel");
    btn.disabled = true;
    btn.textContent = "取消中…";
    api.post("/api/job/" + window.__batchJobId + "/cancel", {}).catch(function () {});
  };
})();
