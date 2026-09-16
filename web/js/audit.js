/* 源码静态审计：拖拽上传 → /api/audit → 表格渲染。
   工作台模式与独立 /audit 页共用；ID 统一 audit- 前缀。 */
(function () {
  "use strict";
  var input = document.getElementById("audit-files");
  var dz = document.getElementById("audit-dz");
  if (!input || !dz) return;

  input.addEventListener("change", showNames);
  dz.addEventListener("click", function (e) {
    if (e.target === dz || e.target.className !== "dz-pick") input.click();
  });
  dz.querySelector(".dz-pick").addEventListener("click", function (e) {
    e.stopPropagation(); input.click();
  });
  ["dragover", "dragenter"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("drag"); });
  });
  dz.addEventListener("drop", function (e) {
    if (e.dataTransfer && e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      showNames();
    }
  });

  function showNames() {
    document.getElementById("audit-names").innerHTML = input.files.length
      ? [...input.files].map(function (f) {
          return esc(f.name) + " (" + (f.size / 1024).toFixed(1) + " KB)";
        }).join("<br>")
      : "";
  }

  window.runAudit = function () {
    var picked = input.files;
    if (!picked.length) { dz.classList.add("drag"); return; }
    var fd = new FormData();
    [...picked].forEach(function (f) { fd.append("files", f); });
    busy(true);
    fetch("/api/audit", { method: "POST", body: fd })
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
          return j;
        });
      })
      .then(function (r) { busy(false); render(r); })
      .catch(function (e) {
        busy(false);
        document.getElementById("audit-out").innerHTML =
          '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
      });
  };

  window.runDemo = function () {
    busy(true);
    api.get("/api/audit/demo")
      .then(function (r) { busy(false); render(r); })
      .catch(function (e) {
        busy(false);
        document.getElementById("audit-out").innerHTML =
          '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
      });
  };

  function busy(on) {
    document.getElementById("audit-go").disabled = on;
    if (on) {
      document.getElementById("audit-summary").style.display = "none";
      document.getElementById("audit-out").innerHTML =
        '<div class="skeleton" style="height:60px;margin-bottom:10px"></div>' +
        '<div class="skeleton" style="height:60px"></div><p class="hint">审计中…</p>';
    }
  }

  function render(r) {
    var sev = r.by_severity || {};
    var summary = document.getElementById("audit-summary");
    summary.style.display = "grid";
    summary.innerHTML =
      cell("扫描文件", r.files) + cell("代码行", (r.lines || 0).toLocaleString()) +
      cell("发现总数", (r.findings || []).length) +
      '<div class="cell"><span>高危</span><b><span class="badge danger">' + (sev.high || 0) + "</span></b></div>" +
      '<div class="cell"><span>中危</span><b><span class="badge warn">' + (sev.medium || 0) + "</span></b></div>" +
      '<div class="cell"><span>低危</span><b><span class="badge ok">' + (sev.low || 0) + "</span></b></div>";

    var findings = r.findings || [];
    if (!findings.length) {
      document.getElementById("audit-out").innerHTML =
        '<p class="muted" style="font-size:13.5px">未命中任何规则线索。</p>';
      return;
    }
    var html = '<div class="sec-title">审计发现 <span class="count">最多展示 120 条</span></div>' +
      '<div class="tbl-wrap"><table class="list"><tr><th>等级</th><th>规则</th><th>位置</th><th>说明 / 修复建议</th></tr>';
    findings.slice(0, 120).forEach(function (f) {
      html += "<tr><td>" + sevBadge(f.severity) + "</td>" +
        '<td class="mono">' + esc(f.rule) + '<br><span class="hint" style="margin:0">' + esc(f.title) + "</span></td>" +
        '<td class="mono" style="font-size:12px;word-break:break-all">' + esc(f.file) + ":" + esc(f.line) +
        '<br><span class="muted">' + esc(String(f.snippet || "").slice(0, 70)) + "</span></td>" +
        '<td style="font-size:12.5px">' + esc(f.advice) + "</td></tr>";
    });
    html += "</table></div>";
    if (findings.length > 120)
      html += '<p class="hint">… 其余 ' + (findings.length - 120) + " 条略</p>";
    document.getElementById("audit-out").innerHTML = html;
  }

  function cell(k, v) {
    return '<div class="cell"><span>' + esc(k) + '</span><b class="mono">' + esc(v) + "</b></div>";
  }
})();
