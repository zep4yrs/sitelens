/* ================= 页签路由（hash 持久化 + 侧栏高亮联动） ================= */
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(function (t) {
    t.classList.toggle("active", t.getAttribute("data-tab") === name);
  });
  document.querySelectorAll(".tabpanel").forEach(function (p) {
    p.classList.toggle("active", p.id === "tab-" + name);
  });
  // text-well 布局：左栏控制 + 右画布输出分离，画布面板随页签联动
  document.querySelectorAll(".tw-canvaspane").forEach(function (p) {
    p.classList.toggle("active", p.getAttribute("data-pane") === name);
  });
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
  if (window.slUpdateNav) window.slUpdateNav();
}
// Turbo：app.js 随换页重放，window 级监听先卸旧再挂新，防叠加
if (window.__slAppHash) window.removeEventListener("hashchange", window.__slAppHash);
window.__slAppHash = function () {
  var h = (location.hash || "#scan").slice(1);
  if (["scan", "netsec", "loginbrute", "audit", "batch"].indexOf(h) >= 0) switchTab(h);
};
window.addEventListener("hashchange", window.__slAppHash);
var initialTab = (location.hash || "#scan").slice(1);
if (["scan", "netsec", "loginbrute", "audit", "batch"].indexOf(initialTab) >= 0) switchTab(initialTab);

/* ================= 综合扫描 ================= */
var currentScanId = null;
var currentJobId = null;
/* 预设等级（quick/standard/deep/full）已由「范围 × 验证 × 强度」三维选择器
   合成取代；引擎 API 仍接受 level 参数与任意布尔组合（兼容脚本调用）。
   耗时预估与映射合成统一走 web/js/scan-options.js（含字典/端口旋钮）。 */
var STAGES = [
  [3, "校验目标（SSRF 防护）"], [12, "采集首页"], [30, "解析证据 / 同域爬取"],
  [50, "运行 7 个检测器"], [72, "验证引擎 + 安全响应头评分"], [78, "关联漏洞情报（三级判定）"],
  [80, "被动安全检测"], [84, "Nuclei 模板子集"], [85, "参数级 DAST"],
  [87, "目录探测"], [88, "WebShell 探测"]
];

var estimateSeconds = scanOpts.estimateSeconds;
function fmtT(sec) {
  sec = Math.max(0, Math.round(sec));
  return sec >= 60 ? Math.floor(sec / 60) + " 分 " + (sec % 60) + " 秒" : sec + " 秒";
}

/* 自定义下拉组件（等级 / 验证码） */
if (window.__slAppDocClick) document.removeEventListener("click", window.__slAppDocClick);
window.__slAppDocClick = function () {
  document.querySelectorAll(".cdd.open").forEach(function (r) { r.classList.remove("open"); });
};
document.addEventListener("click", window.__slAppDocClick);
var capDD = initCDD("lb-cap");

/* ---- 三维选择器：范围（多选）× 验证（多选，被动互斥）× 强度（单选）
   → 经 web/js/scan-options.js 纯函数合成引擎 payload（映射有单测固化）。
   语义：验证按动作拆分、勾谁跑谁；被动与其余互斥（零额外请求）；
   强度为真三档（验证引擎档位 + nuclei 上限 + 字典缩放 + 端口集）。 ---- */
var scopeSet = { web: true };
var verifySet = { afp: true, dir: true, ws: true, dast: true };
var stValue = "std";

function setVerify(key, on) {
  verifySet[key] = on;
  var chip = document.querySelector('#verify-row [data-verify="' + key + '"]');
  if (chip) chip.classList.toggle("on", on);
}
function setPassive(on) {
  verifySet.passive = on;
  var chip = document.querySelector('#verify-row [data-verify="passive"]');
  if (chip) chip.classList.toggle("on", on);
  // 互斥联动：被动开启时清空并禁用其余验证；关闭时恢复可选
  var row = document.getElementById("verify-row");
  if (on) {
    ["afp", "dir", "ws", "dast", "by", "ex", "settle"].forEach(function (k) {
      verifySet[k] = false;
      var c = document.querySelector('#verify-row [data-verify="' + k + '"]');
      if (c) c.classList.remove("on");
    });
  }
  var stGroup = document.getElementById("st-group");
  if (stGroup) stGroup.classList.toggle("disabled", on);
  setHint();
}
function setHint() {
  var h = document.getElementById("hint");
  if (!h) return;
  if (verifySet.passive) {
    h.textContent = "被动模式：零额外请求，仅响应头评分与被动特征；范围探测（子域 / 端口 / 协议）仍可运行。强度档位在此模式下不生效。";
    h.className = "hint warn";
  } else if (verifySet.ex) {
    h.textContent = "利用级验证会发送受控影响证明探针，需在 设置 → 引擎配置 开启「利用级验证」总闸；探针只读无害，gov.cn 永久拒绝。";
    h.className = "hint warn";
  } else if (verifySet.settle) {
    h.textContent = "事实图：随本次扫描收集入口 / 发现 / 证据 / CWE 关联 / 攻击链，可在「攻击链」页查看并导出 graph JSONL（供 5.0 读取）。";
    h.className = "hint";
  } else if (verifySet.by) {
    h.textContent = "403 绕过会发送变体重试请求，仅限自有或已书面授权的目标。";
    h.className = "hint warn";
  } else {
    h.textContent = "";
    h.className = "hint";
  }
}

(function wireSelector() {
  var scopeRow = document.getElementById("scope-row");
  scopeRow.addEventListener("click", function (e) {
    var el = e.target.closest(".chip");
    if (!el) return;
    el.classList.toggle("on");
    scopeSet[el.getAttribute("data-scope")] = el.classList.contains("on");
  });

  var verifyRow = document.getElementById("verify-row");
  verifyRow.addEventListener("click", function (e) {
    var el = e.target.closest(".chip");
    if (!el) return;
    var key = el.getAttribute("data-verify");
    if (key === "passive") {
      var turningOn = !verifySet.passive;
      setPassive(turningOn);
      return;
    }
    if (verifySet.passive) {
      // 主动验证在被动模式下点击：自动切回主动语义
      setPassive(false);
      toast("已切换到主动验证（被动已关闭）");
    }
    var on = !verifySet[key];
    setVerify(key, on);
    if (key === "ex" && on) setHint();
    else if ((key === "by" || key === "dir") && (verifySet.by || verifySet.dir)) setHint();
    else if (!verifySet.afp && !verifySet.dir && !verifySet.ws && !verifySet.dast && !verifySet.by && !verifySet.ex) {
      setHint();
    }
  });

  var stRow = document.getElementById("st-row");
  stRow.addEventListener("click", function (e) {
    var el = e.target.closest(".seg-opt");
    if (!el || verifySet.passive) return;
    stRow.querySelectorAll(".on").forEach(function (x) { x.classList.remove("on"); });
    el.classList.add("on");
    stValue = el.getAttribute("data-st");
  });
})();

function buildOptions() {
  var r = scanOpts.build({ scope: scopeSet, verify: verifySet, strength: stValue });
  if (!r.ok) {
    var h = document.getElementById("hint");
    if (h) { h.textContent = r.error; h.className = "hint warn"; }
    toast(r.error, "err");
    return null;
  }
  if (r.warnings && r.warnings.length) {
    var h2 = document.getElementById("hint");
    if (h2) { h2.textContent = r.warnings.join(" "); h2.className = "hint warn"; }
  } else {
    setHint();
  }
  return r.options;
}

/* 本机未装 ddddocr 时禁用需要 OCR 的验证码模式 */
api.get("/api/captcha/capability").then(function (c) {
  if (c.ocr) return;
  document.querySelectorAll("#lb-cap .cdd-opt").forEach(function (o) {
    if (o.dataset.v !== "none") {
      o.classList.add("disabled");
      o.disabled = true;
      var desc = o.querySelector("span");
      if (desc) desc.textContent += "（本机未装 ddddocr）";
    }
  });
  var hint = document.getElementById("lb-cap-hint");
  if (hint) hint.innerHTML =
    '<span style="color:var(--warn)">⚠ 本机未安装 ddddocr，验证码识别模式不可用（pip install ddddocr 后重启生效）。</span>';
}).catch(function () {});

var liveTimer = null, liveStart = 0, liveEst = 0;
function renderLivePanel(options) {
  liveEst = estimateSeconds(options);
  liveStart = Date.now();
  var rows = STAGES.map(function (st, i) {
    return '<div class="stage" id="stage-' + i + '"><span class="s-ico">○</span> ' + st[1] + "</div>";
  }).join("");
  document.getElementById("result").innerHTML =
    '<div class="livebox card"><div class="lv-head">扫描进行中' +
    '<button class="btn ghost small" id="cancel-btn" onclick="cancelScan()">取消扫描</button></div>' + rows +
    '<div class="lv-feed" id="lv-feed"></div>' +
    '<div class="lv-meta">已用时 <b id="lv-elapsed">0 秒</b> · 预计剩余 <b id="lv-eta">' +
    fmtT(liveEst) + "</b></div></div>";
  liveTimer = setInterval(function () {
    var el = (Date.now() - liveStart) / 1000;
    var eta = document.getElementById("lv-eta");
    var el2 = document.getElementById("lv-elapsed");
    if (!eta) { clearInterval(liveTimer); return; }
    el2.textContent = fmtT(el);
    eta.textContent = fmtT(Math.max(liveEst - el, 3));
  }, 1000);
}
function markStage(p) {
  STAGES.forEach(function (st, i) {
    var el = document.getElementById("stage-" + i);
    if (el && p > st[0]) { el.querySelector(".s-ico").textContent = "✓"; el.classList.add("done"); }
  });
}
function setProgress(p, msg, job) {
  document.getElementById("bar").style.width = p + "%";
  document.getElementById("st-state").textContent = "scanning";
  document.getElementById("st-msg").textContent = msg || "";
  markStage(p);

  /* 实时动态：引擎事件流（阶段/命中/绕过/认证）尾部 8 条，命中计数高亮 */
  var feedEl = document.getElementById("lv-feed");
  if (!feedEl || !job) return;
  var evs = job.events || [];
  if (!evs.length) { feedEl.innerHTML = ""; return; }
  var hits = 0, bypass = 0;
  var rows = evs.slice(-8).reverse().map(function (ev) {
    var color = "#94a3b8";
    if (ev.kind === "hit") { hits++; color = "#f87171"; }
    else if (ev.kind === "bypass") { bypass++; color = "#fbbf24"; }
    else if (ev.kind === "auth") { color = "#5eead4"; }
    return '<div style="display:flex;gap:6px;align-items:baseline;padding:2px 0">' +
      '<span style="color:' + color + ';flex:1;word-break:break-all">' +
      esc(ev.text) + "</span></div>";
  }).join("");
  var head = '实时动态';
  if (hits || bypass) {
    head += ' · <span style="color:#f87171">命中 ' + hits + "</span>" +
      (bypass ? ' · <span style="color:#fbbf24">绕过 ' + bypass + "</span>" : "");
  }
  feedEl.innerHTML = '<div class="hint" style="margin-bottom:4px">' + head + "</div>" + rows;
}

function startScan() {
  var url = document.getElementById("url").value.trim();
  if (!url) { document.getElementById("url").focus(); return; }
  var options = buildOptions();
  if (!options) return; // 范围校验失败（如全不选），buildOptions 已给出提示
  var ck = document.getElementById("opt-cookie").value.trim();
  if (ck) options.auth_cookie = ck;
  if (document.getElementById("opt-ua").checked) options.browser_ua = true;

  document.getElementById("idle-wrap").style.display = "none";
  document.getElementById("pw").style.display = "block";
  document.getElementById("go").disabled = true;
  renderLivePanel(options);
  setProgress(3, "提交任务…");

  /* 后端 /api/scan 从 body 顶层读取各选项（data.get("deep") 等），必须平铺不能嵌套 */
  var payload = Object.assign({ url: url }, options);
  api.post("/api/scan", payload)
    .then(function (r) {
      currentJobId = r.job_id;
      return pollJob(r.job_id, setProgress);
    })
    .then(function (job) {
      document.getElementById("go").disabled = false;
      if (liveTimer) clearInterval(liveTimer);
      if (job.cancelled) {
        document.getElementById("st-state").textContent = "cancelled";
        document.getElementById("st-msg").textContent = "已取消";
        document.getElementById("result").innerHTML =
          '<div class="empty"><span class="big">⊘</span>扫描已取消（局部结果未入库）</div>';
        return null;
      }
      document.getElementById("st-state").textContent = "done";
      document.getElementById("st-msg").textContent = "完成";
      toast("扫描完成", "ok");
      currentScanId = job.scan_id;
      return api.get("/api/history/" + job.scan_id);
    })
    .then(function (row) { if (row) renderResult(row.result, row.id); })
    .catch(function (e) {
      document.getElementById("go").disabled = false;
      if (liveTimer) clearInterval(liveTimer);
      document.getElementById("st-state").textContent = "error";
      document.getElementById("st-msg").textContent = e.message;
      document.getElementById("result").innerHTML =
        '<div class="empty"><span class="big">✕</span>' + esc(e.message) + "</div>";
    });
}

function pollJob(jobId, onProgress) {
  return new Promise(function (resolve, reject) {
    var timer = slPoll(function () {
      api.get("/api/job/" + jobId).then(function (job) {
        if (job.status === "done") { clearInterval(timer); resolve(job); }
        else if (job.status === "cancelled") {
          clearInterval(timer); resolve({ cancelled: true, message: job.message });
        }
        else if (job.status === "error") { clearInterval(timer); reject(new Error(job.message || "任务失败")); }
        else if (onProgress) onProgress(job.progress || 0, job.message, job);
      }).catch(function (e) { clearInterval(timer); reject(e); });
    }, 1000);
  });
}

function cancelScan() {
  if (!currentJobId) return;
  var btn = document.getElementById("cancel-btn");
  if (btn) { btn.disabled = true; btn.textContent = "取消中…"; }
  document.getElementById("st-msg").textContent = "取消中…";
  api.post("/api/job/" + currentJobId + "/cancel", {}).catch(function () {});
}

/* ---------------- 结果渲染 ---------------- */
var CAT_NAMES = {};
api.get("/api/categories").then(function (r) {
  r.categories.forEach(function (c) { CAT_NAMES[c.id] = c.name; });
}).catch(function () {});

function renderResult(r, scanId) {
  var html = "";

  /* 证据链复现/复制的注册表：键为渲染期序号，值为核心文本 */
  window._EV = window._EV || {};
  var evSeq = 0;
  function regEv(t) { var k = "e" + (++evSeq); window._EV[k] = t || ""; return k; }
  window.copyEvd = function (k) {
    var t = (window._EV || {})[k] || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t);
    } else {
      var ta = document.createElement("textarea");
      ta.value = t; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
    }
  };
  function replayDetails(text) {
    if (!text) return "";
    var k = regEv(text);
    return '<details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">curl 复现命令 <button class="btn ghost small" onclick="event.preventDefault();copyEvd(\'' + k + '\')">复制</button></summary>' +
      '<pre class="mono" style="white-space:pre-wrap;font-size:11.5px;margin:4px 0 0">' + esc(text) + "</pre></details>";
  }
  function evdPane(v) {
    var p = "";
    if (v.replay) {
      p += '<div style="margin-top:6px"><b style="font-size:12px">复现命令</b>' +
        '<pre class="mono" style="white-space:pre-wrap;font-size:11.5px;margin:4px 0 0">' + esc(v.replay) + "</pre>" +
        '<button class="btn ghost small" onclick="copyEvd(\'' + regEv(v.replay) + '\')">复制命令</button></div>';
    }
    if (v.request) {
      p += '<div style="margin-top:6px"><b style="font-size:12px">请求</b>' +
        '<pre class="mono" style="white-space:pre-wrap;font-size:11.5px;margin:4px 0 0">' + esc(v.request) + "</pre></div>";
    }
    if (v.response) {
      p += '<div style="margin-top:6px"><b style="font-size:12px">响应</b>' +
        '<span class="hint"> HTTP ' + esc(String(v.response.status)) + " · " + esc(String(v.response.size)) + "B</span>" +
        '<pre class="mono" style="white-space:pre-wrap;font-size:11.5px;margin:4px 0 0">' + esc(v.response.snippet || "") + "</pre></div>";
    }
    if ((v.signals || []).length) {
      p += '<div style="margin-top:6px"><b style="font-size:12px">信号</b>' +
        '<span class="hint"> ' + esc(v.signals.join(" · ")) + "</span></div>";
    }
    return p;
  }

  /* 采集失败 / 被 WAF 拦截时给出明确原因与建议（引擎 error 字段） */
  if (r.error) {
    var is403 = String(r.error).indexOf("403") >= 0;
    html += '<div class="card" style="border-color:color-mix(in srgb,var(--warn) 50%,transparent);margin-bottom:16px">' +
      '<b style="color:var(--warn)">⚠ ' + esc(r.error) + '</b>' +
      (is403 ? '<span class="hint" style="display:block;margin-top:4px">目标可能按 UA / WAF 拦截了扫描器（本工具默认自报 SiteLens/2.0）。' +
        '可勾选上方「浏览器 UA」后重新扫描。</span>' : '') +
      "</div>";
  }

  /* 风险摘要卡：机器先做第一层判断，把最值得关注的发现推到最前（评审#8） */
  var verAll = r.verified || [];
  var sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var ranked = verAll.slice().sort(function (a, b) {
    var ra = sevRank[a.severity] != null ? sevRank[a.severity] : 9;
    var rb = sevRank[b.severity] != null ? sevRank[b.severity] : 9;
    var d = ra - rb;
    if (d) return d;
    if (!!b.confirmed !== !!a.confirmed) return b.confirmed ? 1 : -1;
    return (b.request ? 1 : 0) - (a.request ? 1 : 0);
  });
  var top = ranked.slice(0, 3);
  if (top.length) {
    html += '<div class="sec-title">最值得关注 <span class="count">' + top.length + "</span>" +
      '<span class="hint" style="margin-left:8px">按严重度与证据强度排序 · 完整明细见下方与导出</span></div>';
    top.forEach(function (v) {
      var evN = 1 + (v.request ? 1 : 0) + (v.response ? 1 : 0) + ((v.signals || []).length ? 1 : 0) + (v.confirmed ? 1 : 0);
      html += '<div class="card" style="margin-bottom:10px">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
        "<b>" + esc(v.title || v.check || "") + "</b>" +
        sevBadge(v.severity) +
        '<span class="hint">证据 ' + evN + "/5 · " + (v.confirmed ? "二次确认通过" : "单轮命中") + "</span></div>" +
        '<div class="mono" style="word-break:break-all;font-size:12.5px;margin-top:6px">' + esc(v.url || "") + "</div>" +
        replayDetails(v.replay || "") +
        "</div>";
    });
    if (ranked.length > 3) {
      html += '<p class="hint" style="margin:4px 0 12px">其余 ' + (ranked.length - 3) + " 条见下方「已验证发现」与导出文件。</p>";
    }
  }

  var sec = r.security || {};
  var grade = sec.grade || "-";
  var gradeCls = (grade === "F" || grade === "D") ? "danger" : (grade === "C" ? "warn" : "ok");
  html += '<div class="summary">' +
    cell("Host", r.host) + cell("标题", r.title || "-") +
    cell("IP", r.ip || "-") + cell("响应", (r.response_time_ms || 0) + " ms") +
    cell("耗时", (r.duration || 0) + " s") +
    '<div class="cell"><span>安全响应头</span><b><span class="badge ' + gradeCls + '">' +
    esc(grade) + " " + (sec.score || 0) + "分</span></b></div></div>";

  var techs = r.technologies || [];
  html += '<div class="sec-title">指纹识别 <span class="count">' + techs.length + " 项</span>" +
    '<span class="right">' + exportButtons() + "</span></div>";
  if (techs.length) {
    var groups = {};
    techs.forEach(function (t) {
      (t.categories && t.categories.length ? t.categories : ["misc"]).forEach(function (c) {
        (groups[c] = groups[c] || []).push(t);
      });
    });
    Object.keys(groups).forEach(function (cat) {
      html += '<div class="tech-group"><div class="gname">' + esc(CAT_NAMES[cat] || cat) + "</div>" +
        '<div class="tech-list">' + groups[cat].map(function (t) {
          var ver = t.version ? '<span class="ver">v' + esc(t.version) + "</span>" : "";
          var ev = (t.evidence && t.evidence.length)
            ? '<span class="ev" title="' + esc(t.evidence.join("\n")) + '">ⓘ</span>' : "";
          var conf = '<span class="conf"><i style="width:' + (t.confidence || 0) + '%"></i></span>';
          return '<span class="badge">' + esc(t.name) + " " + ver + conf + ev + "</span>";
        }).join("") + "</div></div>";
    });
  } else {
    html += '<p class="muted" style="font-size:13px">未识别到技术组件。</p>';
  }

  var ver = r.verified || [];
  html += '<div class="sec-title">已验证漏洞 <span class="count">' + ver.length +
    " 条（探测请求实际命中）</span></div>";
  if (ver.length) {
    html += '<div class="tbl-wrap"><table class="vulns"><tr><th>严重度</th><th>检测项</th><th>命中地址</th><th>修复建议</th></tr>';
    ver.forEach(function (v) {
      var pane = evdPane(v);
      var block = pane ? '<details style="margin-top:4px"><summary style="cursor:pointer;font-size:12px">证据链</summary>' + pane + "</details>" : "";
      var imp = "";
      if (v.impact === "proven") imp = ' <span class="badge danger">影响已证明</span>';
      else if (v.impact === "observed") imp = ' <span class="badge warn">可利用面观测</span>';
      var impEv = v.impact_evidence ? '<div style="font-size:12px;color:var(--muted-fg)">利用级：' + esc(v.impact_evidence) + "</div>" : "";
      html += "<tr><td>" + sevBadge(v.severity) + "</td>" +
        '<td class="mono">' + esc(v.check) + " " + esc(v.title) + imp + "</td>" +
        '<td class="mono" style="font-size:12px;word-break:break-all">' + esc(v.url) +
        "（" + esc(v.evidence) + "）" + impEv + block + "</td><td>" + esc(v.advice) + "</td></tr>";
    });
    html += "</table></div>";
  } else {
    html += '<p class="muted" style="font-size:13px">无（本轮等级未运行验证检测或未命中）。</p>';
  }

  var vulns = r.vulnerabilities || [];
  html += '<div class="sec-title">漏洞情报关联 <span class="count">' + vulns.length +
    " 条（按组件关联的历史漏洞，非漏洞验证）</span></div>";
  if (vulns.length) {
    html += '<div class="tbl-wrap"><table class="vulns"><tr><th>严重度</th><th>判定</th><th>涉及技术</th><th>漏洞</th><th>类型</th><th>来源</th></tr>';
    vulns.slice(0, 40).forEach(function (v) {
      var name = esc(v.name || v.title || v.cve || "");
      if (v.ref) name = safeLink(v.ref, v.name || v.title || v.cve || "");
      var lv = "";
      if (v.verdict === "confirmed") lv = '<span class="badge danger">确认受影响</span>';
      else if (v.verdict === "possible") lv = '<span class="badge warn">可能受影响</span>';
      else if (v.verdict === "excluded") lv = '<span class="badge ok">不受影响</span>';
      html += "<tr><td>" + sevBadge(v.severity, v.severity_zh) + "</td><td>" + lv + "</td>" +
        '<td class="mono">' + esc(v.tech) + "</td>" +
        "<td>" + (v.cve ? '<span class="mono">' + esc(v.cve) + "</span> " : "") + name +
        (v.templates && v.templates.length ? '<div style="font-size:12px;color:var(--muted-fg)">可跑模板：' +
          esc(v.templates.slice(0, 3).join(" · ")) + (v.templates.length > 3 ? " 等 " + v.templates.length + " 条" : "") + "</div>" : "") +
        "</td>" +
        "<td>" + esc(v.type || "-") + '</td><td class="mono">' + esc(v.src) + "</td></tr>";
    });
    html += "</table></div>";
    if (vulns.length > 40)
      html += '<p class="hint">… 其余 ' + (vulns.length - 40) + " 条见导出文件</p>";
  } else {
    html += '<p class="muted" style="font-size:13px">未命中已知漏洞情报。</p>';
  }

  var ex = r.extras || {};
  var titles = { active_fp: "主动路径指纹", dir_scan: "目录探测", subdomain: "子域名",
                 service: "端口服务", netsec: "TLS / DNS 安全", weak_audit: "登录爆破结果",
                 webshell: "WebShell 路径探测", jsmap: "JS 攻击面", dast: "DAST 检测",
                 passive: "被动安全检测", bypass: "403 绕过探测", dir: "目录探测",
                 netproto: "协议模板检测（tcp/dns/ssl）", exploit: "利用级无害验证" };
  Object.keys(ex).forEach(function (key) {
    var items = ex[key] || [];
    var cnt = Array.isArray(items) ? items.length : null;
    html += '<div class="sec-title">' + esc(titles[key] || key) +
      (cnt !== null ? ' <span class="count">' + cnt + "</span>" : "") + "</div>";
    if (key === "exploit") {
      // 汇总对象：{proven, observed, gate}
      html += '<div class="extras-box mono">proven ' + esc(String(items.proven || 0)) +
        " · observed " + esc(String(items.observed || 0)) + " · 闸门 " + esc(String(items.gate || "-")) + "</div>";
      return;
    }
    if (!items.length) { html += '<p class="muted" style="font-size:13px">未发现。</p>'; return; }
    html += '<div class="extras-box mono">';
    items.forEach(function (it) { html += extrasLine(key, it) + "<br>"; });
    html += "</div>";
  });

  document.getElementById("result").innerHTML = html;
  if (scanId) document.getElementById("st-time").textContent = "记录 #" + scanId;
}

function cell(label, value) {
  return '<div class="cell"><span>' + esc(label) + "</span><b>" + esc(value) + "</b></div>";
}
function exportButtons() {
  return '<button class="btn ghost small" onclick="exportAs(\'json\')">JSON</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'csv\')">明细 CSV</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'wide\')">宽表 CSV</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'html\')">HTML 报告</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'md\')">MD 报告</button>';
}
window.exportAs = function (fmt) {
  if (currentScanId) location.href = "/api/export/" + currentScanId + "?fmt=" + fmt;
};

/* ?url= 自动开扫（首页搜索框跳转入口） */
(function () {
  var q = new URLSearchParams(location.search).get("url");
  if (q) {
    document.getElementById("url").value = q;
    startScan();
  }
})();

/* ================= 网络层检测 ================= */
function runNetsec() {
  var host = document.getElementById("ns-host").value.trim();
  if (!host) return;
  document.getElementById("ns-go").disabled = true;
  document.getElementById("ns-out").innerHTML =
    '<div class="skeleton" style="height:60px"></div><p class="hint">检测中…（TLS 握手 + DNS 查询）</p>';
  api.post("/api/netsec", { host: host }).then(function (r) {
    document.getElementById("ns-go").disabled = false;
    var hits = r.findings || [];
    if (!hits.length) {
      document.getElementById("ns-out").innerHTML =
        '<p style="color:var(--ok);font-size:14px">✔ ' + esc(r.host) + " 未发现网络层安全问题</p>";
      return;
    }
    var html = '<div class="tbl-wrap"><table class="list"><tr><th>严重度</th><th>检测项</th><th>证据</th><th>修复建议</th></tr>';
    hits.forEach(function (h) {
      html += "<tr><td>" + sevBadge(h.severity) + "</td>" +
        '<td class="mono">' + esc(h.check) + '<br><span class="hint" style="margin:0">' + esc(h.title) + "</span></td>" +
        '<td class="mono" style="font-size:12px;word-break:break-all">' + esc(h.url) +
        (h.evidence ? "<br>" + esc(h.evidence) : "") + "</td>" +
        "<td>" + esc(h.advice) + "</td></tr>";
    });
    document.getElementById("ns-out").innerHTML = html + "</table></div>";
  }).catch(function (e) {
    document.getElementById("ns-go").disabled = false;
    document.getElementById("ns-out").innerHTML =
      '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
  });
}
document.getElementById("ns-host").addEventListener("keydown", function (e) {
  if (e.key === "Enter") runNetsec();
});

/* ================= 登录爆破 ================= */
var lbAuth = document.getElementById("lb-authed");
var lbGo = document.getElementById("lb-go");
lbAuth.addEventListener("change", function () {
  lbGo.disabled = !this.checked;
  document.getElementById("lb-st").textContent = this.checked ? "" : "需要勾选授权确认";
});

var lbFrame = document.getElementById("lb-preview");
function togglePreview() {
  var url = document.getElementById("lb-url").value.trim();
  if (!url) return;
  if (lbFrame.style.display !== "block") {
    lbFrame.src = url;
    lbFrame.style.display = "block";
    document.getElementById("lb-pv-btn").textContent = "隐藏预览";
  } else {
    lbFrame.style.display = "none";
    document.getElementById("lb-pv-btn").textContent = "显示登录页预览";
  }
}

function runBrute() {
  var url = document.getElementById("lb-url").value.trim();
  if (!url) return;
  lbGo.disabled = true;
  lbFrame.style.display = "none";
  document.getElementById("lb-pw").style.display = "block";
  document.getElementById("lb-out").innerHTML = "";
  api.post("/api/loginbrute", {
    url: url,
    authorized: true,
    captcha_type: capDD.value,
    captcha_field: document.getElementById("lb-cap-field").value.trim() || "captcha"
  }).then(function (r) {
    return pollJob(r.job_id, function (p, msg) {
      document.getElementById("lb-bar").style.width = p + "%";
      document.getElementById("lb-st").textContent = msg || "";
    });
  }).then(function (job) {
    lbGo.disabled = !lbAuth.checked;
    lbFrame.style.display = "none";
    var hits = (job.result && job.result.hits) || [];
    if (!hits.length) {
      document.getElementById("lb-out").innerHTML =
        '<p style="color:var(--ok);font-size:14px">✔ 未命中弱口令（字典内无匹配）</p>';
      return;
    }
    var html = '<p style="color:var(--danger);font-size:14px">⚠ 命中 ' + hits.length + " 组弱口令：</p>" +
      '<div class="tbl-wrap"><table class="list"><tr><th>用户名</th><th>密码</th><th>提交地址</th></tr>';
    hits.forEach(function (h) {
      html += '<tr><td class="mono">' + esc(h.user) + '</td><td class="mono">' + esc(h.password) +
        '</td><td class="mono" style="font-size:12px;word-break:break-all">' + esc(h.url) + "</td></tr>";
    });
    document.getElementById("lb-out").innerHTML = html + "</table></div>";
  }).catch(function (e) {
    lbGo.disabled = !lbAuth.checked;
    document.getElementById("lb-out").innerHTML =
      '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
  });
}

/* ================= text-well 布局：左右分割条拖拽 ================= */
(function () {
  var split = document.getElementById("tw-split");
  var left = document.getElementById("tw-left");
  if (!split || !left) return;
  var st = window.__slSplitState || (window.__slSplitState = { on: false, x: 0, w: 0 });
  try {
    var saved = parseInt(localStorage.getItem("tw-left-w") || "", 10);
    if (saved >= 240 && saved <= 520) left.style.width = saved + "px";
  } catch (e) {}
  split.addEventListener("mousedown", function (e) {
    st.on = true; st.x = e.clientX; st.w = left.getBoundingClientRect().width;
    split.classList.add("on");
    document.body.style.cursor = "col-resize";
    e.preventDefault();
  });
  if (window.__slSplitMove) document.removeEventListener("mousemove", window.__slSplitMove);
  window.__slSplitMove = function (e) {
    if (!st.on) return;
    left.style.width = Math.min(520, Math.max(240, st.w + e.clientX - st.x)) + "px";
  };
  document.addEventListener("mousemove", window.__slSplitMove);
  if (window.__slSplitUp) document.removeEventListener("mouseup", window.__slSplitUp);
  window.__slSplitUp = function () {
    if (!st.on) return;
    st.on = false;
    split.classList.remove("on");
    document.body.style.cursor = "";
    try { localStorage.setItem("tw-left-w", String(left.getBoundingClientRect().width)); } catch (e) {}
  };
  document.addEventListener("mouseup", window.__slSplitUp);
})();
