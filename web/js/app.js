/* ================= 页签路由（hash 持久化 + 侧栏高亮联动） ================= */
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(function (t) {
    var on = t.getAttribute("data-tab") === name;
    t.classList.toggle("active", on);
    if (on) t.setAttribute("aria-current", "true"); else t.removeAttribute("aria-current");
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
/* FE-12 零丢失：最近一次提交 /api/scan 的完整参数（url + 三维选项），
   「继续扫描」按原参数重提，不要求用户重选一遍。 */
var lastScanPayload = null;
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
    ["afp", "dir", "ws", "dast", "by", "ex"].forEach(function (k) {
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

/* G09/G10 高级 Web 检测：与「范围/验证」同款多选下拉（chips），默认全关。
   提交为 options.dast 对象；chips 变更同时同步扫描中提示。 */
var advSet = { idor: false, logic: false, upload: false, deser: false, proto: false };
(function wireAdv() {
  var row = document.getElementById("adv-row");
  if (!row) return;
  row.addEventListener("click", function (e) {
    var el = e.target.closest(".chip");
    if (!el) return;
    el.classList.toggle("on");
    advSet[el.getAttribute("data-adv")] = el.classList.contains("on");
    updateAdvNote();
  });
})();

function buildOptions() {
  var r = scanOpts.build({
    scope: scopeSet, verify: verifySet, strength: stValue, advanced: advSet
  });
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

/* ---- G09/G10 高级检测：扫描中提示 / 计划-发现结果卡 ---- */

/* 扫描中提示：进度条下方一行说明（左栏开关变化时同步）。 */
function updateAdvNote() {
  var el = document.getElementById("adv-note");
  if (!el) return;
  var on = scanOpts.ADV_KEYS.filter(function (k) { return advSet[k]; });
  if (!on.length) { hideAdvNote(); return; }
  el.hidden = false;
  el.textContent = "高级 Web 检测已启用：" +
    on.map(function (k) { return scanOpts.ADV_LABELS[k]; }).join(" / ");
}

function hideAdvNote() {
  var el = document.getElementById("adv-note");
  if (el) { el.hidden = true; el.textContent = ""; }
}

/* 按实际下发参数显示提示（「继续扫描」复用旧 payload 时也准确）。 */
function setAdvNoteFromOptions(options) {
  var labels = scanOpts.advancedLabels ? scanOpts.advancedLabels(options) : [];
  var el = document.getElementById("adv-note");
  if (!el) return;
  if (!labels.length) { hideAdvNote(); return; }
  el.hidden = false;
  el.textContent = "高级 Web 检测已启用：" + labels.join(" / ");
}

var ADV_MODULE_LABELS = {
  idor: "越权矩阵", logic: "业务逻辑", upload: "上传绕过",
  deser: "反序列化", proto: "WS/HTTP2"
};

function advPlanText(p) {
  if (p == null) return "";
  if (typeof p === "string") return p;
  if (typeof p === "object") {
    return String(p.title || p.check || p.name || p.desc || p.url || "");
  }
  return String(p);
}

function advFindingHTML(f) {
  var sev = String((f && (f.severity || f.level)) || "").toLowerCase();
  var cls = (sev === "high" || sev === "critical") ? "danger" : (sev === "medium" ? "warn" : "info");
  var check = String((f && (f.check || f.id || f.name)) || "检测项");
  var title = String((f && (f.title || f.desc || "")) || "");
  var url = String((f && (f.url || f.target || f.path)) || "");
  var ev = String((f && (f.evidence || f.detail || f.summary)) || "");
  return '<li class="adv-find"><span class="badge ' + cls + '">' + esc(sev || "info") + "</span> " +
    '<b class="mono">' + esc(check) + "</b>" + (title ? " " + esc(title) : "") +
    (url ? '<div class="adv-find-sub mono">' + esc(url) + "</div>" : "") +
    (ev ? '<div class="adv-find-sub">' + esc(ev) + "</div>" : "") + "</li>";
}

/* 结果卡：读取 result.extras.web_advanced（契约见引擎 G09/G10 接线）。
   兼容三种形态：{plan,findings} / {idor:{plan,findings},...} / 发现数组；
   缺字段/空对象 → 返回 ""（结果页不占位）。 */
function advancedCard(r) {
  var wa = r && r.extras && r.extras.web_advanced;
  if (!wa) return "";
  var modules = [];
  var plan = [];
  var findings = [];
  if (Array.isArray(wa)) {
    wa.forEach(function (x) {
      if (x && typeof x === "object") findings.push(x);
      else if (x) plan.push(advPlanText(x));
    });
  } else if (typeof wa === "object") {
    var topDry = wa.dry_run === true || wa.dryRun === true;
    Object.keys(wa).forEach(function (k) {
      var v = wa[k];
      if (k === "dry_run" || k === "dryRun" || k === "enabled" || v == null) return;
      if (k === "plan" && Array.isArray(v)) {
        plan = plan.concat(v.map(advPlanText).filter(Boolean));
        return;
      }
      if (k === "findings" && Array.isArray(v)) { findings = findings.concat(v); return; }
      if (typeof v === "object") {
        modules.push({
          key: k,
          label: ADV_MODULE_LABELS[k] || String(v.name || v.label || k),
          dryRun: v.dry_run === true || v.dryRun === true || topDry,
          plan: Array.isArray(v.plan) ? v.plan.map(advPlanText).filter(Boolean) : [],
          findings: Array.isArray(v.findings) ? v.findings : []
        });
      }
    });
  }
  if (!modules.length && plan.length === 0 && findings.length === 0) return "";

  var modHTML = "";
  modules.forEach(function (m) {
    findings = findings.concat(m.findings);
    modHTML += '<div class="adv-mod"><span class="badge">' + esc(m.label) + "</span>" +
      (m.dryRun ? ' <span class="badge ok">dry-run</span>' : "") +
      '<span class="hint" style="margin:0">计划 ' + m.plan.length + " 项 · 发现 " + m.findings.length + " 项</span>" +
      (m.plan.length
        ? '<ul class="adv-plan">' + m.plan.slice(0, 6).map(function (p) {
            return "<li>" + esc(p) + "</li>";
          }).join("") + "</ul>"
        : "") +
      "</div>";
  });

  var html = '<div class="adv-card card"><div class="adv-head"><b>高级 Web 检测</b>' +
    '<span class="badge ok">默认 dry-run</span></div>';
  if (modHTML) {
    html += '<div class="adv-mods">' + modHTML + "</div>";
  } else if (plan.length) {
    html += '<ul class="adv-plan">' + plan.slice(0, 8).map(function (p) {
      return "<li>" + esc(p) + "</li>";
    }).join("") + "</ul>";
  }
  if (findings.length) {
    html += '<div class="adv-finds"><b>发现 ' + findings.length + " 项</b><ul>" +
      findings.slice(0, 20).map(advFindingHTML).join("") + "</ul>" +
      (findings.length > 20
        ? '<p class="hint">… 其余 ' + (findings.length - 20) + " 条见导出文件</p>"
        : "") + "</div>";
  } else {
    html += '<p class="hint">本次未发现高级检测问题（dry-run 计划已记录在结果 extras）。</p>';
  }
  return html + "</div>";
}

/* ---- 扫描前反馈：目标预检 + 扫描计划（不发任何请求，纯本地计算） ---- */
function updatePlan() {
  var el = document.getElementById("plan");
  if (!el) return;
  var input = document.getElementById("url");
  var raw = input ? input.value : "";
  /* 空输入：不占版面、不报错（保持原交互：点开始会聚焦输入框） */
  if (!String(raw || "").trim()) {
    clearPreflight();
    el.hidden = true;
    el.innerHTML = "";
    var goEmpty = document.getElementById("go");
    if (goEmpty) { goEmpty.disabled = false; goEmpty.title = ""; }
    return;
  }
  var v = window.slLive ? window.slLive.validateTarget(raw) : { ok: !!raw, warnings: [] };
  var b = null;
  try {
    b = scanOpts.build({ scope: scopeSet, verify: verifySet, strength: stValue, advanced: advSet });
  } catch (e) { b = null; }
  var opts = (b && b.ok) ? b.options : null;
  var items = [];
  if (opts) {
    items.push(opts.deep ? "同域浅爬取" : "仅入口页");
    var advLabels = scanOpts.advancedLabels ? scanOpts.advancedLabels(opts) : [];
    if (advLabels.length) items.push("高级 Web 检测（" + advLabels.join("/") + "）");
    else if (opts.dast) items.push("参数级 DAST");
    if (opts.passive) items.push("被动检测（零额外请求）");
    if (opts.dir_scan) items.push("目录探测");
    if (opts.subdomain) items.push("子域枚举");
    if (opts.service_probe) items.push("端口识别");
    if (opts.checks === "core") items.push("模板检测 core");
    if (opts.checks === "all") items.push("模板检测 all");
    if (opts.exploit) items.push("利用级验证");
    if (opts.js_map) items.push("JS 攻击面");
    items.push("请求量级 " + (window.slLive ? window.slLive.requestBucket(opts) : "-"));
  }
  var html = "";
  if (!v.ok) {
    clearPreflight();
    html += '<div class="plan-warn">' + esc(v.error) + "</div>";
  } else {
    html += '<div class="plan-head"><b>扫描计划</b><span class="hint mono">' + esc(v.normalized || raw) + "</span></div>";
    if (items.length) {
      html += '<div class="plan-items">' + items.map(function (x) {
        return '<span class="plan-item">' + esc(x) + "</span>";
      }).join("") + "</div>";
    }
    if (opts) html += '<div class="plan-eta">预计耗时 <b>' + fmtT(estimateSeconds(opts)) +
      "</b> · 经验值，随站点规模浮动</div>";
  }
  var warns = (v.warnings || []).concat((b && b.warnings) || []);
  if (opts && opts.dast && opts.checks === "all") warns.push("DAST + 全量模板：请求量较大，确认目标可承受");
  warns.forEach(function (w) { html += '<div class="plan-warn">' + esc(w) + "</div>"; });
  el.innerHTML = html;
  el.hidden = !html;
  var go = document.getElementById("go");
  if (go) { go.disabled = !v.ok; go.title = v.ok ? "" : v.error; }
}
function wirePlan() {
  var input = document.getElementById("url");
  if (input && !input.__slPlanWired) {
    input.__slPlanWired = true;
    input.addEventListener("input", function () { updatePlan(); maybePreflight(); });
    input.addEventListener("change", function () { updatePlan(); maybePreflight(); });
  }
  ["scope-row", "verify-row", "st-row"].forEach(function (id) {
    var row = document.getElementById(id);
    if (row && !row.__slPlanWired) {
      row.__slPlanWired = true;
      row.addEventListener("click", function () { setTimeout(updatePlan, 0); });
    }
  });
  var preCb = document.getElementById("opt-preflight");
  if (preCb) {
    try {
      var saved = localStorage.getItem("sitelens-preflight");
      if (saved === "0") preCb.checked = false;
    } catch (e) {}
    if (!preCb.__slWired) {
      preCb.__slWired = true;
      preCb.addEventListener("change", function () {
        try { localStorage.setItem("sitelens-preflight", preCb.checked ? "1" : "0"); } catch (e) {}
        maybePreflight();
      });
    }
  }
  ["opt-cookie", "opt-ua"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el && !el.__slPreWired) {
      el.__slPreWired = true;
      el.addEventListener("change", function () { maybePreflight(); });
    }
  });
  updatePlan();
}

/* ---- 扫描前预检（1 次只读 GET；结果在开始扫描时复用为首页，总请求不增加） ---- */
var preflightId = null, preflightFor = "", preflightSeq = 0, preflightTimer = null, lastSuggestion = null;

function preflightEnabled() {
  var cb = document.getElementById("opt-preflight");
  if (cb) return !!cb.checked;
  try { return localStorage.getItem("sitelens-preflight") !== "0"; } catch (e) { return true; }
}
function clearPreflight() { preflightId = null; preflightFor = ""; lastSuggestion = null; }

function maybePreflight() {
  if (preflightTimer) clearTimeout(preflightTimer);
  var input = document.getElementById("url");
  var raw = input ? input.value.trim() : "";
  var v = window.slLive ? window.slLive.validateTarget(raw) : { ok: false };
  if (!v.ok || !preflightEnabled()) { clearPreflight(); updatePlan(); return; }
  if (raw === preflightFor && preflightId) return;
  preflightTimer = setTimeout(function () { runPreflight(raw); }, 600);
}

function runPreflight(url) {
  var el = document.getElementById("plan");
  var seq = ++preflightSeq;
  if (el) {
    el.hidden = false;
    el.innerHTML = '<div class="plan-head"><b>预检中…</b><span class="hint">1 次只读请求</span></div>';
  }
  var body = { url: url };
  if (document.getElementById("opt-ua") && document.getElementById("opt-ua").checked) body.browser_ua = true;
  var ck = document.getElementById("opt-cookie") ? document.getElementById("opt-cookie").value.trim() : "";
  if (ck) body.auth_cookie = ck;
  api.post("/api/preflight", body).then(function (r) {
    if (seq !== preflightSeq) return;
    preflightId = r.preflight_id || null;
    preflightFor = url;
    renderPreflight(r, null);
  }).catch(function (e) {
    if (seq !== preflightSeq) return;
    clearPreflight();
    renderPreflight(null, e && e.message ? e.message : "预检失败");
  });
}

function renderPreflight(pf, err) {
  var el = document.getElementById("plan");
  if (!el) return;
  if (err) {
    el.hidden = false;
    el.innerHTML = '<div class="plan-head"><b>预检失败</b><span class="hint">' + esc(err) + "</span></div>" +
      '<div class="plan-eta">仍可直接开始扫描；也可 <a href="#" onclick="retryPreflight();return false;">重试预检</a></div>';
    return;
  }
  var s = window.slLive ? window.slLive.suggest(pf) : { strength: "std", verify: {}, reasons: [], warnings: [] };
  lastSuggestion = s;
  var tech = (pf.tech || []).slice(0, 6).join(" · ");
  var LEVEL_NAMES = { fast: "快速档", std: "标准档", deep: "深度档", full: "完整档", exhaustive: "穷尽档" };
  var level = LEVEL_NAMES[s.strength] || "标准档";
  var html = '<div class="plan-head"><b>目标预检</b><span class="hint mono">' + esc(pf.final_url || pf.requested_url || "") + "</span></div>" +
    '<div class="plan-items">' +
    '<span class="plan-item">HTTP ' + (Number(pf.status) || 0) + "</span>" +
    (pf.title ? '<span class="plan-item">' + esc(pf.title) + "</span>" : "") +
    (pf.server ? '<span class="plan-item">' + esc(pf.server) + "</span>" : "") +
    '<span class="plan-item">' + (Number(pf.response_ms) || 0) + "ms</span>" +
    (tech ? '<span class="plan-item">' + esc(tech) + "</span>" : "") + "</div>";
  if (pf.blocked) html += '<div class="plan-warn">WAF/限流：' + esc(pf.block_reason || "已拦截") + "</div>";
  if ((s.reasons || []).length) {
    html += '<div class="plan-head" style="margin-top:8px"><b>建议</b><span class="hint">' + esc(level) + "</span></div>";
    s.reasons.forEach(function (r) { html += '<div class="plan-eta">· ' + esc(r) + "</div>"; });
  }
  (s.warnings || []).forEach(function (w) { html += '<div class="plan-warn">' + esc(w) + "</div>"; });
  html += '<div class="plan-eta"><button class="btn ghost small" onclick="applySuggestion()">应用建议</button> ' +
    '<button class="btn ghost small" onclick="retryPreflight()">重新预检</button></div>';
  el.hidden = false;
  el.innerHTML = html;
}

window.retryPreflight = function () {
  var input = document.getElementById("url");
  if (input && input.value.trim()) runPreflight(input.value.trim());
};
window.applySuggestion = function () {
  var s = lastSuggestion;
  if (!s) return;
  var st = document.querySelector('#st-row .seg-opt[data-st="' + s.strength + '"]');
  if (st && !st.classList.contains("on")) st.click();
  Object.keys(s.verify || {}).forEach(function (k) {
    var chip = document.querySelector('#verify-row [data-verify="' + k + '"]');
    if (chip && chip.classList.contains("on") !== !!s.verify[k]) chip.click();
  });
  toast("已应用建议：" + s.strength + " 档", "ok");
  updatePlan();
};

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
}).catch(function (e) { window.slReportError(e, { quiet: true }); });

var liveTimer = null, liveStart = 0, liveEst = 0, livePct = 3, liveElapsed = 0;
function renderLivePanel(options) {
  liveEst = estimateSeconds(options);
  liveStart = Date.now();
  livePct = 3;
  liveElapsed = 0;
  var rows = STAGES.map(function (st, i) {
    return '<div class="stage" id="stage-' + i + '"><span class="s-ico">○</span> ' + st[1] + "</div>";
  }).join("");
  document.getElementById("result").innerHTML =
    '<div class="livebox card"><div class="lv-head">扫描进行中' +
    '<button class="btn ghost small" id="cancel-btn" onclick="cancelScan()">取消扫描</button></div>' +
    '<div class="lv-stats" id="lv-stats"></div>' +
    '<div class="lv-warn" id="lv-warn" hidden></div>' +
    rows +
    '<div class="lv-feed" id="lv-feed"></div>' +
    '<div class="lv-meta">已用时 <b id="lv-elapsed">0 秒</b> · 预计剩余 <b id="lv-eta">' +
    fmtT(liveEst) + "</b></div></div>";
  liveTimer = setInterval(function () {
    var el = (Date.now() - liveStart) / 1000;
    var eta = document.getElementById("lv-eta");
    var el2 = document.getElementById("lv-elapsed");
    if (!eta) { clearInterval(liveTimer); return; }
    el2.textContent = fmtT(el);
    eta.textContent = fmtT(window.slLive ? window.slLive.etaSeconds(livePct, el, liveEst) : Math.max(liveEst - el, 3));
  }, 1000);
}
function markStage(p) {
  STAGES.forEach(function (st, i) {
    var el = document.getElementById("stage-" + i);
    if (el && p > st[0]) { el.querySelector(".s-ico").textContent = "✓"; el.classList.add("done"); }
  });
}
/* 引擎实时阶段 → 时间线高亮（比纯百分比更准：DAST 可能长时间停在 85%） */
var PHASE_STAGE = {
  prepare: 0, home: 1, jsmap: 2, crawl: 2, fingerprint: 3, security: 4,
  checks: 5, passive: 6, nuclei: 7, dast: 8, exploit: 8, active: 9, done: 10
};
function markPhase(phase) {
  var idx = PHASE_STAGE[phase];
  if (idx == null) return;
  STAGES.forEach(function (st, i) {
    var el = document.getElementById("stage-" + i);
    if (!el) return;
    el.classList.toggle("active", i === idx);
    if (i < idx) { el.querySelector(".s-ico").textContent = "✓"; el.classList.add("done"); }
  });
}
/* 实时统计条：请求/页面/被拦/瞬时速率（来自 job.live = engine.LiveStats） */
function statChips(L) {
  var rate = Number(L.rate || 0);
  var cells = [
    ["阶段", L.phase_name || L.phase || "-"],
    ["请求", L.requests || 0],
    ["页面", L.pages || 0],
    ["被拦", L.blocked || 0],
    ["速率", rate > 0 ? rate.toFixed(1) + " req/s" : "—"]
  ];
  return cells.map(function (c) {
    var danger = (c[0] === "被拦" && Number(L.blocked || 0) > 0) ? " danger" : "";
    return '<div class="lv-stat' + danger + '"><span>' + esc(c[0]) + "</span><b>" + esc(String(c[1])) + "</b></div>";
  }).join("");
}
function setProgress(p, msg, job) {
  livePct = p;
  document.getElementById("bar").style.width = p + "%";
  document.getElementById("st-state").textContent = "scanning";
  document.getElementById("st-msg").textContent = msg || "";
  markStage(p);

  /* 实时统计 + WAF 拦截提示 + 阶段时间线（job.live 为引擎节流推送） */
  var L = job && job.live;
  if (L) {
    liveElapsed = (L.elapsed_ms || 0) / 1000;
    var stats = document.getElementById("lv-stats");
    if (stats) stats.innerHTML = statChips(L);
    var warn = document.getElementById("lv-warn");
    if (warn) {
      if (Number(L.blocked || 0) > 0) {
        warn.hidden = false;
        warn.textContent = "⚠ 目标疑似 WAF/限流：已拦 " + L.blocked + " 次，扫描器已自动降速；被拦响应不参与判定。";
      } else {
        warn.hidden = true;
      }
    }
    markPhase(L.phase);
  }

  /* 实时动态：引擎事件流（阶段/命中/绕过/认证）尾部 8 条，命中计数高亮 */
  var feedEl = document.getElementById("lv-feed");
  if (!feedEl || !job) return;
  var evs = job.events || [];
  if (!evs.length) { feedEl.innerHTML = ""; return; }
  var hits = 0, bypass = 0;
  var rows = evs.slice(-8).reverse().map(function (ev) {
    var color = getComputedStyle(document.documentElement).getPropertyValue("--muted-fg").trim() || "#9b9ba4";
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
  var v = window.slLive ? window.slLive.validateTarget(url) : { ok: !!url };
  if (!v.ok) {
    var h = document.getElementById("hint");
    if (h) { h.textContent = v.error; h.className = "hint warn"; }
    updatePlan();
    document.getElementById("url").focus();
    return;
  }
  var options = buildOptions();
  if (!options) return; // 范围校验失败（如全不选），buildOptions 已给出提示
  var ck = document.getElementById("opt-cookie").value.trim();
  if (ck) options.auth_cookie = ck;
  if (document.getElementById("opt-ua").checked) options.browser_ua = true;

  /* 后端 /api/scan 从 body 顶层读取各选项（data.get("deep") 等），必须平铺不能嵌套 */
  var payload = Object.assign({ url: url }, options);
  if (preflightId && preflightFor === url) payload.preflight_id = preflightId;
  lastScanPayload = payload;
  runScanPayload(payload, options);
}

/* runScanPayload 提交扫描并轮询；与表单解耦，供「继续扫描」按原参数重提复用。 */
function runScanPayload(payload, options) {
  clearPartialBanner();
  hideHero(); // 扫描开始：收起空态 hero
  document.getElementById("pw").style.display = "block";
  document.getElementById("go").disabled = true;
  renderLivePanel(options || payload);
  setProgress(3, "提交任务…");
  setAdvNoteFromOptions(options || payload); // G09/G10：扫描中提示（进度条下方一行）

  api.post("/api/scan", payload)
    .then(function (r) {
      /* URL 自动修正回显：后端只改格式不改目标，修正说明必须让用户看见 */
      if (r && r.url_corrections && r.url_corrections.length) {
        toast("地址已自动修正：" + r.url_corrections.join("、"), "ok");
      }
      currentJobId = r.job_id;
      return pollJob(r.job_id, setProgress);
    })
    .then(function (job) {
      document.getElementById("go").disabled = false;
      if (liveTimer) clearInterval(liveTimer);
      hideAdvNote(); // 扫描结束（done/partial/cancelled）即收提示
      /* FE-12：被中断的扫描不再「结果全丢」——引擎已把部分结果落库 */
      if (job && job.partial) {
        document.getElementById("st-state").textContent = "partial";
        document.getElementById("st-msg").textContent = "已中断（部分结果已保存）";
        toast("扫描已中断，部分结果已保存", "ok");
        showPartialBanner(job);
        loadPartialPreview(job);
        return null;
      }
      if (job && job.cancelled) {
        document.getElementById("st-state").textContent = "cancelled";
        document.getElementById("st-msg").textContent = "已取消";
        /* 取消后回到空态：清空画布并恢复 hero（已完成阶段可能已入历史） */
        document.getElementById("result").innerHTML = "";
        showHero();
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
      hideAdvNote();
      document.getElementById("st-state").textContent = "error";
      document.getElementById("st-msg").textContent = e.message;
      document.getElementById("result").innerHTML =
        '<div class="empty"><span class="big">✕</span>' + esc(e.message) + "</div>";
    });
}

/* ---------------- FE-12 部分结果：提示条 + 续扫 ---------------- */
function clearPartialBanner() {
  var old = document.getElementById("partial-banner");
  if (old && old.parentNode) old.parentNode.removeChild(old);
}

function showPartialBanner(job) {
  clearPartialBanner();
  var anchor = document.getElementById("result");
  if (!anchor || !anchor.parentNode) return;
  var msg = (job && job.message) || "扫描被中断，已完成阶段的结果已保存到历史";
  var box = document.createElement("div");
  box.id = "partial-banner";
  box.className = "partial-banner";
  box.setAttribute("role", "status");
  box.innerHTML = "<b>已中断（部分结果已保存）</b>" +
    '<span class="hint">' + esc(msg) + "</span>" +
    '<button type="button" class="btn small" onclick="resumePartialScan()">继续扫描</button>';
  anchor.parentNode.insertBefore(box, anchor);
}

/* 部分结果预览：引擎落库后取同 URL 最新一条历史渲染（失败则只留提示条）。 */
function loadPartialPreview(job) {
  if (job && job.scan_id) {
    api.get("/api/history/" + job.scan_id).then(function (row) {
      if (row && row.result) { currentScanId = row.id; renderResult(row.result, row.id); }
    }).catch(function () { /* 预览失败不影响提示条与续扫按钮 */ });
    return;
  }
  var want = (lastScanPayload && lastScanPayload.url) || "";
  if (!want) return;
  api.get("/api/history?limit=5").then(function (list) {
    var rows = (list && list.scans) || [];
    var hit = null;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i] && rows[i].url === want) { hit = rows[i]; break; }
    }
    if (!hit) return;
    return api.get("/api/history/" + hit.id).then(function (row) {
      if (!row || !row.result) return;
      currentScanId = row.id;
      renderResult(row.result, row.id);
    });
  }).catch(function () { /* 预览失败不影响提示条与续扫按钮 */ });
}

/* 继续扫描：复用上次提交的 url/level（三维选项）原样重提；无记录则回落到表单。 */
window.resumePartialScan = function () {
  var url = (lastScanPayload && lastScanPayload.url) ||
    (document.getElementById("url").value || "").trim();
  if (!url) return;
  document.getElementById("url").value = url;
  if (lastScanPayload && lastScanPayload.url === url) {
    toast("按上次参数重新扫描…", "ok");
    runScanPayload(JSON.parse(JSON.stringify(lastScanPayload)), lastScanPayload);
    return;
  }
  startScan();
};

function pollJob(jobId, onProgress) {
  return new Promise(function (resolve, reject) {
    // slPoll 句柄必须 handle.stop()（clearInterval 对句柄无效，会漏成每秒永续轮询）
    var handle = slPoll(function () {
      api.get("/api/job/" + jobId).then(function (job) {
        if (job.status === "done") { handle.stop(); resolve(job); }
        else if (job.status === "partial") {
          /* FE-12：引擎迁移到 partial（取消/中断后部分结果已落库） */
          handle.stop();
          resolve({ partial: true, status: "partial", message: job.message, scan_id: job.scan_id });
        }
        else if (job.status === "cancelled") {
          handle.stop(); resolve({ cancelled: true, message: job.message });
        }
        else if (job.status === "error") { handle.stop(); reject(new Error(job.message || "任务失败")); }
        else if (onProgress) onProgress(job.progress || 0, job.message, job);
      }).catch(function (e) { handle.stop(); reject(e); });
    }, 1000);
  });
}

function cancelScan() {
  if (!currentJobId) return;
  var btn = document.getElementById("cancel-btn");
  if (btn) { btn.disabled = true; btn.textContent = "取消中…"; }
  document.getElementById("st-msg").textContent = "取消中…";
  api.post("/api/job/" + currentJobId + "/cancel", {})
    .catch(function (e) { window.slReportError(e); });
}

/* ---------------- 结果渲染 ---------------- */
var CAT_NAMES = {};
api.get("/api/categories").then(function (r) {
  r.categories.forEach(function (c) { CAT_NAMES[c.id] = c.name; });
}).catch(function (e) { window.slReportError(e, { quiet: true }); });

/* 扫描覆盖度/诊断卡（5.2 效率轮 diagnostics，additive）：
   把「这次到底扫了多少、有没有被拦、请求省了多少」摊开给用户看——
   被 WAF/限流拦截的响应不参与判定，必须在报告里显式声明，避免"静默少报"。 */
var PHASE_NAMES = {
  home: "首页", jsmap: "JS 端点", crawl: "爬取", fingerprint: "指纹",
  security: "安全头", dast: "DAST"
};
function coverageCard(r) {
  var d = r && r.diagnostics;
  if (!d) return "";
  var pages = (r.pages || []).length;
  var blocked = Number(d.blocked || 0);
  var phases = d.phases || [];
  var waf = d.waf_reasons || {};
  var wafKeys = Object.keys(waf);
  var rateTxt = (d.rate_mode === "polite")
    ? "polite 固定间隔"
    : "balanced ≤" + (d.max_rps || 8) + " req/s";
  var cells = [
    ["访问页面", pages + " 页"],
    ["实际请求", (d.requests || 0) + " 次"],
    ["去重省下", (d.dedup_hits || 0) + " 次"],
    ["被 WAF/限流拦截", blocked + " 次"],
    ["平均速率", Number(d.avg_rps || 0).toFixed(1) + " req/s"],
    ["限速档", rateTxt]
  ];
  var h = '<div class="cov-card"><div class="cov-head"><b>扫描覆盖度</b>' +
    '</div>' +
    '<div class="cov-grid">' + cells.map(function (c) {
      var cls = (c[0].indexOf("拦截") >= 0 && blocked > 0) ? "danger" : "";
      return '<div class="cov-cell"><span>' + esc(c[0]) + '</span><b class="' + cls + '">' + esc(c[1]) + "</b></div>";
    }).join("") + "</div>";
  if (wafKeys.length) {
    h += '<div class="cov-note warn">WAF/限流原因：' + wafKeys.map(function (k) {
      return esc(k) + " ×" + waf[k];
    }).join(" · ") + "</div>";
  }
  var rows = phases.filter(function (p) { return (p.requests || 0) > 0 || (p.blocked || 0) > 0; });
  if (rows.length) {
    h += '<div class="tbl-wrap" style="margin-top:10px"><table class="vulns cov-table">' +
      "<tr><th>阶段</th><th>请求</th><th>去重省下</th><th>被拦</th><th>耗时</th></tr>";
    rows.forEach(function (p) {
      var dur = (p.duration_ms || 0) >= 1000
        ? ((p.duration_ms || 0) / 1000).toFixed(1) + " s"
        : (p.duration_ms || 0) + " ms";
      h += "<tr><td>" + esc(PHASE_NAMES[p.phase] || p.phase) + "</td><td>" + (p.requests || 0) +
        "</td><td>" + (p.dedup_hits || 0) + "</td><td>" + (p.blocked || 0) + "</td><td>" + dur + "</td></tr>";
    });
    h += "</table></div>";
  }
  h += '<div class="cov-note">覆盖声明：以上为本次扫描实际触达范围；未列出的模块（未开启或未命中）不在覆盖内。' +
    (blocked > 0 ? "被拦部分可能造成漏报，建议降低速率/更换出口后重扫。" : "") + "</div></div>";
  return h;
}

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
      '</div>';
    top.forEach(function (v) {
      var evN = 1 + (v.request ? 1 : 0) + (v.response ? 1 : 0) + ((v.signals || []).length ? 1 : 0) + (v.confirmed ? 1 : 0);
      html += '<div class="card" style="margin-bottom:10px">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
        "<b>" + esc(v.title || v.check || "") + "</b>" +
        sevBadge(v.severity) +
        '<span class="hint">证据 ' + evN + "/5 · " + (v.confirmed ? "二次确认通过" : "单轮命中") + "</span></div>" +
        '<div class="mono" style="word-break:break-all;font-size:12.5px;margin-top:6px">' + esc(v.url || "") + "</div>" +
        (v.advice ? '<div class="hint" style="margin-top:4px">建议：' + esc(v.advice) + "</div>" : "") +
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
  /* extras 提前取出：摘要区 ml_prior 与 ml_sev 说明都要读（下方通用 extras 循环同用） */
  var ex = r.extras || {};
  /* 产品先验（extras.ml_prior）：摘要区一行——top 产品 → 提权 N 项、增量纳入 M 项。
     5.2 阶段 2 起优先「指纹技术名 → 产品映射」（source=fingerprint，确定性，
     不展示概率）；指纹无命中时才回退模型（source=model，展示概率）。
     字段缺席（无有效先验）时整块隐藏，不留空壳。 */
  var priorCell = "";
  var prior = ex.ml_prior;
  if (prior && prior.products && prior.products.length) {
    var pTop = prior.products[0] || {};
    var pProm = Array.isArray(prior.promoted) ? prior.promoted.length : 0;
    var fpSource = prior.source === "fingerprint";
    var pLabel = fpSource ? "产品先验（指纹）" : "AI 产品先验";
    var pProb = fpSource ? "" : "（" + Number(pTop.prob || 0).toFixed(3) + "）";
    priorCell = '<div class="cell" style="grid-column:1/-1"><span>' + pLabel + '</span><b>' +
      esc(pTop.product || "-") + pProb + " → 提权 " +
      esc(String(prior.boosted || 0)) + " 项、增量纳入 " + pProm + " 项</b></div>";
  }
  html += '<div class="summary">' +
    cell("Host", r.host) + cell("标题", r.title || "-") +
    cell("IP", r.ip || "-") + cell("响应", (r.response_time_ms || 0) + " ms") +
    cell("耗时", (r.duration || 0) + " s") +
    '<div class="cell"><span>安全响应头</span><b><span class="badge ' + gradeCls + '">' +
    esc(grade) + " " + (sec.score || 0) + "分</span></b></div>" + priorCell + "</div>";

  /* 证据链/攻击链入口：本次扫描已收集事实图（默认开启），直接深链到攻击链页 */
  if (scanId) {
    html += '<p class="chain-link"><a class="btn ghost small" href="/chain?id=' +
      encodeURIComponent(String(scanId)) + '">查看证据链 / 攻击链</a></p>';
  }

  /* 扫描覆盖度（diagnostics）：放在摘要之后、明细之前——先讲清"扫了多少/有没有被拦" */
  html += coverageCard(r);

  /* G09/G10：高级 Web 检测（计划 / 发现）；result.extras.web_advanced 缺失时整卡不渲染 */
  html += advancedCard(r);

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
    html += '<div class="tbl-wrap"><table class="vulns"><tr><th>严重度</th><th>检测项</th><th>命中地址</th><th>修复建议</th><th>复核</th></tr>';
    ver.forEach(function (v, i) {
      var pane = evdPane(v);
      var block = pane ? '<details style="margin-top:4px"><summary style="cursor:pointer;font-size:12px">证据链</summary>' + pane + "</details>" : "";
      var imp = "";
      if (v.impact === "proven") imp = ' <span class="badge danger">影响已证明</span>';
      else if (v.impact === "observed") imp = ' <span class="badge warn">可利用面观测</span>';
      var impEv = v.impact_evidence ? '<div style="font-size:12px;color:var(--muted-fg)">利用级：' + esc(v.impact_evidence) + "</div>" : "";
      var evN = 1 + (v.request ? 1 : 0) + (v.response ? 1 : 0) + ((v.signals || []).length ? 1 : 0) + (v.confirmed ? 1 : 0);
      html += "<tr><td>" + sevBadge(v.severity) + "</td>" +
        '<td class="mono"><span class="badge">证据 ' + evN + "/5</span> " + esc(v.check) + " " + esc(v.title) + imp + "</td>" +
        '<td class="mono" style="font-size:12px;word-break:break-all">' + esc(v.url) +
        "（" + esc(v.evidence) + "）" + impEv + block + "</td><td>" + esc(v.advice) + "</td>" +
        '<td class="triage-cell" data-triage="verified:' + i + '"></td></tr>';
    });
    html += "</table></div>";
  } else {
    html += '<p class="muted" style="font-size:13px">无（本轮等级未运行验证检测或未命中）。</p>';
  }

  /* 配置卫生发现（extras.hygiene）：Cookie 安全属性 / CSRF token 这类
     配置事实。真实存在但不属于漏洞验证，与「已验证漏洞」分列呈现——
     混在一起会同时拉低准确率与召回口径（v5.0.1 起引擎侧已分离）。 */
  var hyg = (r.extras && r.extras.hygiene) || [];
  if (hyg.length) {
    html += '<div class="sec-title">配置卫生 <span class="count">' + hyg.length +
      " 条（配置事实，非漏洞验证）</span></div>";
    html += '<div class="tbl-wrap"><table class="vulns"><tr><th>严重度</th><th>检测项</th><th>命中地址</th><th>建议</th></tr>';
    hyg.forEach(function (v) {
      html += "<tr><td>" + sevBadge(v.severity) + "</td>" +
        '<td class="mono">' + esc(v.check) + " " + esc(v.title) + "</td>" +
        '<td class="mono" style="font-size:12px;word-break:break-all">' + esc(v.url) +
        "（" + esc(v.evidence) + "）</td><td>" + esc(v.advice) + "</td></tr>";
    });
    html += "</table></div>";
  }

  var vulns = r.vulnerabilities || [];
  html += '<div class="sec-title">漏洞情报关联 <span class="count">' + vulns.length +
    " 条（按组件关联的历史漏洞，非漏洞验证）</span></div>";
  if (vulns.length) {
    html += '<div class="tbl-wrap"><table class="vulns"><tr><th>严重度</th><th>判定</th><th>涉及技术</th><th>漏洞</th><th>类型</th><th>来源</th><th>复核</th></tr>';
    vulns.slice(0, 40).forEach(function (v, i) {
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
        "<td>" + esc(v.type || "-") + '</td><td class="mono">' + esc(v.src) + "</td>" +
        '<td class="triage-cell" data-triage="vuln:' + i + '"></td></tr>';
    });
    html += "</table></div>";
    if (vulns.length > 40)
      html += '<p class="hint">… 其余 ' + (vulns.length - 40) + " 条见导出文件</p>";
  } else {
    html += '<p class="muted" style="font-size:13px">未命中已知漏洞情报。</p>';
  }

  /* AI 预测（Result.Predictions，5.0 L3；5.2 阶段 1/2 起查表优先）：
     逐 CVE 先验——受影响产品 Top-3、CWE 弱点类型、严重度区间与来源徽章：
       - sev_source：nvd 查表（分数精确）/linear（±1.19）/onnx（可选高级包，±1.07）
       - tech_source：nvd（NVD CPE）/intel（情报行 product）/model（cve-tech 模型）
       - cwe_source：nvd（NVD weaknesses）/model（cwe-type 模型）
     查表结果的 prob 固定为 1（非概率），故仅 model 来源显示概率。
     先验参考，不参与扫描判定；无预测时整块不渲染。 */
  var preds = r.predictions || [];
  if (preds.length) {
    html += '<div class="sec-title">AI 预测 <span class="count">' + preds.length +
      " 条（先验参考，不参与扫描判定）</span></div>";
    html += '<div class="tbl-wrap"><table class="vulns"><tr><th>CVE</th><th>受影响产品 Top 3</th><th>弱点类型</th><th>严重度区间</th><th>来源</th></tr>';
    preds.slice(0, 40).forEach(function (p) {
      var tp = p.tech_top5 || [];
      var techSrc = p.tech_source || "";
      var t3 = tp.length
        ? tp.slice(0, 3).map(function (t) {
            var s = esc(t.product);
            // 查表结果不是概率（prob=1），只有模型推理才展示概率。
            return techSrc === "model" ? s + " " + Number(t.prob || 0).toFixed(3) : s;
          }).join(" · ")
        : "-";
      var sevTxt = "-";
      var src = p.sev_source || "";
      if (p.sev_score > 0) {
        if (src === "nvd") {
          sevTxt = Number(p.sev_score).toFixed(1) + "（NVD CVSS）";
        } else {
          var band = src === "linear" ? 1.19 : 1.07;
          var lo = Math.max(0, p.sev_score - band), hi = Math.min(10, p.sev_score + band);
          sevTxt = Number(p.sev_score).toFixed(1) + " ± " + band.toFixed(2) +
            "（" + lo.toFixed(1) + " – " + hi.toFixed(1) + "）";
        }
      }
      var badges = [];
      badges.push(src === "onnx"
        ? '<span class="badge acc">模型推理</span>'
        : (src === "linear" ? '<span class="badge">线性模型</span>'
          : (src === "nvd" ? '<span class="badge">NVD 查表</span>'
            : '<span class="badge">无先验</span>')));
      if (techSrc === "nvd") badges.push('<span class="badge">产品查表</span>');
      if (techSrc === "intel") badges.push('<span class="badge">产品情报</span>');
      if (p.cwe_source === "nvd") badges.push('<span class="badge">CWE 查表</span>');
      html += '<tr><td class="mono">' + esc(p.cve) + "</td>" +
        '<td class="mono" style="font-size:12.5px">' + t3 + "</td>" +
        '<td class="mono">' + esc(p.cwe_type || "-") + "</td>" +
        "<td>" + sevTxt + "</td><td>" + badges.join(" ") + "</td></tr>";
    });
    html += "</table></div>";
    if (preds.length > 40)
      html += '<p class="hint">… 其余 ' + (preds.length - 40) + " 条见 JSON 导出</p>";
  }

  // extras 里混着三类东西：① 真结果（子域名/端口/探测命中）→ 成节展示；
  // ② 元数据（输入规范化、鉴权矩阵、分片、NVD 图加载状态）→ 不在正文出现；
  // ③ 模型先验（ml_prior/ml_sev）→ 摘要区与降级说明已有，不进通用列表。
  var EXTRAS_SKIP = { ml_prior: 1, ml_sev: 1, url_input: 1, url_normalized: 1,
                      url_corrections: 1, auth_matrix: 1, pages_omitted: 1,
                      note: 1, graph_nvd: 1, shards: 1 };
  var titles = { active_fp: "主动路径指纹", dir_scan: "目录探测", dir_full_words: "目录全量词表",
                 dir: "目录探测", subdomain: "子域名", takeover: "子域接管",
                 service: "端口服务", netsec: "TLS / DNS 安全", weak_audit: "登录爆破结果",
                 webshell: "WebShell 路径探测", jsmap: "JS 攻击面", js: "JS 端点",
                 dast: "DAST 检测", passive: "被动安全检测", bypass: "403 绕过探测",
                 netproto: "协议模板检测（tcp/dns/ssl）", exploit: "利用级无害验证",
                 nuclei: "Nuclei 模板调度", hygiene: "配置卫生", web_advanced: "高级 Web 检测",
                 budget: "预算降级", panic: "扫描内异常" };
  Object.keys(ex).forEach(function (key) {
    if (EXTRAS_SKIP[key]) return;
    var items = ex[key] || [];
    // 空结果不占版面：数组为空（或对象无字段）时整节跳过——不再打印「子域名 0 / 未发现。」
    // 这类空节只会让报告变长、让用户以为漏了什么。模块真跑了没命中，摘要里已有覆盖度说明。
    if (Array.isArray(items)) {
      if (items.length === 0) return;
    } else if (!items || typeof items !== "object" || Object.keys(items).length === 0) {
      return;
    }
    var cnt = Array.isArray(items) ? items.length : null;
    html += '<div class="sec-title">' + esc(titles[key] || key) +
      (cnt !== null ? ' <span class="count">' + cnt + "</span>" : "") + "</div>";
    if (key === "exploit") {
      // 汇总对象：{proven, observed, gate}
      html += '<div class="extras-box mono">proven ' + esc(String(items.proven || 0)) +
        " · observed " + esc(String(items.observed || 0)) + " · 闸门 " + esc(String(items.gate || "-")) + "</div>";
      return;
    }
    if (key === "nuclei") {
      // 调度可见性汇总（对象非数组）：预算被 CVE 通道 / tag 命中 / LRU 轮转各吃掉多少。
      // 这是「指纹真受影响的 CVE 反查模板并提权」那条通道的唯一在线读数——
      // cve_hits 长期为 0 说明指纹没对上情报（模板池瞄的不是这台机器）。
      var srcs = items.sources && typeof items.sources === "object"
        ? Object.keys(items.sources).map(function (k) { return k + ":" + items.sources[k]; }).join(" ") : "-";
      html += '<div class="extras-box mono">' +
        "候选池 " + esc(String(items.index_total || 0)) +
        " · tag 命中 " + esc(String(items.tag_hits || 0)) +
        " · 受影响 CVE " + esc(String(items.cve_total || 0)) +
        " · CVE 命中模板 " + esc(String(items.cve_hits || 0)) +
        "<br>本轮选入 " + esc(String(items.selected || 0)) + "/" + esc(String(items.budget || 0)) +
        " · 来源 " + esc(srcs) + "</div>";
      return;
    }
    // 空数组已在循环开头跳过，这里必为非空列表（对象型在上面分支已 return）。
    html += '<div class="extras-box mono">';
    items.forEach(function (it) { html += extrasLine(key, it) + "<br>"; });
    html += "</div>";
  });

  document.getElementById("result").innerHTML = html;
  hideHero(); // 有结果：收起空态 hero
  if (scanId) document.getElementById("st-time").textContent = "记录 #" + scanId;
  /* CP-08：人工复核（误报/确认/忽略）+ 白名单灰显。异步加载，接口未接/旧引擎
     时 triage 内部静默降级，不影响结果页任何既有内容。 */
  if (window.SLTriage && window.SLTriage.enhance) {
    try {
      window.SLTriage.enhance(document.getElementById("result"), r, scanId);
    } catch (e) {
      if (window.slReportError) window.slReportError(e, { quiet: true });
    }
  }
}

function cell(label, value) {
  return '<div class="cell"><span>' + esc(label) + "</span><b>" + esc(value) + "</b></div>";
}
function exportButtons() {
  return '<button class="btn ghost small" onclick="exportAs(\'json\')">JSON</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'csv\')">明细 CSV</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'wide\')">宽表 CSV</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'html\')">HTML 报告</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'md\')">MD 报告</button>' +
    '<button class="btn ghost small" onclick="exportAs(\'sarif\')">SARIF</button>';
}
window.exportAs = function (fmt) {
  if (!currentScanId) return;
  slDownload("/api/export/" + currentScanId + "?fmt=" + fmt,
    "sitelens-" + currentScanId + "." + fmt, fmt === "html")
    .catch(function (e) { toast("导出失败：" + e.message, "err"); });
};

/* ?url= 预填 + 自动开扫（首页搜索框跳转入口）
   D-10：自动发起主动扫描前必须用户显式确认——否则任意外部链接
   （http://127.0.0.1:<port>/app?url=<目标>）被点开就等价于以本机为出口
   对任意目标发起扫描，既是未授权扫描风险，也把用户变成攻击跳板。 */
(function () {
  var q = new URLSearchParams(location.search).get("url");
  if (!q) return;
  var input = document.getElementById("url");
  if (input) input.value = q;
  if (window.confirm("是否立即扫描该目标？\n\n" + q)) {
    startScan();
  } else {
    /* 已预填，用户可自行点「开始扫描」 */
    var hint = document.getElementById("hint");
    if (hint) { hint.textContent = "已填入目标，确认后点「开始扫描」"; hint.className = "hint"; }
    if (window.toast) window.toast("已填入目标，未自动开扫", "ok");
  }
})();

/* ================= CP-09 证书到期提醒 ================= */
/* 数据源（资产提醒任务提供）：GET /api/assets/cert-expiry?host=
     {ok:true, host, not_after:"2026-12-31T00:00:00Z", days:88}
   兼容 days_left / remaining_days / notAfter；接口未接（404/网络异常）时回退到
   本次 /api/netsec 返回的 assets.days_left；两者都没有则隐藏卡片（静默降级）。 */
function certGrade(days) {
  if (days == null || !isFinite(days)) return { cls: "", label: "未知" };
  if (days < 0) return { cls: "danger", label: "已过期" };
  if (days <= 7) return { cls: "danger", label: "剩余 " + days + " 天（紧急）" };
  if (days <= 30) return { cls: "warn", label: "剩余 " + days + " 天（临期）" };
  return { cls: "ok", label: "剩余 " + days + " 天" };
}

function hideCertCard() {
  var el = document.getElementById("ns-cert");
  if (el) el.hidden = true;
}

function renderCertCard(host, days, notAfter, via) {
  var el = document.getElementById("ns-cert");
  if (!el) return;
  if (days == null && !notAfter) { el.hidden = true; return; }
  var g = certGrade(days);
  var when = notAfter
    ? String(notAfter).replace("T", " ").replace(/(\.\d+)?Z$/, "").slice(0, 16)
    : "";
  el.hidden = false;
  el.className = "cert-card" + (g.cls ? " " + g.cls : "");
  el.innerHTML = '<div class="cert-line"><span class="cert-title">证书到期</span>' +
    '<span class="badge ' + (g.cls || "") + '">' + esc(g.label) + "</span></div>" +
    '<div class="cert-sub mono">' + esc(host) + (when ? " · 到期 " + esc(when) : "") +
    (via ? " · " + esc(via) : "") + "</div>";
}

function renderCertFromAssets(host, a) {
  if (!a) { hideCertCard(); return; }
  var days = a.days_left != null ? Number(a.days_left)
    : a.days != null ? Number(a.days) : NaN;
  var notAfter = a.not_after || a.notAfter || "";
  if (!isFinite(days) && !notAfter) { hideCertCard(); return; }
  renderCertCard(host, isFinite(days) ? days : null, notAfter, "来自本次网络层检测");
}

function loadCertExpiry(host, assetsFallback) {
  hideCertCard();
  if (!host) return;
  api.get("/api/assets/cert-expiry?host=" + encodeURIComponent(host)).then(function (r) {
    r = r || {};
    if (r.ok === false) { hideCertCard(); return; }
    var raw = r.days != null ? r.days
      : r.days_left != null ? r.days_left
        : r.remaining_days != null ? r.remaining_days : null;
    var days = raw == null ? NaN : Number(raw);
    var notAfter = r.not_after || r.notAfter || r.expires_at || "";
    if (!isFinite(days) && !notAfter) { renderCertFromAssets(host, assetsFallback); return; }
    renderCertCard(host, isFinite(days) ? days : null, notAfter, "");
  }).catch(function () {
    /* 接口未接/异常：静默回退到本次 netsec 结果里的证书资产（若有） */
    renderCertFromAssets(host, assetsFallback);
  });
}

/* ================= 网络层检测 ================= */
function runNetsec() {
  var host = document.getElementById("ns-host").value.trim();
  if (!host) return;
  var portsEl = document.getElementById("ns-ports");
  var wantPorts = !!(portsEl && portsEl.checked);
  hideCertCard();
  document.getElementById("ns-go").disabled = true;
  document.getElementById("ns-out").innerHTML =
    '<div class="skeleton" style="height:60px"></div><p class="hint">检测中…（TLS 握手 + DNS 查询' + (wantPorts ? " + 端口探测" : "") + "）</p>";
  api.post("/api/netsec" + (wantPorts ? "?ports=1" : ""), { host: host }).then(function (r) {
    document.getElementById("ns-go").disabled = false;
    loadCertExpiry(host, r.assets);
    var hits = (r.findings || []).concat(r.ports || []);
    var head = "";
    if (r.assets) {
      var a = r.assets;
      head = '<div class="ns-card" style="border-top:3px solid var(--info)">' +
        '<div class="ns-head"><span class="ns-light" style="background:var(--info)"></span><b>证书资产</b></div>' +
        '<div class="mono ns-ev">颁发者：' + esc(a.issuer || "-") + "</div>" +
        (a.sans && a.sans.length ? '<div class="mono ns-ev">SAN：' + esc(a.sans.join(", ")) + "</div>" : "") +
        (a.not_after ? '<div class="mono ns-ev">到期：' + esc(a.not_after) + "（剩余 " + esc(String(a.days_left)) + " 天）</div>" : "") +
        "</div>";
    }
    if (!hits.length) {
      document.getElementById("ns-out").innerHTML = head ||
        ('<div class="ns-grid"><div class="ns-card" style="border-top:3px solid var(--ok)"><div class="ns-head"><span class="ns-light" style="background:var(--ok)"></span><b>' + esc(r.host) + "</b></div><div class='ns-title'>未发现网络层安全问题</div></div></div>");
      return;
    }
    var cards = hits.map(function (h) {
      var sev = (h.severity || "").toLowerCase();
      var dot = (sev === "high" || sev === "critical") ? "var(--danger)" : sev === "medium" ? "var(--warn)" : "var(--info)";
      return '<div class="ns-card" style="border-top:3px solid ' + dot + '">' +
        '<div class="ns-head"><span class="ns-light" style="background:' + dot + '"></span><b class="mono">' + esc(h.check) + "</b>" + sevBadge(h.severity) + "</div>" +
        '<div class="ns-title">' + esc(h.title) + "</div>" +
        (h.url ? '<div class="mono ns-ev">' + esc(h.url) + "</div>" : "") +
        (h.evidence ? '<div class="mono ns-ev">' + esc(h.evidence) + "</div>" : "") +
        (h.advice ? '<div class="hint">' + esc(h.advice) + "</div>" : "") +
        "</div>";
    });
    document.getElementById("ns-out").innerHTML = head + '<div class="ns-grid">' + cards.join("") + "</div>";
  }).catch(function (e) {
    document.getElementById("ns-go").disabled = false;
    loadCertExpiry(host, null); // netsec 失败但证书到期接口可能可用：独立再试一次
    document.getElementById("ns-out").innerHTML =
      '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
  });
}
document.getElementById("ns-host").addEventListener("keydown", function (e) {
  if (e.key === "Enter") runNetsec();
});
document.getElementById("ns-host").addEventListener("input", hideCertCard);

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
  var t0 = Date.now(); // 实时面板计时起点
  var jobId = null;
  api.post("/api/loginbrute", {
    url: url,
    authorized: true,
    captcha_type: capDD.value,
    // 无验证码档位必须发空串：后端把非空 captcha_field 当「显式指定」，
    // 会导致每次尝试都去找验证码图片而全部跳过
    captcha_field: capDD.value !== "none" ? (document.getElementById("lb-cap-field").value.trim() || "captcha") : "",
    multistep: !!(document.getElementById("lb-multistep") && document.getElementById("lb-multistep").checked)
  }).then(function (r) {
    jobId = r.job_id;
    return pollJob(jobId, function (p, msg, job) {
      document.getElementById("lb-bar").style.width = p + "%";
      document.getElementById("lb-st").textContent = msg || "";
      // 走查 Major：实时尝试计数（done/total 由引擎 progress 回调逐次上报）
      var done = job.done || 0, total = job.total || 0;
      var secs = ((Date.now() - t0) / 1000).toFixed(0);
      document.getElementById("lb-out").innerHTML =
        '<div class="lb-live"><span class="badge warn">尝试中</span>' +
        '<span class="mono" style="font-size:13px">' + done + " / " + total + "</span>" +
        '<span class="muted" style="font-size:12.5px">已用 ' + secs + "s · " +
        (total ? Math.round(done * 100 / total) : 0) + "%</span>" +
        '<span class="mono muted" style="font-size:12px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
        esc(msg || "") + "</span></div>";
    });
  }).then(function () {
    // /api/job/{id} 不带 results：完成后必须取 /results 才有 hits
    return api.get("/api/job/" + jobId + "/results");
  }).then(function (job) {
    lbGo.disabled = !lbAuth.checked;
    lbFrame.style.display = "none";
    var hits = (job.results && job.results.hits) || [];
    window.__slBruteHits = hits;
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
    html += "</table></div>";
    html += '<button class="btn ghost small" style="margin-top:10px" onclick="exportHits()">⤓ 导出命中（CSV）</button>';
    document.getElementById("lb-out").innerHTML = html;
  }).catch(function (e) {
    lbGo.disabled = !lbAuth.checked;
    document.getElementById("lb-out").innerHTML =
      '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
  });
}

// 25B-B5：导出命中弱口令为 CSV
window.exportHits = function () {
  var hits = (window.__slBruteHits = window.__slBruteHits || []);
  if (!hits.length) { toast("暂无命中可导出", "err"); return; }
  var csv = "user,password,url\n" + hits.map(function (h) {
    return '"' + String(h.user).replace(/"/g, '""') + '","' + String(h.password).replace(/"/g, '""') + '","' + String(h.url).replace(/"/g, '""') + '"';
  }).join("\n");
  var blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" });
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "brute_hits.csv";
  a.click();
  URL.revokeObjectURL(a.href);
  toast("已导出 " + hits.length + " 条命中", "ok");
};

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

/* ================= 工作台空态 hero（未扫描时替代右栏空白） ================= */
function hideHero() {
  var el = document.getElementById("wb-hero");
  if (el) el.hidden = true;
}

/* 最近 3 条历史：失败静默（接口不可用/旧引擎时 hero 其余部分照常） */
function loadHeroRecent() {
  var wrap = document.getElementById("wb-hero-recent-wrap");
  var box = document.getElementById("wb-hero-recent");
  if (!wrap || !box || !window.api) return;
  api.get("/api/history?limit=3").then(function (res) {
    var rows = (res && res.scans) || [];
    if (!rows.length) { wrap.hidden = true; return; }
    wrap.hidden = false;
    box.innerHTML = rows.map(function (s) {
      var grade = s && s.security_grade
        ? '<span class="badge">' + esc(String(s.security_grade)) + "</span>" : "";
      var at = String((s && s.scanned_at) || "").replace("T", " ").slice(0, 16);
      return '<a class="wb-hero-recent-item" href="/history?id=' + encodeURIComponent(String(s.id)) + '">' +
        '<span class="mono">' + esc(String((s && (s.host || s.url)) || "")) + "</span>" + grade +
        '<span class="hint">' + esc(at) + "</span></a>";
    }).join("");
  }).catch(function () { wrap.hidden = true; });
}

function showHero() {
  var el = document.getElementById("wb-hero");
  if (!el) return;
  var go = document.getElementById("go");
  if (go && go.disabled) return; // 扫描中不显示
  el.hidden = false;
  loadHeroRecent();
}

function initHero() {
  var el = document.getElementById("wb-hero");
  if (!el) return;
  el.addEventListener("click", function (e) {
    var goTo = e.target.closest ? e.target.closest("[data-hero-goto]") : null;
    if (goTo && typeof switchTab === "function") switchTab(goTo.getAttribute("data-hero-goto"));
  });
  var result = document.getElementById("result");
  if (!result || !result.innerHTML.trim()) showHero();
}

initHero();

/* ================= UI 细节：多选下拉 / URL 清空 / 状态点 ================= */
(function () {
  // 多选下拉（范围/验证）：按钮开合、点芯片不收起、外部点击收起、摘要同步
  function bindMulti(id, labelId, placeholder) {
    var root = document.getElementById(id);
    var label = document.getElementById(labelId);
    var row = root ? root.querySelector(".chip-row") : null;
    if (!root || !label || !row) return;
    function summary() {
      var on = [...row.querySelectorAll(".chip.on")];
      var names = on.map(function (c) { return c.textContent.trim(); });
      if (!names.length) { label.textContent = placeholder; return; }
      label.textContent = names.length === 1 ? names[0] : names[0] + " 等 " + names.length + " 项";
    }
    root.querySelector(".cdd-btn").addEventListener("click", function (e) {
      e.stopPropagation();
      var willOpen = !root.classList.contains("open");
      document.querySelectorAll(".cdd.open").forEach(function (c) { c.classList.remove("open"); });
      if (willOpen) root.classList.add("open");
    });
    root.querySelector(".cdd-pop").addEventListener("click", function (e) { e.stopPropagation(); });
    row.addEventListener("click", function () { summary(); });
    summary();
  }
  bindMulti("dd-scope", "dd-scope-label", "扫描范围");
  bindMulti("dd-verify", "dd-verify-label", "验证方式");
  bindMulti("dd-adv", "dd-adv-label", "高级检测（默认关）");
  document.addEventListener("click", function (e) {
    if (!e.target.closest || e.target.closest(".cdd")) return;
    document.querySelectorAll(".cdd.open").forEach(function (c) { c.classList.remove("open"); });
  });

  // URL 一键清空
  var url = document.getElementById("url");
  var clearBtn = document.getElementById("url-clear");
  if (url && clearBtn) {
    var wrap = url.closest(".tw-urlwrap");
    var sync = function () { wrap.classList.toggle("has-text", !!url.value); };
    url.addEventListener("input", sync);
    clearBtn.addEventListener("click", function () {
      url.value = "";
      sync();
      url.focus();
      /* 清空输入 = 回到空态：重置右栏并恢复 hero（扫描进行中不动） */
      var go = document.getElementById("go");
      if (go && go.disabled) return;
      document.getElementById("result").innerHTML = "";
      hideAdvNote();
      clearPartialBanner();
      updatePlan();
      showHero();
    });
    sync();
  }

  // 状态点：随 #st-state 文案变色（idle 灰 / running 绿脉冲 / done 绿常亮）
  var st = document.getElementById("st-state");
  var dot = document.getElementById("st-dot");
  if (st && dot) {
    var apply = function () {
      var t = st.textContent || "";
      dot.className = "st-dot";
      if (/running|扫描/.test(t)) dot.classList.add("run");
      else if (/done|完成/.test(t)) dot.classList.add("ok");
    };
    new MutationObserver(apply).observe(st, { childList: true, characterData: true, subtree: true });
    apply();
  }
})();

/* 扫描前反馈：首次渲染 + Turbo 换页重放（元素级 __slPlanWired 防重复监听） */
if (typeof wirePlan === 'function') wirePlan();
