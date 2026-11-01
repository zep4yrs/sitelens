/* =========================================================================
   CP-08 UI triage：结果页人工复核（误报 / 确认 / 忽略）+ 白名单提示 + 汇总。
   -------------------------------------------------------------------------
   指纹口径与 internal/server/batchdiff.go 完全一致（同一 finding 在前后端得到
   同一 fingerprint，导出的 SARIF partialFingerprints 亦然）：
       fingerprint = sha256(kind + "|" + identity) 前 16 字节（32 位 hex）
       vuln：CVE 优先（大写）；无 CVE 用 product|name|tech|type（小写 trim）
       verified：src|check(缺失退回 title)|diffURLKey(url)
   后端接口（internal/server/triage.go，路由由 server.Handler 注册）：
       GET  /api/triage/{scanId}   → {entries:[{fingerprint,verdict,...}], summary}
       POST /api/triage/{scanId}   {fingerprint,verdict,note}
       GET  /api/whitelist         → {entries:[{host,rule_id,...}]}
   降级：接口未接 / 旧引擎 / 引擎不可达 → 不渲染任何 triage UI，结果页照常；
        sha256 自检失败同样整体禁用（宁可不显示，也不写错指纹）。
   依赖：window.api / window.esc（common.js）；均做存在性判断。
   ========================================================================= */
(function () {
  "use strict";

  var hasWindow = typeof window !== "undefined";
  if (!hasWindow) return;

  var ESC = (typeof window.esc === "function")
    ? window.esc
    : function (s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
          return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
      };

  /* ---------------- SHA-256（纯 JS，离线可用：WebView2/普通浏览器一致） ---------------- */
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256Bytes(data) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var len = data.length;
    var bitLen = len * 8;
    var padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    padded.set(data);
    padded[len] = 0x80;
    var dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    var w = new Uint32Array(64);
    for (var i = 0; i < padded.length; i += 64) {
      for (var j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4);
      for (j = 16; j < 64; j++) {
        var s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        var s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (j = 0; j < 64; j++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var out = new Uint8Array(32);
    var ov = new DataView(out.buffer);
    for (i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
    return out;
  }

  function utf8Bytes(str) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(str);
    var s = unescape(encodeURIComponent(str));
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  function sha256Hex(str) {
    var d = sha256Bytes(utf8Bytes(str));
    var hex = "";
    for (var i = 0; i < d.length; i++) hex += (d[i] < 16 ? "0" : "") + d[i].toString(16);
    return hex;
  }

  /* 自检：实现写错时整体禁用，避免「指纹对不上后端」的静默错乱（宁可没有 UI） */
  var SELF_TEST_OK = sha256Hex("abc") ===
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  /* ---------------- 指纹（与 Go 侧逐字对齐） ---------------- */
  function fingerprint(kind, identity) { return sha256Hex(kind + "|" + identity).slice(0, 32); }

  function mapField(m, key) {
    if (!m) return "";
    var v = m[key];
    return typeof v === "string" ? v.trim() : "";
  }
  function normField(s) { return String(s == null ? "" : s).trim().toLowerCase(); }

  /* diffURLKey 与 internal/server/batchdiff.go 同口径：scheme/host 小写、去默认
     端口、空 path 视作 "/"、去尾部斜杠，保留 path/query；不可解析则 trim+小写。 */
  function diffURLKey(raw) {
    var s = String(raw == null ? "" : raw).trim();
    if (!s) return "";
    var u;
    try { u = new URL(s); } catch (e) { return s.toLowerCase(); }
    if (!u.hostname) return s.toLowerCase();
    var scheme = String(u.protocol || "").replace(":", "").toLowerCase();
    var host = String(u.hostname).toLowerCase();
    var port = u.port || "";
    if ((scheme === "http" && port === "80") || (scheme === "https" && port === "443")) port = "";
    var p = u.pathname || "";
    if (!p) p = "/";
    if (p.length > 1) { p = p.replace(/\/+$/, ""); if (!p) p = "/"; }
    var out = scheme + "://" + host + (port ? ":" + port : "") + p;
    var q = String(u.search || "").slice(1);
    if (q) out += "?" + q;
    return out;
  }

  function verifiedFp(v) {
    if (!v) return "";
    var src = mapField(v, "src");
    var check = mapField(v, "check") || mapField(v, "title");
    var url = mapField(v, "url");
    if (!check && !src && !url) return "";
    return fingerprint("verified", src + "|" + check + "|" + diffURLKey(url));
  }

  function vulnFp(v) {
    if (!v) return "";
    var cve = mapField(v, "cve").toUpperCase();
    if (cve) return fingerprint("vuln", cve);
    var parts = [normField(v.product), normField(v.name), normField(v.tech), normField(v.type)];
    if (parts.join("|").replace(/\|/g, "") === "") return "";
    return fingerprint("vuln", parts.join("|"));
  }

  function hostOf(raw) {
    var u;
    try { u = new URL(String(raw == null ? "" : raw).trim()); } catch (e) { return ""; }
    return u.hostname || "";
  }

  /* ---------------- 白名单匹配（与 store.IsWhitelisted 同语义） ---------------- */
  function normalizeHost(raw) {
    var h = String(raw == null ? "" : raw).trim();
    if (!h) return "";
    var i = h.indexOf("://");
    if (i >= 0) {
      try { var u = new URL(h); if (u.hostname) h = u.hostname; } catch (e) { /* 保持原样 */ }
    }
    var cut = h.search(/[/?#]/);
    if (cut >= 0) h = h.slice(0, cut);
    if ((h.match(/:/g) || []).length === 1) h = h.slice(0, h.lastIndexOf(":"));
    return h.replace(/\.+$/, "").toLowerCase();
  }

  function isWhitelisted(list, host, rule) {
    var q = normalizeHost(host);
    if (!q) return false;
    var rid = String(rule == null ? "" : rule).trim().toLowerCase();
    for (var i = 0; i < list.length; i++) {
      var e = list[i] || {};
      var er = String(e.rule_id == null ? "" : e.rule_id).trim().toLowerCase();
      if (er !== "*" && er !== rid) continue;
      var p = String(e.host == null ? "" : e.host).trim().toLowerCase();
      if (p.slice(0, 2) === "*.") {
        var suffix = p.slice(1); // ".example.com"（不含 apex）
        if (q.length > suffix.length && q.slice(-suffix.length) === suffix) return true;
      } else if (p && p === q) {
        return true;
      }
    }
    return false;
  }

  /* ---------------- 渲染 ---------------- */
  var VERDICTS = [
    ["false_positive", "误报"],
    ["confirmed", "确认"],
    ["ignored", "忽略"]
  ];
  var LABEL = { false_positive: "误报", confirmed: "确认", ignored: "忽略" };

  function itemByRef(res, ref) {
    var pos = String(ref || "").indexOf(":");
    if (pos < 0) return null;
    var kind = ref.slice(0, pos);
    var idx = Number(ref.slice(pos + 1));
    if (!isFinite(idx) || idx < 0) return null;
    var list = kind === "verified" ? (res.verified || [])
      : kind === "vuln" ? (res.vulnerabilities || []) : null;
    var item = list && list[idx];
    if (!item) return null;
    var host = hostOf(item.url) || String(res.host || "");
    if (kind === "verified") {
      return { fp: verifiedFp(item), rule: mapField(item, "check") || mapField(item, "title"), host: host };
    }
    return { fp: vulnFp(item), rule: mapField(item, "cve") || mapField(item, "name"), host: host };
  }

  function buttonsHTML(verdict) {
    var h = '<span class="triage-btns" role="group" aria-label="人工复核">';
    VERDICTS.forEach(function (v) {
      var on = verdict === v[0];
      h += '<button type="button" class="btn ghost small triage-btn' + (on ? " on" : "") +
        '" data-verdict="' + v[0] + '" aria-pressed="' + (on ? "true" : "false") + '">' + v[1] + "</button>";
    });
    return h + "</span>";
  }

  function setCellState(cell, verdict) {
    cell.innerHTML = buttonsHTML(verdict);
    bindButtons(cell, verdict);
  }

  function bindButtons(cell, verdict) {
    var scan = Number(cell.getAttribute("data-scan"));
    var fp = cell.getAttribute("data-fp") || "";
    Array.prototype.forEach.call(cell.querySelectorAll(".triage-btn"), function (btn) {
      btn.addEventListener("click", function () {
        mark(cell, scan, fp, btn.getAttribute("data-verdict"), btn);
      });
    });
    cell.setAttribute("data-verdict", verdict || "");
  }

  function mark(cell, scan, fp, verdict, btn) {
    if (!fp || !scan) return;
    var btns = cell.querySelectorAll(".triage-btn");
    Array.prototype.forEach.call(btns, function (b) { b.disabled = true; });
    window.api.post("/api/triage/" + scan, { fingerprint: fp, verdict: verdict, note: "" })
      .then(function (r) {
        cell.setAttribute("data-fp", fp);
        setCellState(cell, verdict);
        var sum = document.getElementById("triage-sum");
        if (sum && r && r.summary) paintSummary(sum, r.summary, sum.getAttribute("data-wl"));
        if (window.toast) window.toast("已标记：" + LABEL[verdict] + "（可再次点击改判）", "ok");
      })
      .catch(function (e) {
        Array.prototype.forEach.call(btns, function (b) { b.disabled = false; });
        if (window.slReportError) window.slReportError(e);
        else if (window.toast) window.toast("标记失败：" + (e && e.message ? e.message : e), "err");
        void btn;
      });
  }

  function paintSummary(el, summary, wlCount) {
    summary = summary || {};
    var fp = Number(summary.false_positive || 0);
    var cf = Number(summary.confirmed || 0);
    var ig = Number(summary.ignored || 0);
    var total = Number(summary.total != null ? summary.total : fp + cf + ig);
    var wl = Number(wlCount || 0);
    el.innerHTML = "<b>人工复核</b>" +
      '<span>误报 <b>' + fp + "</b></span>" +
      '<span>确认 <b>' + cf + "</b></span>" +
      '<span>忽略 <b>' + ig + "</b></span>" +
      (total ? '<span class="hint">共 ' + total + " 条已标记</span>" : "") +
      (wl ? '<span class="hint">白名单命中 ' + wl + " 条（已灰显）</span>" : "") +
      '<span class="hint">每条发现可标记；再次点击可改判</span>';
  }

  /* enhance：renderResult 写完 #result 后调用（app.js 末尾） */
  function enhance(container, res, scanId) {
    if (!container || !res || !scanId) return;
    if (!SELF_TEST_OK) { if (window.console) console.warn("[triage] sha256 自检失败，已禁用人工复核 UI"); return; }
    if (!window.api || typeof window.api.get !== "function") return;
    var scan = Number(scanId);
    if (!scan) return;
    var cells = container.querySelectorAll("[data-triage]");
    if (!cells.length) return;

    Promise.all([
      window.api.get("/api/triage/" + scan).catch(function () { return null; }),
      window.api.get("/api/whitelist").catch(function () { return null; })
    ]).then(function (rs) {
      var tri = rs[0], wl = rs[1];
      if (!tri && !wl) return; // 接口未接/不可用：静默降级，不碰结果页
      var marks = {};
      ((tri && tri.entries) || []).forEach(function (e) {
        if (e && e.fingerprint) marks[e.fingerprint] = e;
      });
      var wlList = (wl && wl.entries) || [];
      var muted = 0;

      Array.prototype.forEach.call(cells, function (cell) {
        var ref = cell.getAttribute("data-triage") || "";
        var item = itemByRef(res, ref);
        if (!item) { cell.innerHTML = '<span class="hint">—</span>'; return; }
        if (!item.fp) { cell.innerHTML = '<span class="hint">不可标记</span>'; return; }
        cell.setAttribute("data-scan", String(scan));
        cell.setAttribute("data-fp", item.fp);
        if (isWhitelisted(wlList, item.host, item.rule)) {
          cell.innerHTML = '<span class="badge info" title="命中白名单：' +
            ESC(item.host + " / " + item.rule) + '">白名单</span>';
          var row = cell.parentNode;
          if (row && row.classList) row.classList.add("triage-muted");
          muted++;
          return;
        }
        var marked = marks[item.fp];
        setCellState(cell, marked && marked.verdict);
        if (marked && rowOf(cell)) rowOf(cell).classList.add("triage-marked");
      });

      if (tri) {
        var sum = document.createElement("div");
        sum.id = "triage-sum";
        sum.className = "triage-sum";
        sum.setAttribute("role", "status");
        sum.setAttribute("data-wl", String(muted));
        paintSummary(sum, tri.summary, muted);
        container.insertBefore(sum, container.firstChild);
      }
    }).catch(function () { /* 静默降级：结果页不因 triage 失败而受影响 */ });
  }

  function rowOf(cell) {
    var n = cell.parentNode;
    return n && n.tagName === "TR" ? n : null;
  }

  window.SLTriage = {
    enhance: enhance,
    // 内部工具：供自测/排障（不参与 UI 逻辑）
    _internal: {
      sha256Hex: sha256Hex,
      fingerprint: fingerprint,
      verifiedFp: verifiedFp,
      vulnFp: vulnFp,
      diffURLKey: diffURLKey,
      normalizeHost: normalizeHost,
      isWhitelisted: isWhitelisted,
      selfTestOK: SELF_TEST_OK
    }
  };
})();
