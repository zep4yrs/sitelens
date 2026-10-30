// 扫描前/扫描中的纯函数助手（无 DOM 依赖，node --test 可直测）。
// app.js 通过 window.slLive 消费；服务端 live 字段由 engine.LiveStats 提供。
(function (root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.slLive = api;
})(typeof window !== "undefined" ? window : null, function () {
  // validateTarget 目标预检：扫描前给出明确错误/风险提示（不发任何请求）。
  function validateTarget(raw) {
    var s = String(raw == null ? "" : raw).trim();
    if (!s) return { ok: false, error: "请输入目标地址（http:// 或 https://）", warnings: [] };
    var u;
    try {
      u = new URL(s);
    } catch (e) {
      return { ok: false, error: "地址格式不正确，需要完整 URL（如 https://example.com）", warnings: [] };
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { ok: false, error: "仅支持 http/https 目标（当前 " + u.protocol + "）", warnings: [] };
    }
    if (!u.hostname) return { ok: false, error: "缺少主机名", warnings: [] };
    var warnings = [];
    var host = u.hostname.toLowerCase();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      warnings.push("目标是 IP 地址：请确认已获得该资产授权");
    }
    if (host === "localhost" || /^127\./.test(host) || /^10\./.test(host) ||
        /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)) {
      warnings.push("目标是本机/内网地址：仅建议对自有资产扫描");
    }
    return { ok: true, normalized: u.href, warnings: warnings };
  }

  // etaSeconds 扫描中 ETA：进度 <8% 时用经验估时兜底，之后按实际速率外推。
  function etaSeconds(percent, elapsedSec, baseEstimate) {
    var p = Number(percent) || 0;
    var el = Math.max(0, Number(elapsedSec) || 0);
    var base = Math.max(0, Number(baseEstimate) || 0);
    if (p >= 8) return Math.max(3, Math.round((el * (100 - p)) / p));
    return Math.max(3, Math.round(base - el));
  }

  // requestBucket 扫描前请求量级粗估（不承诺数字，只给低/中/高，避免假精确）。
  function requestBucket(options) {
    var o = options || {};
    var score = 0;
    if (o.dast) score += 3;
    if (o.deep) score += 1;
    if (o.dir_scan) score += 1;
    if (o.webshell) score += 1;
    if (o.subdomain) score += 1;
    if (o.service_probe) score += 1;
    if (o.exploit) score += 1;
    if (o.checks === "core") score += 1;
    if (o.checks === "all") score += 2;
    if (score >= 5) return "高";
    if (score >= 2) return "中";
    return "低";
  }

  return { validateTarget: validateTarget, etaSeconds: etaSeconds, requestBucket: requestBucket };
});
