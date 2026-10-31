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

  // suggest 根据预检结果给出建议档位（只建议，不自动改选项；app.js 由用户点「应用建议」）。
  function suggest(pf) {
    var p = pf || {};
    var reasons = [];
    var warnings = [];
    var tech = (p.tech || []).join(" ").toLowerCase();
    var server = String(p.server || "").toLowerCase();
    var waf = !!p.blocked || /cloudflare|akamai|sucuri|imperva|big-?ip|f5|waf/.test(server);
    var strength = "std";
    var verify = { afp: true, dir: true, ws: true, dast: true };

    if (waf) {
      verify.dast = false;
      reasons.push("检测到 WAF/限流特征" + (p.block_reason ? "（" + p.block_reason + "）" : "") + "：激进档会被拦，建议先降速");
      warnings.push("已建议关闭 DAST；确认目标可承受后可手动打开");
    } else if (/wordpress|drupal|joomla|thinkphp|spring|struts|laravel|django|rails|shiro/.test(tech)) {
      reasons.push("识别到 " + (p.tech || []).slice(0, 3).join(" / ") + "：保留专项检测与指纹识别");
    } else if (!tech && Number(p.status) >= 200 && Number(p.status) < 300) {
      strength = "fast";
      verify = { afp: false, dir: false, ws: false, dast: false };
      reasons.push("未识别到框架或参数入口：建议快速档，减少无效请求");
    }

    var st = Number(p.status) || 0;
    if (st === 401) warnings.push("目标要求认证：请填写认证 Cookie 后再扫描");
    if (st === 403) warnings.push("目标返回 403：可尝试开启浏览器 UA");
    if (st === 429 || st === 503) warnings.push("目标限流/暂不可用：建议 polite 档或稍后再扫");
    if (Number(p.response_ms) > 2000) warnings.push("目标响应较慢（" + p.response_ms + "ms）：建议降低速率");
    try {
      var a = new URL(p.requested_url || "");
      var b = new URL(p.final_url || "");
      if (a.hostname && b.hostname && a.hostname !== b.hostname) {
        warnings.push("目标跳转到其他主机（" + b.hostname + "）：请确认授权范围");
      }
    } catch (e) { /* URL 不完整时忽略 */ }

    return {
      strength: strength,
      verify: verify,
      reasons: reasons.slice(0, 3),
      warnings: warnings.slice(0, 3)
    };
  }

  return { validateTarget: validateTarget, etaSeconds: etaSeconds, requestBucket: requestBucket, suggest: suggest };
});
