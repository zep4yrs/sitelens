/* 三维选择器 → 引擎 payload 的纯映射（无 DOM 依赖，node --test 可测）。
   输入: { scope:{web,sub,srv,np,js,weak},
           verify:{passive,afp,dir,ws,dast,by,ex},
           strength:'fast'|'std'|'full' }
   输出: { ok, error?, warnings?, options?, effectiveStrength? }
   语义：验证按「动作」拆分，勾谁跑谁；被动与其余互斥（零额外请求）；
   强度为真三档（验证引擎档位 + nuclei 上限 + 字典缩放 + 端口集），
   被动模式下不消费强度。 */
(function () {
  "use strict";

  var TIERS = {
    fast: { checks: "none", nuclei_cap: 300, dir_max_paths: 60,
            shell_max_paths: 40, sub_max_words: 200, probe_ports: "common" },
    std:  { checks: "core", nuclei_cap: 1500, dir_max_paths: 150,
            shell_max_paths: 100, sub_max_words: 500, probe_ports: "common" },
    full: { checks: "all",  nuclei_cap: 6000, dir_max_paths: 300,
            shell_max_paths: 200, sub_max_words: 2000, probe_ports: "full" }
  };

  var SCOPE_KEYS = ["web", "sub", "srv", "np", "js", "weak"];
  var VERIFY_ACTIVE = ["afp", "dir", "ws", "dast", "by", "ex"];

  function build(input) {
    input = input || {};
    var scope = input.scope || {};
    var verify = input.verify || {};
    var strength = TIERS[input.strength] ? input.strength : "std";
    var warnings = [];

    var anyScope = SCOPE_KEYS.some(function (k) { return !!scope[k]; });
    if (!anyScope) {
      return { ok: false,
        error: "至少选择一个范围项（Web 站点 / 子域资产 / 端口服务 / 协议模板 / JS 端点 / 敏感信息审计）" };
    }

    var o = {};

    // ---- 被动：零额外请求。与其余验证互斥，强度维度不消费 ----
    if (verify.passive) {
      if (VERIFY_ACTIVE.some(function (k) { return !!verify[k]; })) {
        warnings.push("被动模式不发送任何主动请求，其余验证项已忽略。");
      }
      warnings.push("被动模式不消费强度档位。");
      if (scope.sub) { o.subdomain = true; o.takeover = true; }
      if (scope.srv) o.service_probe = true;
      if (scope.np) o.netproto = true;
      if (scope.js) warnings.push("JS 端点提取需抓取脚本文件，被动模式下已跳过。");
      if (scope.weak) warnings.push("敏感信息审计需主动请求，被动模式下已跳过。");
      o.netsec = true;   // 响应头评分：基于首页响应，零额外请求
      o.passive = true;
      o.checks = "none";
      return { ok: true, warnings: warnings, options: o, effectiveStrength: null };
    }

    // ---- 主动路径 ----
    if (scope.web) o.deep = true;
    else warnings.push("未选 Web 站点：仅浅访问首页，爬取类验证的覆盖面有限。");

    if (scope.sub) { o.subdomain = true; o.takeover = true; }
    if (scope.srv) o.service_probe = true;
    if (scope.np) o.netproto = true;
    if (scope.js) o.js_map = true;
    if (scope.weak) o.weak_audit = true;

    if (verify.afp) o.active_fp = true;
    if (verify.dir) o.dir_scan = true;
    if (verify.ws) o.webshell = true;
    if (verify.dast) o.dast = true;
    if (verify.by) {
      if (verify.dir) o.dir_bypass = true;
      else warnings.push("403 绕过需与「目录探测」同开，该项已忽略。");
    }
    if (verify.ex) {
      o.exploit = true;
      warnings.push("利用级验证需配置 exploit.enabled 与授权白名单；未授权目标零请求。");
    }
    if (verify.dast && !scope.web) {
      warnings.push("参数注入依赖爬取到的页面与表单，未选 Web 站点时覆盖有限。");
    }

    // 强度档位旋钮（只对已选模块下发，缺省档沿用引擎配置的不下发）
    var tier = TIERS[strength];
    o.checks = tier.checks;
    o.nuclei_cap = tier.nuclei_cap;
    if (verify.dir) o.dir_max_paths = tier.dir_max_paths;
    if (verify.ws) o.shell_max_paths = tier.shell_max_paths;
    if (scope.sub) o.sub_max_words = tier.sub_max_words;
    if (scope.srv && tier.probe_ports === "full") o.probe_ports = "full";

    return { ok: true, warnings: warnings, options: o, effectiveStrength: strength };
  }

  /* 耗时预估（秒）：粗粒度 UX 提示，非 SLA。 */
  function estimateSeconds(options) {
    var t = 5; // 基础（首页采集 + 指纹 + 情报关联）
    if (!options) return t;
    if (options.deep) t += 8;
    if (options.active_fp) t += 12;
    if (options.dir_scan) t += 40 + Math.round((options.dir_max_paths || 300) * 0.6);
    if (options.webshell) t += 40 + Math.round((options.shell_max_paths || 200) * 0.2);
    if (options.subdomain) t += 50 + Math.round((options.sub_max_words || 2000) * 0.012);
    if (options.takeover) t += 15;
    if (options.service_probe) t += options.probe_ports === "full" ? 40 : 15;
    if (options.netproto) t += 10;
    if (options.js_map) t += 8;
    if (options.weak_audit) t += 60;
    if (options.dir_bypass) t += 25;
    if (options.exploit) t += 60;
    if (options.checks === "core") t += 40 + Math.round((options.nuclei_cap || 300) * 0.1);
    if (options.checks === "all") t += 300 + Math.round((options.nuclei_cap || 300) * 0.35);
    return t;
  }

  var API = {
    build: build,
    estimateSeconds: estimateSeconds,
    TIERS: TIERS,
    SCOPE_KEYS: SCOPE_KEYS,
    VERIFY_ACTIVE: VERIFY_ACTIVE
  };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else window.scanOpts = API;
})();
