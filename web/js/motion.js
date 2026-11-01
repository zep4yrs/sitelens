/* SiteLens 动效工具（FE-05，5.2.x）
   ============================================================================
   UMD 零依赖：浏览器挂 window.slMotion；Node（node --test / require）走
   module.exports。扫描/结果加载的骨架屏与列表渐入由 app.js 直接调用
   `window.slMotion.showSkeleton(...)` / `listStagger(...)`（本文件不自动跑，
   避免在未接线页面产生副作用；声明式接线用 init()）。

   设计纪律：
     - 时长/缓动只消费 tokens.css 的 --t-fast / --t-med / --t-slow / --ease；
       取不到 CSS 变量时用 DURATION 兜底（与 tokens 同值）。
     - 默认尊重 prefers-reduced-motion: reduce：不播放动画、直接呈现终态，
       并把级联延迟清零（respectReducedMotion() 供调用方自行判断）。
     - 骨架屏只做装饰（aria-hidden="true"），加载状态文案由调用方用
       aria-live 区域提供；showSkeleton 会在宿主上维护 aria-busy。
     - 不做无限循环背景动效（骨架 shimmer 是唯一的循环，且 reduced-motion
       时被 CSS 关闭）；列表级联最多前 MAX_STAGGER 项（≤300ms 预算）。

   API：
     prefersReducedMotion() / respectReducedMotion() -> boolean
     fadeIn(el, opts) -> Promise<Element>            // opts: {duration, delay, onDone}
     skeleton(html, opts) -> Element|null            // 只创建不插入；html 可为模板串/变体名
     showSkeleton(target, opts) -> handle|null        // {el, done(cb), remove()}
     listStagger(target, opts) -> number              // 返回被级联的项数
     clearStagger(target)
     init(root)                                       // data-motion="fade|stagger" 声明式接线
     DURATION / STAGGER_MS / MAX_STAGGER
   ========================================================================== */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.slMotion = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /* 与 tokens.css 对齐的兜底值（毫秒）；实际优先读 CSS 变量 */
  var DURATION = { fast: 150, med: 250, slow: 400 };
  var STAGGER_MS = 25;    // 与 app.css 既有列表级联步进一致
  var MAX_STAGGER = 12;   // 前 12 项级联（≤300ms），其后直接呈现
  var EASE = "cubic-bezier(0.2, 0, 0, 1)"; // 与 --ease 同值（仅兜底）

  function hasDOM() {
    return typeof document !== "undefined" && !!document.createElement;
  }

  function prefersReducedMotion() {
    try {
      if (typeof window === "undefined" || !window.matchMedia) return false;
      return !!window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    } catch (e) {
      return false;
    }
  }

  /* 语义别名：调用方可以 `if (respectReducedMotion()) { 直接呈现终态 }` */
  function respectReducedMotion() {
    return prefersReducedMotion();
  }

  /* 读取 tokens.css 的 --t-*（拿不到时回退 DURATION） */
  function tokenMs(name, fallback) {
    if (!hasDOM() || !document.documentElement) return fallback;
    try {
      var raw = window.getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      if (!raw) return fallback;
      if (raw.slice(-2) === "ms") return parseFloat(raw) || fallback;
      if (raw.slice(-1) === "s") return (parseFloat(raw) || 0) * 1000 || fallback;
    } catch (e) { /* 忽略：回退兜底值 */ }
    return fallback;
  }

  function durationMs(opts, key) {
    opts = opts || {};
    if (typeof opts.duration === "number" && opts.duration >= 0) return opts.duration;
    return tokenMs("--t-" + (key || "med"), DURATION[key || "med"] || DURATION.med);
  }

  function clearInline(el) {
    if (!el || !el.style) return;
    el.style.animationDelay = "";
    el.style.animationDuration = "";
  }

  /* ---------------- 渐入 ---------------- */
  function fadeIn(el, opts) {
    opts = opts || {};
    if (!el || !el.classList) return Promise.resolve(el);
    var finish = function () {
      el.classList.remove("sl-fade-in");
      clearInline(el);
      if (typeof opts.onDone === "function") {
        try { opts.onDone(el); } catch (e) { /* 回调异常不影响动画收尾 */ }
      }
    };
    // 减少动效：直接呈现终态，不排队等 animationend
    if (respectReducedMotion()) {
      finish();
      return Promise.resolve(el);
    }
    var dur = durationMs(opts, opts.key || "med");
    var delay = typeof opts.delay === "number" && opts.delay > 0 ? opts.delay : 0;
    el.classList.remove("sl-fade-in");
    void el.offsetWidth; // 强制 reflow：允许同一元素重复触发动画
    el.style.animationDuration = dur + "ms";
    if (delay) el.style.animationDelay = delay + "ms";
    el.classList.add("sl-fade-in");
    return new Promise(function (resolve) {
      var settled = false;
      var settle = function () {
        if (settled) return;
        settled = true;
        el.removeEventListener("animationend", onEnd);
        clearTimeout(timer);
        finish();
        resolve(el);
      };
      var onEnd = function (e) {
        if (e && e.target !== el) return;
        settle();
      };
      el.addEventListener("animationend", onEnd);
      // animationend 在 display:none/后台标签页可能不触发：兜底定时器
      var timer = setTimeout(settle, dur + delay + 60);
    });
  }

  /* ---------------- 骨架屏 ---------------- */
  var SKEL_LINE = '<span class="skel skel-line"></span>';
  var WIDTHS = ["w90", "w70", "w50"];

  function lineHTML(width) {
    return '<span class="skel skel-line ' + (width || "") + '"></span>';
  }

  /* 按变体生成骨架内部 HTML（纯静态、无用户输入） */
  function buildSkeletonHTML(opts) {
    opts = opts || {};
    var variant = opts.variant || "text";
    var rows = Math.max(1, Math.min(50, opts.rows || 3));
    var lines = Math.max(1, Math.min(6, opts.lines || 2));
    var i, j, out = [];
    if (variant === "table") {
      out.push('<div class="skel-row"><span class="skel skel-cell w1"></span>' +
        '<span class="skel skel-cell"></span><span class="skel skel-cell"></span>' +
        '<span class="skel skel-cell"></span></div>');
      for (i = 0; i < rows; i++) {
        out.push('<div class="skel-row"><span class="skel skel-cell w1"></span>' +
          '<span class="skel skel-cell"></span><span class="skel skel-cell"></span>' +
          '<span class="skel skel-cell"></span></div>');
      }
    } else if (variant === "card") {
      for (i = 0; i < rows; i++) {
        out.push('<div class="skel skel-card">' + lineHTML("w40") + lineHTML("") +
          lineHTML("w70") + "</div>");
      }
    } else if (variant === "list") {
      for (i = 0; i < rows; i++) {
        out.push('<div class="skel-row"><span class="skel skel-dot"></span>' +
          lineHTML(i % 2 ? "w50" : "w70") + "</div>");
      }
    } else {
      for (i = 0; i < rows; i++) {
        out.push('<div class="skel-block">');
        for (j = 0; j < lines; j++) out.push(lineHTML(WIDTHS[j % WIDTHS.length]));
        out.push("</div>");
      }
    }
    return out.join("");
  }

  /* skeleton(html, opts)
     - html 为含 "<" 的字符串：直接作为骨架内部标记（调用方提供的静态模板，勿传用户输入）
     - html 为变体名（text|table|card|list）：按变体生成
     - html 省略：默认 text
     返回骨架容器元素（.skel-group，aria-hidden），不插入 DOM。 */
  function skeleton(html, opts) {
    if (!hasDOM()) return null;
    opts = opts || {};
    if (typeof html === "object" && html) { opts = html; html = null; }
    var inner;
    if (typeof html === "string" && html.indexOf("<") >= 0) {
      inner = html; // 静态模板：仅允许调用方写死的标记
    } else {
      if (typeof html === "string" && html) opts = Object.assign({}, opts, { variant: html });
      inner = buildSkeletonHTML(opts);
    }
    var el = document.createElement("div");
    el.className = "skel-group" + (opts.className ? " " + opts.className : "");
    el.setAttribute("aria-hidden", "true"); // 装饰性：状态由 aria-live 文案告知
    el.setAttribute("data-sl-skel", "1");
    el.innerHTML = inner;
    return el;
  }

  function resolveElement(target) {
    if (!target) return null;
    if (typeof target === "string") {
      if (!hasDOM()) return null;
      return document.querySelector(target);
    }
    if (target.nodeType === 1) return target;
    return null;
  }

  /* showSkeleton(target, opts)：插入骨架到宿主，返回 {el, done, remove}
     - 同一宿主只保留一组骨架（重复调用先清旧的）
     - 宿主维护 aria-busy="true"，done() 后恢复 */
  function showSkeleton(target, opts) {
    var host = resolveElement(target);
    if (!host || !hasDOM()) return null;
    opts = opts || {};
    var old = host.querySelector(":scope > [data-sl-skel]");
    if (old && old.parentNode) old.parentNode.removeChild(old);
    var el = skeleton(opts.variant || "text", opts);
    if (!el) return null;
    host.appendChild(el);
    host.setAttribute("aria-busy", "true");
    var removed = false;
    var handle = {
      el: el,
      remove: function () {
        if (removed) return;
        removed = true;
        if (el.parentNode) el.parentNode.removeChild(el);
        host.removeAttribute("aria-busy");
      },
      /* done(cb)：移除骨架并恢复 aria-busy；cb 在移除后调用（放真实内容） */
      done: function (cb) {
        handle.remove();
        if (typeof cb === "function") {
          try { cb(host); } catch (e) { /* 回调异常不外抛 */ }
        }
      }
    };
    return handle;
  }

  /* ---------------- 列表级联 ---------------- */
  function elementsOf(target) {
    if (!target) return [];
    if (typeof target === "string") {
      if (!hasDOM()) return [];
      return Array.prototype.slice.call(document.querySelectorAll(target));
    }
    if (target.nodeType === 1) {
      // 传容器：默认对直接子元素级联
      return Array.prototype.slice.call(target.children || []);
    }
    if (typeof target.length === "number") return Array.prototype.slice.call(target);
    return [];
  }

  /* listStagger(target, opts)
     target 可为容器（对子元素）、NodeList/数组、选择器串。
     opts: {stagger=25, max=12, duration}
     返回被设置级联的项数；reduced-motion 时清零延迟并返回 0。 */
  function listStagger(target, opts) {
    opts = opts || {};
    var els = elementsOf(target);
    if (!els.length) return 0;
    if (respectReducedMotion()) {
      els.forEach(function (el) { clearInline(el); el.classList.remove("sl-stagger-item"); });
      return 0;
    }
    var step = typeof opts.stagger === "number" && opts.stagger >= 0 ? opts.stagger : STAGGER_MS;
    var max = typeof opts.max === "number" && opts.max > 0 ? opts.max : MAX_STAGGER;
    var dur = opts.duration;
    var applied = 0;
    els.forEach(function (el, i) {
      if (!el || !el.classList) return;
      el.classList.add("sl-stagger-item");
      if (i < max) {
        el.style.animationDelay = i * step + "ms";
        applied++;
      } else {
        el.style.animationDelay = "0ms"; // 超出预算：直接呈现，不再排队
      }
      if (typeof dur === "number") el.style.animationDuration = dur + "ms";
    });
    return applied;
  }

  function clearStagger(target) {
    elementsOf(target).forEach(function (el) {
      if (!el || !el.classList) return;
      el.classList.remove("sl-stagger-item");
      clearInline(el);
    });
  }

  /* init(root)：声明式接线（页面/common.js 在需要时可调用；本文件不自动执行）
     - [data-motion="fade"] → fadeIn
     - [data-motion="stagger"] → 对其子元素 listStagger */
  function init(root) {
    if (!hasDOM()) return 0;
    root = resolveElement(root) || document;
    var n = 0;
    root.querySelectorAll('[data-motion="fade"]').forEach(function (el) {
      fadeIn(el);
      n++;
    });
    root.querySelectorAll('[data-motion="stagger"]').forEach(function (el) {
      listStagger(el);
      n++;
    });
    return n;
  }

  return {
    version: "5.2.0",
    DURATION: DURATION,
    STAGGER_MS: STAGGER_MS,
    MAX_STAGGER: MAX_STAGGER,
    EASE: EASE,
    prefersReducedMotion: prefersReducedMotion,
    respectReducedMotion: respectReducedMotion,
    tokenMs: tokenMs,
    fadeIn: fadeIn,
    skeleton: skeleton,
    showSkeleton: showSkeleton,
    listStagger: listStagger,
    clearStagger: clearStagger,
    init: init,
    buildSkeletonHTML: buildSkeletonHTML
  };
});
