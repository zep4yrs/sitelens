/* 源码静态审计（25A 升级版，FE-09 懒加载瘦身）：上传 → /api/audit →
   文件树 + Monaco 预览 + 标注跳转。工作台模式与独立 /audit 页共用；ID 统一
   audit- 前缀。
   Monaco 懒加载（/monaco/vs 本地路径，零 CDN）：
   - 初始页面不加载；首次进入审计页（window.slAuditActivate，common.js 模式
     切换时调用）或首次打开编辑器时才注入 loader.js + editor.main；
   - 加载中显示骨架占位；失败降级为只读 textarea + 提示（功能受限但不白屏）；
   - 单例状态挂 window.__slAuditMonaco，Turbo 换页/重复进入幂等复用；
   - models 按 URI 常驻——切走再切回，文件内容与标注不丢。只读预览：审计线索
     需人工复查。 */
(function () {
  "use strict";
  var input = document.getElementById("audit-files");
  var dz = document.getElementById("audit-dz");
  if (!input || !dz) return;

  var treeEl = document.getElementById("audit-tree");
  var editorEl = document.getElementById("audit-editor");
  var edEmpty = document.getElementById("audit-ed-empty");
  var summaryEl = document.getElementById("audit-summary");
  var outEl = document.getElementById("audit-out");
  var goBtn = document.getElementById("audit-go");

  var LANGS = { py: "python", js: "javascript", php: "php", go: "go", sql: "sql",
    html: "html", css: "css", json: "json", java: "java", rb: "ruby",
    c: "c", cpp: "cpp", cc: "cpp", h: "cpp", sh: "shell", yml: "yaml", yaml: "yaml" };
  var SEV_MARK = { critical: 8, high: 8, medium: 4, low: 2, info: 2 };
  var SEV_LINE = { critical: "audit-line-critical", high: "audit-line-high",
    medium: "audit-line-medium", low: "audit-line-low", info: "audit-line-low" };

  /* ---------------- 上传交互 ---------------- */
  input.addEventListener("change", showNames);
  dz.addEventListener("click", function (e) {
    if (e.target === dz || (e.target.className + "").indexOf("dz-pick") >= 0) input.click();
  });
  var pick = dz.querySelector(".dz-mini-txt");
  if (pick) pick.addEventListener("click", function (e) { e.stopPropagation(); input.click(); });
  ["dragover", "dragenter"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("drag"); });
  });
  dz.addEventListener("drop", function (e) {
    if (!e.dataTransfer) return;
    // 拖入目录（Chromium：items 带 webkitGetAsEntry）
    var entry = e.dataTransfer.items && e.dataTransfer.items[0] &&
      e.dataTransfer.items[0].webkitGetAsEntry && e.dataTransfer.items[0].webkitGetAsEntry();
    if (entry && entry.isDirectory) {
      e.preventDefault();
      collectDirEntry(entry).then(function (files) { ingestFolder(files, entry.name); });
      return;
    }
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      showNames();
    }
  });

  /* ---------------- 文件夹选择（25A：整目录上传） ---------------- */
  var dirBtn = document.getElementById("audit-dir-btn");
  var dirInput = document.getElementById("audit-dir-input");
  if (dirBtn && dirInput) {
    dirBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      dirInput.click();
    });
    dirInput.addEventListener("change", function () {
      var files = [...dirInput.files];
      if (!files.length) return;
      // webkitdirectory：每个 file.webkitRelativePath = "所选目录名/子路径/文件"
      var root = (files[0].webkitRelativePath || "project/").split("/")[0] || "project";
      ingestFolder(files, root);
      dirInput.value = "";
    });
  }

  // 可审计文本扩展（后端 zip 链路最终只认 .py/.js/.php，其余入树但不产出规则命中）
  var DIR_OK_EXT = ["py", "js", "php", "go", "java", "ts", "tsx", "jsx", "html", "htm",
    "css", "scss", "sql", "yml", "yaml", "json", "rb", "c", "h", "cpp", "cc", "sh", "md", "txt", "env", "ini", "xml"];
  var DIR_SKIP_DIR = /(^|\/)(node_modules|\.git|vendor|dist|build|__pycache__|\.venv|venv|target|\.idea|\.vscode)(\/|$)/;
  var MAX_DIR_FILES = 800;
  var MAX_DIR_BYTES = 8 << 20;

  function dirKeep(relPath, size) {
    var ext = (/\.([a-z0-9]+)$/i.exec(relPath) || [])[1];
    if (!ext || DIR_OK_EXT.indexOf(ext.toLowerCase()) < 0) return false;
    if (DIR_SKIP_DIR.test(relPath)) return false;
    if (size > MAX_DIR_BYTES) return false;
    return true;
  }

  // 把目录文件集打包 zip（JSZip，页内生成），rootName 为顶层目录名。
  // 打包期间置忙：input 上挂着的 zip 在完成前不被新 ingest 覆盖（懒加载竞态）。
  var ingestBusy = false;
  function ingestFolder(files, rootName) {
    if (ingestBusy) { toast("正在打包上一个目录…", "err"); return; }
    files.forEach(function (f) {
      if (!f.__rel) {
        // webkitdirectory 路径形如 root/sub/a.py → 去掉顶层 root 后为 zip 内相对路径
        var rp = f.webkitRelativePath || f.name;
        var parts = rp.split("/");
        parts.shift();
        f.__rel = parts.join("/") || f.name;
      }
    });
    var kept = files.filter(function (f) { return dirKeep(f.__rel, f.size); });
    if (!kept.length) { toast("该目录没有可审计的源码文件", "err"); return; }
    var total = kept.reduce(function (a, f) { return a + f.size; }, 0);
    if (kept.length > MAX_DIR_FILES) kept = kept.slice(0, MAX_DIR_FILES);
    var info = "已选目录「" + rootName + "」：" + kept.length + " 个文件（" +
      (total / 1024).toFixed(0) + " KB）" + (kept.length < files.length ? "，已过滤 " + (files.length - kept.length) + " 个（依赖/二进制/超限）" : "");
    var namesEl = document.getElementById("audit-names");
    if (namesEl) namesEl.textContent = info;

    ingestBusy = true;
    var busyTimeout = setTimeout(function () {  // 防卡死：30s 未完成自动复位
      if (ingestBusy) { ingestBusy = false; toast("目录打包超时，请重试", "err"); }
    }, 30000);
    ensureJsZip(function () {
      if (!window.JSZip) { // 三次重试后仍未就位：明确报错并复位，不再静默卡死
        clearTimeout(busyTimeout);
        ingestBusy = false;
        toast("打包组件加载失败，请刷新页面重试", "err");
        return;
      }
      var zip = new JSZip();
      kept.forEach(function (f) {
        zip.file(rootName + "/" + f.__rel, f);
      });
      zip.generateAsync({ type: "blob", compression: "DEFLATE" }).then(function (blob) {
        clearTimeout(busyTimeout);
        var dt = new DataTransfer();
        dt.items.add(new File([blob], rootName + ".zip", { type: "application/zip" }));
        input.files = dt.files;
        ingestBusy = false;
        showNames();
        toast("目录已打包：" + kept.length + " 个文件，可开始审计", "ok");
      }).catch(function () {
        clearTimeout(busyTimeout);
        ingestBusy = false;
        toast("目录打包失败", "err");
      });
    });
  }

  // 递归读取拖入的目录项（Chromium FileSystemEntry）
  function collectDirEntry(dirEntry) {
    var out = [];
    var reader = dirEntry.createReader();
    function readAll() {
      return new Promise(function (resolve) {
        reader.readEntries(function (entries) {
          if (!entries.length) return resolve();
          var ops = entries.map(function (en) {
            if (en.isDirectory) return collectDirEntry(en).then(function (sub) { out = out.concat(sub); });
            return new Promise(function (res2) {
              en.file(function (f) {
                // fullPath 形如 /root/sub/a.py，去掉顶层目录段（rootName 由 ingestFolder 统一前置），避免 zip 内 proj/proj/…
                f.__rel = en.fullPath.replace(/^\//, "").split("/").slice(1).join("/") || f.name;
                out.push(f);
                res2();
              }, res2);
            });
          });
          Promise.all(ops).then(function () { readAll().then(resolve); });
        }, resolve);
      });
    }
    return readAll().then(function () { return out; });
  }

  var jszipLoading = null, jszipTags = 0;
  function ensureJsZip(cb) {
    if (window.JSZip) { cb(); return; }
    if (jszipLoading) {
      // 已有进行中的加载：settle 后重查全局——若仍未就位（加载无效/被清），下次调用会另装新标签
      jszipLoading.then(function () { ensureJsZip(cb); });
      return;
    }
    jszipLoading = new Promise(function (resolve) {
      jszipTags++;
      var s = document.createElement("script");
      s.src = "/js/jszip.min.js?v=" + jszipTags; // 版本号击穿可能失效的缓存响应
      s.onload = s.onerror = function () { resolve(); }; // settle 只代表本次尝试结束
      document.head.appendChild(s);
      setTimeout(resolve, 8000); // 请求悬挂兜底
    });
    jszipLoading.then(function () { jszipLoading = null; }); // settle 即作废句柄
    jszipLoading.then(cb);
  }

  function showNames() {
    var el = document.getElementById("audit-names");
    if (el) el.innerHTML = input.files.length
      ? [...input.files].map(function (f) {
          return esc(f.name) + " (" + (f.size / 1024).toFixed(1) + " KB)";
        }).join("<br>")
      : "";
  }

  /* ---------------- Monaco 懒加载 / 单例 / 降级（FE-09） ----------------
     状态挂 window.__slAuditMonaco 跨 Turbo 换页复用：
       idle → loading → ready | failed
     只有「进入审计页」或「打开编辑器」才真正下载 /monaco/vs（约 12MB）；
     失败时降级为只读 textarea（app.html 内 #audit-fallback），不白屏。 */
  var MONACO_STATE = window.__slAuditMonaco || (window.__slAuditMonaco = {
    status: "idle", promise: null, error: null
  });
  // 就绪后要执行的一次性任务（跨渲染存活，避免 Turbo 换页丢队列）
  var READY_QUEUE = window.__slAuditReadyQueue || (window.__slAuditReadyQueue = []);
  var MONACO_TIMEOUT_MS = 12000; // 弱网/资源缺失兜底：超时按失败降级

  function monacoReady() {
    return !!(window.monaco && window.monaco.editor);
  }
  function monacoFailed() {
    return MONACO_STATE.status === "failed";
  }
  function queueMonacoReady(fn) {
    if (monacoReady()) { try { fn(); } catch (e) {} return; }
    if (monacoFailed()) return; // 已降级：不执行依赖 Monaco 的逻辑
    READY_QUEUE.push(fn);
  }
  function flushReadyQueue() {
    var q = READY_QUEUE.splice(0, READY_QUEUE.length);
    q.forEach(function (fn) { try { fn(); } catch (e) {} });
  }

  function showEditorLoading(on) {
    var el = document.getElementById("audit-ed-loading");
    if (el) el.hidden = !on;
  }
  function enableFallback(err) {
    var hint = document.getElementById("audit-ed-fallback-hint");
    if (hint) hint.hidden = false;
    showEditorLoading(false);
    toast("编辑器组件加载失败，已降级为纯文本预览", "err");
    if (window.console && console.warn) console.warn("[audit] Monaco 降级:", err && err.message);
  }
  function isFallback() {
    var ta = document.getElementById("audit-fallback");
    return !!(ta && !ta.hidden);
  }

  function ensureMonaco(cb) {
    if (monacoReady()) {
      // 超时判失败后 loader 迟到的成功：自愈回 ready，撤掉降级提示
      if (MONACO_STATE.status === "failed") {
        MONACO_STATE.status = "ready";
        MONACO_STATE.error = null;
        var hint = document.getElementById("audit-ed-fallback-hint");
        if (hint) hint.hidden = true;
        var ta = document.getElementById("audit-fallback");
        if (ta) { ta.hidden = true; ta.value = ""; }
        var empty = document.getElementById("audit-ed-empty");
        if (empty) empty.style.display = "";
      }
      if (cb) cb();
      return;
    }
    if (monacoFailed()) { if (cb) cb(); return; }
    if (MONACO_STATE.promise) {
      MONACO_STATE.promise.then(function () { if (cb) cb(); });
      return;
    }
    MONACO_STATE.status = "loading";
    showEditorLoading(true);
    MONACO_STATE.promise = new Promise(function (resolve) {
      var settled = false;
      var finish = function (ok, err) {
        if (settled) return;
        settled = true;
        MONACO_STATE.promise = null;
        if (ok && monacoReady()) {
          MONACO_STATE.status = "ready";
          showEditorLoading(false);
          flushReadyQueue();
        } else {
          MONACO_STATE.status = "failed";
          MONACO_STATE.error = err || new Error("Monaco 加载失败");
          enableFallback(MONACO_STATE.error);
          READY_QUEUE.length = 0; // 降级后丢弃 Monaco 依赖任务
        }
        resolve(MONACO_STATE.status);
      };
      var boot = function () {
        try {
          window.require.config({ paths: { vs: "/monaco/vs" } });
          window.require(["vs/editor/editor.main"],
            function () { finish(true); },
            function (e) { finish(false, e || new Error("editor.main 加载失败")); });
        } catch (e) {
          finish(false, e);
        }
      };
      // 重复进入/换页后 loader 可能已在 head：直接 require，不重复插脚本
      if (window.require && typeof window.require.config === "function" && window.__slMonacoLoader) {
        boot();
        return;
      }
      var s = document.createElement("script");
      s.src = "/monaco/vs/loader.js";
      s.async = true;
      s.setAttribute("data-sl-monaco", "loader");
      s.onload = function () {
        window.__slMonacoLoader = true;
        boot();
      };
      s.onerror = function () { finish(false, new Error("loader.js 加载失败")); };
      document.head.appendChild(s);
      setTimeout(function () {
        if (!settled && !monacoReady()) finish(false, new Error("Monaco 加载超时"));
      }, MONACO_TIMEOUT_MS);
    });
    MONACO_STATE.promise.then(function () { if (cb) cb(); });
  }

  function models() { return window.__slAuditModels || (window.__slAuditModels = {}); }
  function langOf(path) {
    var m = /\.([a-z0-9]+)$/i.exec(path);
    return (m && LANGS[m[1].toLowerCase()]) || "plaintext";
  }
  function getOrCreateModel(path, content) {
    var uri = monaco.Uri.parse("inmemory://audit/" + path);
    var m = monaco.editor.getModel(uri);
    if (m) return m;
    return monaco.editor.createModel(content || "", langOf(path), uri);
  }
  function ensureEditor() {
    var ed = window.__slAuditEditor;
    if (ed && ed._slHost && document.body.contains(ed._slHost)) { ed.layout(); return ed; }
    if (ed) { try { ed.dispose(); } catch (e) {} }
    ed = monaco.editor.create(editorEl, {
      readOnly: true, automaticLayout: true, model: null,
      fontSize: 12.5, minimap: { enabled: false }, scrollBeyondLastLine: false,
      theme: document.documentElement.classList.contains("dark") ? "vs-dark" : "vs",
      renderLineHighlight: "all", padding: { top: 10 }, lineNumbersMinChars: 3
    });
    ed._slHost = editorEl;
    var wrap = editorEl.parentElement;
    if (wrap) wrap.classList.add("ready"); // 25B：编辑器就绪淡入
    window.__slAuditEditor = ed;
    return ed;
  }

  /* ---------------- 文件树（sources → 目录树） ---------------- */
  function buildTree(paths) {
    var root = {};
    paths.forEach(function (p) {
      var parts = p.split("/");
      var cur = root;
      for (var i = 0; i < parts.length - 1; i++) {
        cur = cur[parts[i]] = cur[parts[i]] || {};
      }
      cur[parts[parts.length - 1]] = null; // 文件叶子
    });
    return root;
  }
  function renderTree(node, contents, openPath, prefix) {
    var ul = document.createElement("ul");
    Object.keys(node).sort(function (a, b) {
      var da = node[a] !== null, db = node[b] !== null; // 目录优先
      if (da !== db) return da ? -1 : 1;
      return a < b ? -1 : a > b ? 1 : 0;
    }).forEach(function (name) {
      var li = document.createElement("li");
      var child = node[name];
      var full = prefix ? prefix + "/" + name : name; // 完整相对路径（contents 的键）
      if (child !== null) {
        var dir = document.createElement("div");
        dir.className = "tw-node tw-dir";
        dir.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 14 1.5-2.9A2 2 0 0 1 9.24 9.8H12a2 2 0 0 1 1.98 1.83L14 14"/><path d="M3 12V7.82a2 2 0 0 1 .58-1.41L7.41 2.6A2 2 0 0 1 8.82 2h6.36a2 2 0 0 1 1.41.58l3.83 3.82A2 2 0 0 1 21 7.82V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg><span>' + esc(name) + "</span>";
        var sub = renderTree(child, contents, openPath, full);
        dir.addEventListener("click", function () {
          sub.style.display = sub.style.display === "none" ? "" : "none";
        });
        li.appendChild(dir);
        li.appendChild(sub);
      } else {
        var has = Object.prototype.hasOwnProperty.call(contents, full) && contents[full] !== undefined;
        var f = document.createElement("div");
        f.className = "tw-node" + (has ? "" : " no-preview");
        f.setAttribute("data-file", full);
        f.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg><span>' + esc(name) + "</span>";
        f.addEventListener("click", function () {
          if (!has) { toast("该文件无预览（二进制或未收录）", "err"); return; }
          openFile(full);
        });
        li.appendChild(f);
      }
      ul.appendChild(li);
    });
    return ul;
  }

  function openFile(path) {
    var contents = window.__slAuditContents || {};
    var content = contents[path];
    if (content === undefined) {
      // 兜底：叶子名精确匹配失败时按路径后缀找（历史响应路径差异容错）
      var cand = Object.keys(contents).filter(function (k) {
        return k === path || k.indexOf("/" + path, k.length - path.length - 1) >= 0;
      });
      if (cand.length) { path = cand[0]; content = contents[path]; }
    }
    if (content === undefined) { toast("该文件无预览内容", "err"); return; }
    ensureMonaco(function () {
      if (!monacoReady()) { openFileFallback(path, content); return; }
      var ed = ensureEditor();
      var model = getOrCreateModel(path, content);
      ed.setModel(model);
      if (edEmpty) edEmpty.style.display = "none";
      // 高亮该文件的命中行（按 path 记账，避免重复叠加）
      var decosByPath = window.__slAuditDecos || (window.__slAuditDecos = {});
      var finds = (window.__slAuditFindings || []).filter(function (f) { return f.file === path; });
      var decos = finds.map(function (f) {
        return { range: new monaco.Range(f.line, 1, f.line, 1),
          options: { isWholeLine: true, className: SEV_LINE[f.severity] || "audit-line-low" } };
      });
      var old = decosByPath[path] || [];
      decosByPath[path] = ed.deltaDecorations(old, decos);
      if (finds.length) ed.revealLineInCenter(finds[0].line);
      // 树选中态
      document.querySelectorAll("#audit-tree .tw-node.on").forEach(function (n) { n.classList.remove("on"); });
      var node = document.querySelector('#audit-tree .tw-node[data-file="' + cssEsc(path) + '"]');
      if (node) node.classList.add("on");
    });
  }
  function cssEsc(s) { return (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/"/g, '\\"'); }

  /* FE-09 降级路径：Monaco 不可用时用只读 textarea 展示源码（功能受限但不白屏） */
  function openFileFallback(path, content) {
    var ta = document.getElementById("audit-fallback");
    var hint = document.getElementById("audit-ed-fallback-hint");
    if (!ta) { toast("编辑器不可用，无法预览该文件", "err"); return; }
    ta.hidden = false;
    ta.value = content == null ? "" : String(content);
    if (hint) hint.hidden = false;
    var empty = document.getElementById("audit-ed-empty");
    if (empty) empty.style.display = "none";
    showEditorLoading(false);
    // 树选中态与 Monaco 路径保持一致
    document.querySelectorAll("#audit-tree .tw-node.on").forEach(function (n) { n.classList.remove("on"); });
    var node = document.querySelector('#audit-tree .tw-node[data-file="' + cssEsc(path) + '"]');
    if (node) node.classList.add("on");
  }

  /* 预热：为已加载内容建 models + 标注，并打开首文件（仅 Monaco 就绪后调用）。
     Turbo 换页后旧闭包里的 editorEl 已脱离文档，直接跳过，等新渲染的激活再跑。 */
  function warmModels() {
    if (!monacoReady()) return;
    if (!editorEl || !document.body.contains(editorEl)) return;
    ensureEditor();
    var contents = window.__slAuditContents || {};
    Object.keys(contents).forEach(function (path) {
      var model = getOrCreateModel(path, contents[path]);
      var marks = (window.__slAuditFindings || []).filter(function (f) { return f.file === path; })
        .map(function (f) {
          return {
            startLineNumber: f.line, endLineNumber: f.line, startColumn: 1, endColumn: 1000,
            severity: SEV_MARK[f.severity] || 2,
            message: "[" + f.severity + "] " + f.rule + " " + f.title + "\n" + (f.advice || ""),
            source: "SiteLens audit"
          };
        });
      monaco.editor.setModelMarkers(model, "audit", marks);
    });
    var sources = window.__slAuditSources || [];
    var first = sources.length ? sources[0] : null;
    if (first && contents[first] !== undefined) openFile(first);
  }
  window.__slAuditWarm = warmModels;

  /* ---------------- 审计执行与渲染 ---------------- */
  window.runAudit = function () {
    var picked = input.files;
    if (!picked.length) { dz.classList.add("drag"); return; }
    var fd = new FormData();
    [...picked].forEach(function (f) { fd.append("files", f); });
    busy(true);
    fetch("/api/audit", { method: "POST", headers: apiTok(), body: fd })
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
          return j;
        });
      })
      .then(function (r) { busy(false); render(r); })
      .catch(function (e) {
        busy(false);
        outEl.innerHTML =
          '<p style="color:var(--danger);font-size:13.5px">' + esc(e.message) + "</p>";
      });
  };

  function busy(on) {
    if (goBtn) goBtn.disabled = on;
    if (on) {
      summaryEl.style.display = "none";
      outEl.innerHTML =
        '<div class="skeleton" style="height:60px;margin-bottom:10px"></div>' +
        '<div class="skeleton" style="height:60px"></div><p class="hint">审计中…</p>';
    }
  }

  function render(r) {
    window.__slAuditContents = r.contents || {};
    // 路径归一化：审计引擎可能给绝对路径+反斜杠；统一为与 sources 一致的相对斜杠路径
    (r.findings || []).forEach(function (f) {
      var norm = String(f.file || "").replace(/\\/g, "/");
      (r.sources || []).forEach(function (s) {
        if (norm === s || norm.indexOf("/" + s, norm.length - s.length - 1) >= 0) norm = s;
      });
      f.file = norm;
    });
    window.__slAuditFindings = r.findings || [];

    var sev = r.by_severity || {};
    summaryEl.style.display = "grid";
    summaryEl.innerHTML =
      cell("扫描文件", r.files) + cell("代码行", (r.lines || 0).toLocaleString()) +
      cell("发现总数", (r.findings || []).length) +
      '<div class="cell"><span>高危</span><b><span class="badge danger">' + (sev.high || 0) + "</span></b></div>" +
      '<div class="cell"><span>中危</span><b><span class="badge warn">' + (sev.medium || 0) + "</span></b></div>" +
      '<div class="cell"><span>低危</span><b><span class="badge ok">' + (sev.low || 0) + "</span></b></div>";

    // 文件树
    var sources = r.sources || Object.keys(window.__slAuditContents);
    treeEl.innerHTML = "";
    treeEl.appendChild(renderTree(buildTree(sources), window.__slAuditContents));

    // 发现列表（可点击跳行）
    var findings = r.findings || [];
    if (!findings.length) {
      outEl.innerHTML = '<p class="muted" style="font-size:13.5px">未命中任何规则线索。</p>';
    } else {
      var html = '<div class="sec-title">审计发现 <span class="count">最多展示 120 条 · 点击跳转源码</span></div>';
      findings.slice(0, 120).forEach(function (f) {
        html += '<div class="audit-find sev-' + esc(f.severity) + '" data-file="' + esc(f.file) +
          '" data-line="' + esc(f.line) + '">' +
          '<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">' + sevBadge(f.severity) +
          '<b class="mono" style="font-size:12.5px">' + esc(f.rule) + "</b>" +
          '<span class="muted" style="font-size:12px">' + esc(f.title) + "</span></div>" +
          '<div class="mono" style="font-size:12px;word-break:break-all">' + esc(f.file) + ":" + esc(f.line) +
          ' <span class="muted">' + esc(String(f.snippet || "").slice(0, 70)) + "</span></div>" +
          '<div style="font-size:12.5px;margin-top:4px">' + esc(f.advice) + "</div></div>";
      });
      if (findings.length > 120)
        html += '<p class="hint">… 其余 ' + (findings.length - 120) + " 条略</p>";
      outEl.innerHTML = html;
      outEl.querySelectorAll(".audit-find").forEach(function (row) {
        row.addEventListener("click", function () {
          openFile(row.getAttribute("data-file"));
          var line = parseInt(row.getAttribute("data-line"), 10);
          ensureMonaco(function () {
            if (!monacoReady()) return; // 降级：openFile 已展示纯文本，跳行不可用
            var ed = ensureEditor();
            if (line) {
              ed.revealLineInCenter(line);
              ed.setPosition({ lineNumber: line, column: 1 });
              // 25B 联动反馈：目标行闪烁高亮 600ms 渐隐（一次性，非循环）
              var flash = ed.deltaDecorations([], [{ range: new monaco.Range(line, 1, line, 1),
                options: { isWholeLine: true, className: "audit-line-flash" } }]);
              setTimeout(function () { try { ed.deltaDecorations(flash, []); } catch (e) {} }, 650);
            }
          });
        });
      });
    }

    // FE-09：不在此处强制加载 Monaco（仅跑完审计不该下载 ~12MB 编辑器）。
    // 进入审计页（activateMonaco）或首次打开编辑器时才加载；就绪后预热模型+标注。
    window.__slAuditSources = sources;
    if (monacoReady()) {
      warmModels();
    } else if (monacoFailed()) {
      // 已降级：直接以纯文本展示首文件（不再等 Monaco）
      var firstPath = sources && sources.length ? sources[0] : null;
      if (firstPath && window.__slAuditContents[firstPath] !== undefined) {
        openFileFallback(firstPath, window.__slAuditContents[firstPath]);
      }
    } else {
      queueMonacoReady(warmModels);
      // 程序化入口（__slAuditRender / CDP）兜底：审计页可见时启动懒加载
      if (auditPaneActive()) activateMonaco();
    }
  }

  function cell(k, v) {
    return '<div class="cell"><span>' + esc(k) + '</span><b class="mono">' + esc(v) + "</b></div>";
  }

  /* ---------------- FE-09：懒加载触发（进入审计页 / 打开编辑器） ----------------
     触发点：
       1) common.js 模式切换点击 audit（window.slAuditActivate）；
       2) hash 路由 /audit 或 #audit（首屏直达与前进后退）；
       3) 打开文件/点击发现（openFile → ensureMonaco，已有路径）。
     幂等：ensureMonaco 单例 promise；重复进入只复用不重复下载。 */
  function auditPaneActive() {
    var h = (location.hash || "").slice(1);
    if (h === "audit") return true;
    if ((location.pathname || "").indexOf("/audit") === 0) return true;
    var pane = document.querySelector('.tw-canvaspane[data-pane="audit"]');
    return !!(pane && pane.classList.contains("active"));
  }
  function activateMonaco() {
    if (isFallback()) return; // 已降级：不反复重试
    ensureMonaco(function () {
      // 就绪后：若已有审计结果，预热模型与标注并恢复首文件
      if (monacoReady() && window.__slAuditContents &&
          Object.keys(window.__slAuditContents).length) {
        warmModels();
      }
    });
  }
  window.slAuditActivate = activateMonaco;
  window.__slAuditMonacoState = function () { return MONACO_STATE; }; // 验收/测试钩子

  // 首屏直达 / 前进后退触发（Turbo 换页重放脚本时先卸旧监听，防叠加）
  function maybeActivateFromRoute() {
    if (auditPaneActive()) activateMonaco();
  }
  if (window.__slAuditHashHandler) window.removeEventListener("hashchange", window.__slAuditHashHandler);
  window.__slAuditHashHandler = maybeActivateFromRoute;
  window.addEventListener("hashchange", window.__slAuditHashHandler);
  if (window.__slAuditClickHandler) document.removeEventListener("click", window.__slAuditClickHandler);
  window.__slAuditClickHandler = function (e) {
    var t = e.target && e.target.closest ? e.target.closest('.tab[data-tab="audit"]') : null;
    if (t) activateMonaco();
  };
  document.addEventListener("click", window.__slAuditClickHandler);
  maybeActivateFromRoute(); // 初始 hash 已是 #audit / 独立 /audit 页

  // 测试/验收钩子：CDP 直接以数据驱动渲染（不必真传文件）
  window.__slAuditRender = render;
  window.__slIngestFolder = ingestFolder;

  // 初始空态
  if (treeEl) treeEl.innerHTML = '<div class="tree-empty">上传源码并开始审计后，文件将显示在这里</div>';

  // 预热 JSZip：文件夹链路首次点击前脚本已就位，消除懒加载竞态
  ensureJsZip(function () {});
})();
