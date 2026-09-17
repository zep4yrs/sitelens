/* 源码静态审计（25A 升级版）：上传 → /api/audit → 文件树 + Monaco 预览 + 标注跳转。
   工作台模式与独立 /audit 页共用；ID 统一 audit- 前缀。
   Monaco 懒加载（/monaco/vs 本地路径，零 CDN）；models 按 URI 常驻——
   Turbo 切走再切回，文件内容与标注不丢。只读预览：审计线索需人工复查。 */
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

  // 把目录文件集打包 zip（JSZip，页内生成），rootName 为顶层目录名
  function ingestFolder(files, rootName) {
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

    ensureJsZip(function () {
      var zip = new JSZip();
      kept.forEach(function (f) {
        zip.file(rootName + "/" + f.__rel, f);
      });
      zip.generateAsync({ type: "blob", compression: "DEFLATE" }).then(function (blob) {
        var dt = new DataTransfer();
        dt.items.add(new File([blob], rootName + ".zip", { type: "application/zip" }));
        input.files = dt.files;
        showNames();
        toast("目录已打包：" + kept.length + " 个文件，可开始审计", "ok");
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
                f.__rel = f.webkitRelativePath || en.fullPath.replace(/^\//, "");
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

  var jszipLoading = null;
  function ensureJsZip(cb) {
    if (window.JSZip) { cb(); return; }
    if (jszipLoading) { jszipLoading.then(cb); return; }
    jszipLoading = new Promise(function (resolve) {
      var s = document.createElement("script");
      s.src = "/js/jszip.min.js";
      s.onload = resolve;
      s.onerror = resolve;
      document.head.appendChild(s);
    });
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

  /* ---------------- Monaco 懒加载 / 单例 / models ---------------- */
  var monacoLoading = null;

  function ensureMonaco(cb) {
    if (window.monaco && window.monaco.editor) { cb(); return; }
    if (monacoLoading) { monacoLoading.then(cb); return; }
    monacoLoading = new Promise(function (resolve) {
      var s = document.createElement("script");
      s.src = "/monaco/vs/loader.js";
      s.onload = function () {
        require.config({ paths: { vs: "/monaco/vs" } });
        require(["vs/editor/editor.main"], function () { resolve(); });
      };
      document.head.appendChild(s);
    });
    monacoLoading.then(cb);
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
          if (!has) { toast("该文件无预览（二进制或超过 512KB）", "err"); return; }
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

  /* ---------------- 审计执行与渲染 ---------------- */
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

    // 预加载 Monaco 与文件模型（含标注），首文件自动打开
    ensureMonaco(function () {
      var ed = ensureEditor();
      Object.keys(window.__slAuditContents).forEach(function (path) {
        var model = getOrCreateModel(path, window.__slAuditContents[path]);
        var marks = window.__slAuditFindings.filter(function (f) { return f.file === path; })
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
      var first = sources && sources.length ? sources[0] : null;
      if (first && window.__slAuditContents[first] !== undefined) openFile(first);
    });
  }

  function cell(k, v) {
    return '<div class="cell"><span>' + esc(k) + '</span><b class="mono">' + esc(v) + "</b></div>";
  }

  // 测试/验收钩子：CDP 直接以数据驱动渲染（不必真传文件）
  window.__slAuditRender = render;
  window.__slIngestFolder = ingestFolder;

  // 初始空态
  treeEl.innerHTML = '<div class="tree-empty">上传源码并开始审计后，文件将显示在这里</div>';
})();
