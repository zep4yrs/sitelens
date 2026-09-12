// 桌面壳的 .sitelens.yml 合并器（纯函数，无依赖，node:test 可测）。
//
// 职责：壳只管理少数「壳语义」键（监听端口、数据目录、资产路径），
// 其余键（含用户经设置页保存的引擎配置、注释、未知键）原样保留——
// 此前整文件覆盖是 P0：用户保存的任何引擎配置重启即被抹掉。
//
// 合并语义（与引擎 config.UpsertYAMLSections 的保守精神一致）：
//   - 仅处理两层结构：顶层段（/^\S/）+ 段内键（缩进 ≥2 的 key: value）
//   - 受管键：存在则原位替换值；不存在则追加到段尾
//   - 段不存在则整段追加到文件末尾
//   - 注释、空行、未受管键一律原样保留
//   - 路径值统一双引号 + 正斜杠（YAML 双引号下反斜杠转义是已知坑）
"use strict";

// managed[段][键] = 值（字符串；数字/布尔请先转 String）
function mergeManaged(source, managed) {
  var lines = source === "" ? [] : String(source).split("\n");
  var out = [];
  var seenSection = {};   // 段名 → 是否在文件中出现
  var seenKey = {};       // "段.键" → 是否已替换
  var current = "";       // 当前所在段名

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var sec = line.match(/^([A-Za-z_][\w-]*):\s*(#.*)?$/);
    if (sec) {
      current = sec[1];
      seenSection[current] = true;
      out.push(line);
      continue;
    }
    var kv = line.match(/^(\s+)([A-Za-z_][\w-]*):(\s+)(.*)$/);
    if (kv && managed[current] && Object.prototype.hasOwnProperty.call(managed[current], kv[2])) {
      seenKey[current + "." + kv[2]] = true;
      out.push(kv[1] + kv[2] + ": " + formatValue(managed[current][kv[2]]));
      continue;
    }
    out.push(line);
  }

  // 追加缺失的受管键 / 整段
  Object.keys(managed).forEach(function (section) {
    var keys = managed[section];
    if (!seenSection[section]) {
      if (out.length && out[out.length - 1].trim() !== "") out.push("");
      out.push(section + ":");
      Object.keys(keys).forEach(function (k) {
        out.push("  " + k + ": " + formatValue(keys[k]));
      });
      seenSection[section] = true;
      Object.keys(keys).forEach(function (k) { seenKey[section + "." + k] = true; });
      return;
    }
    Object.keys(keys).forEach(function (k) {
      if (!seenKey[section + "." + k]) {
        // 找到该段最后一行（含其缩进子行）之后插入
        var at = lastLineOfSection(out, section);
        out.splice(at + 1, 0, "  " + k + ": " + formatValue(keys[k]));
      }
    });
  });

  return out.join("\n");
}

// lastLineOfSection 返回段内最后一行的下标（段头起直到下一个顶层键前）。
function lastLineOfSection(lines, section) {
  var header = section + ":";
  var at = -1;
  for (var i = 0; i < lines.length; i++) {
    if (lines[i] === header || lines[i].indexOf(header + " ") === 0) {
      at = i;
      continue;
    }
    if (at >= 0) {
      if (/^\S/.test(lines[i])) break;      // 下一个顶层段：结束
      if (lines[i].trim() !== "") at = i;   // 段内子行（含注释）
    }
  }
  return at;
}

function formatValue(v) {
  return quoteIfNeeded(String(v));
}

// quoteIfNeeded 路径类值加双引号（正斜杠形态，无双引号转义问题）。
function quoteIfNeeded(v) {
  return '"' + v.replace(/\\/g, "/") + '"';
}

module.exports = { mergeManaged: mergeManaged, quoteIfNeeded: quoteIfNeeded };
