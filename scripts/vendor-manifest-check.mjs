#!/usr/bin/env node
/**
 * 第三方前端资产完整性门禁（D-13）
 *
 * 目的：让 `web/vendor/MANIFEST.md` 不再是"写完就算"的文档——台账里声明的每一个
 * sha256 / 体积 / Monaco 目录清单哈希，都在本地与 CI 被逐一实算比对。
 * 台账一旦与文件漂移（换了文件没更新台账、或改了台账却没换文件），此处直接红。
 *
 * 用法：
 *   node scripts/vendor-manifest-check.mjs
 *   退出码 0 = 全部一致（打印一行 PASS）；1 = 存在不一致（打印 期望/实际/路径）。
 *
 * 台账契约（改 MANIFEST 时必须遵守，否则本脚本会判红）：
 *   1) 逐文件完整性表：三列表格行 `| <路径> | <字节> | <sha256> |`
 *      - 路径可带反引号，字节可带千分位逗号，sha256 为 64 位小写十六进制；
 *      - 该表是**唯一真源**（同一文件的哈希不要在别处以别的格式重复出现）。
 *   2) 目录整体：一行 `文件数 **N**，总字节 **M**；` 与一行 `目录清单哈希 **`<sha256>`**`。
 *   3) 逐文件条目数等于 EXPECTED_FILE_ENTRIES（防止"整表被删"变成空校验）。
 *
 * 兼容 Node 18+（CI 镜像为 Debian 自带的 nodejs），不依赖任何第三方包。
 */
import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url)); // scripts/ 的父目录 = 仓库根
const MANIFEST_REL = "web/vendor/MANIFEST.md";
const MONACO_REL = "web/monaco";

/** 台账逐文件表应有的条目数：改动台账时同步改这里（这是"门禁不能空跑"的兜底）。 */
const EXPECTED_FILE_ENTRIES = 10;

const errors = [];
const fail = (msg) => errors.push(msg);
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const sizeNum = (s) => Number(s.replace(/,/g, ""));

if (!existsSync(join(ROOT, MANIFEST_REL))) {
  console.error(`× 找不到台账：${MANIFEST_REL}（本脚本需在仓库内运行）`);
  process.exit(1);
}
const manifest = readFileSync(join(ROOT, MANIFEST_REL), "utf8");

// ---------------------------------------------------------------- 1) 逐文件表
// 只匹配"恰好三列、最后一列是 64 位 hex"的表格行，因此不会误匹配总览表/变更记录表。
// 允许行首缩进（台账里的表嵌在列表项下，缩进 2 空格）与行尾空白/CRLF。
const ROW_RE =
  /^[ \t]*\|\s*`?([^`|\n]+?)`?\s*\|\s*([\d,]+)\s*\|\s*`?([0-9a-f]{64})`?\s*\|[ \t\r]*$/gm;
const rows = [];
for (let m; (m = ROW_RE.exec(manifest)) !== null; ) {
  rows.push({ path: m[1].trim(), size: sizeNum(m[2]), declared: m[3] });
}

if (rows.length !== EXPECTED_FILE_ENTRIES) {
  fail(
    `逐文件表条目数异常：期望 ${EXPECTED_FILE_ENTRIES} 条，实际 ${rows.length} 条` +
      `（表被删行/改格式都会触发；确属有意变更请同步 EXPECTED_FILE_ENTRIES）`
  );
}

for (const row of rows) {
  const abs = join(ROOT, row.path);
  if (!existsSync(abs)) {
    fail(`台账声明的文件不存在\n      路径=${row.path}`);
    continue;
  }
  const st = statSync(abs);
  if (!st.isFile()) {
    fail(`台账条目不是普通文件\n      路径=${row.path}`);
    continue;
  }
  if (st.size !== row.size) {
    fail(
      `体积不一致\n      路径=${row.path}\n      期望(台账)=${row.size}\n      实际(文件)=${st.size}`
    );
  }
  const actual = sha256(readFileSync(abs));
  if (actual !== row.declared) {
    fail(
      `sha256 不一致\n      路径=${row.path}\n      期望(台账)=${row.declared}\n      实际(文件)=${actual}`
    );
  }
}

// ------------------------------------------------- 2) Monaco 目录整体清单哈希
const CNT_RE = /文件数\s*\*\*(\d+)\*\*/;
const BYTES_RE = /总字节\s*\*\*([\d,]+)\*\*/;
const DIRHASH_RE = /目录清单哈希\s*\*\*`([0-9a-f]{64})`\*\*/;
const cntM = manifest.match(CNT_RE);
const bytesM = manifest.match(BYTES_RE);
const dirM = manifest.match(DIRHASH_RE);

function walk(dirAbs, acc = []) {
  for (const e of readdirSync(dirAbs, { withFileTypes: true })) {
    const abs = join(dirAbs, e.name);
    if (e.isDirectory()) walk(abs, acc);
    else if (e.isFile()) acc.push(abs);
    // 符号链接等既非目录也非普通文件的条目：不纳入清单（当前资产中不存在）
  }
  return acc;
}

if (!cntM || !bytesM || !dirM) {
  fail(
    `台账缺少目录整体记录（需要三行：文件数 **N** / 总字节 **M** / 目录清单哈希 **\`<sha256>\`**）`
  );
} else {
  const files = walk(join(ROOT, MONACO_REL));
  const totalBytes = files.reduce((n, abs) => n + statSync(abs).size, 0);
  // 清单格式与 MANIFEST §4.2 完全一致：每行 "<sha256> + 两个空格 + POSIX 相对路径"，按路径排序，
  // LF 换行、带尾随换行；对该字节串取 sha256。
  const listing = files
    .map((abs) => {
      const rel = relative(ROOT, abs).split(sep).join("/");
      return `${sha256(readFileSync(abs))}  ${rel}`;
    })
    .sort((a, b) => {
      const pa = a.slice(66); // 64 位哈希 + 两个空格
      const pb = b.slice(66);
      return pa < pb ? -1 : pa > pb ? 1 : 0;
    });
  const payload = Buffer.from(listing.join("\n") + "\n", "utf8");
  const dirHash = sha256(payload);

  const declaredCount = Number(cntM[1]);
  const declaredBytes = sizeNum(bytesM[1]);
  if (files.length !== declaredCount) {
    fail(
      `Monaco 文件数不一致\n      路径=${MONACO_REL}/\n      期望(台账)=${declaredCount}\n      实际(目录)=${files.length}`
    );
  }
  if (totalBytes !== declaredBytes) {
    fail(
      `Monaco 总字节不一致\n      路径=${MONACO_REL}/\n      期望(台账)=${declaredBytes}\n      实际(目录)=${totalBytes}`
    );
  }
  if (dirHash !== dirM[1]) {
    fail(
      `Monaco 目录清单哈希不一致（有文件被增删改）\n      路径=${MONACO_REL}/（${files.length} 文件）\n` +
        `      期望(台账)=${dirM[1]}\n      实际(目录)=${dirHash}`
    );
  }
}

// ------------------------------------------------------------------- 3) 结果
if (errors.length > 0) {
  console.error("× web/vendor 台账校验失败（第三方前端资产完整性，D-13）：");
  for (const e of errors) console.error("  - " + e);
  console.error(
    "\n修复方式：按 web/vendor/README.md「3. 更新台账」重算并更新 MANIFEST.md；" +
      "若是资产文件被误改，还原文件即可。"
  );
  process.exit(1);
}

console.log(
  `PASS web/vendor 台账一致：${rows.length} 个逐文件 sha256 + Monaco 目录清单` +
    `（${manifest.match(CNT_RE)[1]} 文件 / ${manifest.match(BYTES_RE)[1]} 字节 / ` +
    `${manifest.match(DIRHASH_RE)[1].slice(0, 12)}…）`
);
