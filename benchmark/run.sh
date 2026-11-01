#!/usr/bin/env bash
# CP-04 基准评测批量执行器（Linux/macOS / Git Bash；零第三方依赖，JSON 目标清单与评分需要 node）。
#
# 与 run.ps1 等价：按目标清单逐条调用 `sitelens scan`，原始 JSON 落
#   <out>/raw/<id>.json（stderr 落 <id>.log），汇总 <out>/summary.csv，
#   并写 run-meta.json 冻结版本/配置哈希。评测口径与判分见 benchmark/README.md。
#
# 示例：
#   ./benchmark/run.sh --targets benchmark/targets/lab-matrix.sample.json --mode standard
#   ./benchmark/run.sh --targets targets.txt --out eval/2026Q4 --limit 5 --dry-run
#
# 参数：
#   --targets <file>   目标清单（.json = {suite,version,targets:[{id,url}]}；.txt = 每行 "url" 或 "id url"，# 注释）
#   --out <dir>        输出目录（默认 benchmark/out/<suite>-<mode>-<时间戳>）
#   --mode <m>         fast | standard | deep（对应 profiles/<m>.yml）
#   --sitelens <path>  可执行文件（默认自动找 repo 根 sitelens / bin/dist / PATH）
#   --config <file>    自定义配置（覆盖 --mode profile；冻结口径时固定写死）
#   --truth <file>     若给出且本机有 node，跑完自动评分
#   --timeout <sec>    单目标硬超时（默认 0=不限；Linux 用 coreutils timeout，macOS 需 gtimeout）
#   --limit <n>        只跑前 n 个目标（冒烟）
#   --resume           跳过已有 raw/<id>.json 的目标
#   --dry-run          只打印将执行的命令
#   -h, --help         帮助
#
# 退出码：0 完成；1 有目标执行失败或评分失败；2 参数/环境错误。

set -uo pipefail

BENCH_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname -- "$BENCH_DIR")"
NODE_BIN="$(command -v node || command -v node.exe || true)"

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

fail() {
    echo "错误：$*" >&2
    exit 2
}

TARGETS=""
OUT=""
MODE="standard"
SITELENS=""
CONFIG=""
TRUTH=""
TIMEOUT_SEC=0
LIMIT=0
RESUME=0
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --targets) TARGETS="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --mode) MODE="${2:-}"; shift 2 ;;
        --sitelens) SITELENS="${2:-}"; shift 2 ;;
        --config) CONFIG="${2:-}"; shift 2 ;;
        --truth) TRUTH="${2:-}"; shift 2 ;;
        --timeout) TIMEOUT_SEC="${2:-0}"; shift 2 ;;
        --limit) LIMIT="${2:-0}"; shift 2 ;;
        --resume) RESUME=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) fail "未知参数：$1" ;;
    esac
done

[ -n "$TARGETS" ] || fail "缺少 --targets <targets.json|targets.txt>（样例见 benchmark/targets/）"
[ -f "$TARGETS" ] || fail "目标清单不存在：$TARGETS"
case "$MODE" in fast | standard | deep) ;; *) fail "--mode 只接受 fast|standard|deep" ;; esac

if [ -n "$CONFIG" ]; then
    [ -f "$CONFIG" ] || fail "配置不存在：$CONFIG"
    CONFIG_PATH="$CONFIG"
else
    CONFIG_PATH="$BENCH_DIR/profiles/$MODE.yml"
    [ -f "$CONFIG_PATH" ] || fail "缺少 profile：$CONFIG_PATH"
fi

resolve_sitelens() {
    if [ -n "$SITELENS" ]; then
        if [ -f "$SITELENS" ]; then echo "$SITELENS"; return; fi
        local cmd
        cmd="$(command -v "$SITELENS" || true)"
        [ -n "$cmd" ] && { echo "$cmd"; return; }
        fail "找不到 sitelens 可执行文件：$SITELENS"
    fi
    local c
    for c in "$REPO_ROOT/sitelens" "$REPO_ROOT/sitelens.exe" "$REPO_ROOT/bin/sitelens" "$REPO_ROOT/dist/sitelens"; do
        [ -f "$c" ] && { echo "$c"; return; }
    done
    c="$(command -v sitelens || command -v sitelens.exe || true)"
    [ -n "$c" ] && { echo "$c"; return; }
    fail "未找到 sitelens：请先 go build -o sitelens ./cmd/sitelens，或用 --sitelens 指定"
}
SITELENS_EXE="$(resolve_sitelens)" || exit 2

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

now_ms() {
    local t
    t="$(date +%s%3N 2>/dev/null || true)"
    case "$t" in
        "" | *[!0-9]*) echo $(($(date +%s) * 1000)) ;;
        *) echo "$t" ;;
    esac
}

csv_escape() {
    local v="${1:-}"
    if [[ "$v" == *","* || "$v" == *'"'* || "$v" == *$'\n'* ]]; then
        v="\"${v//\"/\"\"}\""
    fi
    printf '%s' "$v"
}

# 目标清单 → TSV（首行 "#suite<TAB>名字"）
list_targets() {
    case "${TARGETS,,}" in
        *.json)
            [ -n "$NODE_BIN" ] || fail "JSON 目标清单需要 node（或用 .txt 目标清单）"
            "$NODE_BIN" -e '
const fs = require("fs");
const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const items = j.targets || [];
if (items.length === 0) { console.error("targets 为空"); process.exit(1); }
console.log("#suite\t" + (j.suite || ""));
const seen = new Set();
items.forEach((t, i) => {
  const id = String(t.id || ("t" + String(i + 1).padStart(4, "0"))).trim();
  if (seen.has(id)) { console.error("目标 id 重复：" + id); process.exit(1); }
  seen.add(id);
  if (!t.url) { console.error("第 " + (i + 1) + " 项缺少 url"); process.exit(1); }
  console.log(id + "\t" + String(t.url).trim());
});
' "$TARGETS" || fail "目标清单解析失败：$TARGETS"
            ;;
        *)
            awk 'BEGIN { c = 0 }
                 { sub(/^[ \t]+/, ""); sub(/[ \t]+$/, ""); if ($0 == "" || substr($0, 1, 1) == "#") next;
                   n = split($0, a, /[ \t]+/);
                   if (n == 1) { c++; printf "t%04d\t%s\n", c, a[1]; }
                   else printf "%s\t%s\n", a[1], a[2] }' "$TARGETS"
            ;;
    esac
}

SUITE="$(list_targets | sed -n '1s/^#suite\t//p')"
[ -n "$SUITE" ] || SUITE="$(basename "$TARGETS")"
MAPFILE=()
while IFS=$'\t' read -r id url; do
    [ -z "$id" ] && continue
    [ "$id" = "#suite" ] && continue
    MAPFILE+=("$id" "$url")
done < <(list_targets)
TOTAL=$((${#MAPFILE[@]} / 2))
[ "$TOTAL" -gt 0 ] || fail "目标清单为空：$TARGETS"
if [ "$LIMIT" -gt 0 ] && [ "$LIMIT" -lt "$TOTAL" ]; then TOTAL="$LIMIT"; fi

if [ -n "$OUT" ]; then
    RUN_DIR="$OUT"
else
    STAMP="$(date +%Y%m%d-%H%M%S)"
    RUN_DIR="$BENCH_DIR/out/${SUITE}-${MODE}-${STAMP}"
fi
RAW_DIR="$RUN_DIR/raw"
mkdir -p "$RAW_DIR"

if [ "$DRY_RUN" -eq 0 ]; then
    EXE_VER="$("$SITELENS_EXE" -version 2>/dev/null | head -1 || true)"
    cat > "$RUN_DIR/run-meta.json" <<EOF
{
  "product": "SiteLens",
  "suite": "$(printf '%s' "$SUITE" | sed 's/"/\\"/g')",
  "mode": "$MODE",
  "targets": $TOTAL,
  "targetsFile": "$(printf '%s' "$TARGETS" | sed 's/"/\\"/g')",
  "targetsSha256": "$(sha256_of "$TARGETS")",
  "config": "$(printf '%s' "$CONFIG_PATH" | sed 's/"/\\"/g')",
  "configSha256": "$(sha256_of "$CONFIG_PATH")",
  "sitelens": "$(printf '%s' "$SITELENS_EXE" | sed 's/"/\\"/g')",
  "sitelensVer": "$(printf '%s' "$EXE_VER" | sed 's/"/\\"/g')",
  "timeoutSec": $TIMEOUT_SEC,
  "limit": $LIMIT,
  "host": "$(hostname 2>/dev/null || true)",
  "platform": "$(uname -srm 2>/dev/null || true)",
  "startedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
fi

echo "SiteLens CP-04 benchmark"
echo "  suite   : $SUITE"
echo "  mode    : $MODE（config=$CONFIG_PATH）"
echo "  sitelens: $SITELENS_EXE"
echo "  targets : $TOTAL"
echo "  out     : $RUN_DIR"
echo ""

CSV="$RUN_DIR/summary.csv"
printf 'target_id,url,exit_code,duration_ms,verified,vulnerabilities,error\n' > "$CSV"

FAILED=0
INDEX=0
i=0
while [ "$i" -lt "$TOTAL" ]; do
    ID="${MAPFILE[$((i * 2))]}"
    URL="${MAPFILE[$((i * 2 + 1))]}"
    i=$((i + 1))
    INDEX=$((INDEX + 1))
    RAW_FILE="$RAW_DIR/$ID.json"
    LOG_FILE="$RAW_DIR/$ID.log"

    if [ "$RESUME" -eq 1 ] && [ -f "$RAW_FILE" ]; then
        echo "[$INDEX/$TOTAL] $ID 跳过（--resume，已有 raw）"
        printf '%s,%s,,,,\n' "$(csv_escape "$ID")" "$(csv_escape "$URL")" >> "$CSV"
        continue
    fi

    QUOTED_URL="$(printf '%q' "$URL")"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "DRY-RUN: $(printf '%q' "$SITELENS_EXE") -config $(printf '%q' "$CONFIG_PATH") scan $(printf '%q' "$URL") 1> $(printf '%q' "$RAW_FILE") 2> $(printf '%q' "$LOG_FILE")"
        continue
    fi

    echo "[$INDEX/$TOTAL] $ID  $URL"
    START_MS="$(now_ms)"
    EXIT_CODE=0
    if [ "$TIMEOUT_SEC" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
        timeout -s KILL "$TIMEOUT_SEC" "$SITELENS_EXE" -config "$CONFIG_PATH" scan "$URL" > "$RAW_FILE" 2> "$LOG_FILE"
        EXIT_CODE=$?
    else
        "$SITELENS_EXE" -config "$CONFIG_PATH" scan "$URL" > "$RAW_FILE" 2> "$LOG_FILE"
        EXIT_CODE=$?
    fi
    END_MS="$(now_ms)"
    DURATION_MS=$((END_MS - START_MS))
    [ "$DURATION_MS" -ge 0 ] 2>/dev/null || DURATION_MS=0

    VERIFIED=""
    VULNS=""
    RAW_ERR=""
    if [ -n "$NODE_BIN" ] && [ -f "$RAW_FILE" ]; then
        COUNTS="$("$NODE_BIN" -e '
const fs = require("fs");
try {
  const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const v = Array.isArray(j.verified) ? j.verified.length : 0;
  const w = Array.isArray(j.vulnerabilities) ? j.vulnerabilities.length : 0;
  const e = typeof j.error === "string" ? j.error : "";
  console.log(v + "\t" + w + "\t" + e.replace(/[\t\r\n]+/g, " "));
} catch (e) {
  console.log("\t\traw JSON 解析失败");
}' "$RAW_FILE" 2>/dev/null || true)"
        IFS=$'\t' read -r VERIFIED VULNS RAW_ERR <<< "$COUNTS"
    fi
    ERR_MSG=""
    if [ "$EXIT_CODE" -eq 124 ] || [ "$EXIT_CODE" -eq 137 ]; then
        ERR_MSG="timeout>${TIMEOUT_SEC}s"
    elif [ "$EXIT_CODE" -ne 0 ]; then
        ERR_MSG="exit=$EXIT_CODE"
    fi
    [ -n "$RAW_ERR" ] && ERR_MSG="${ERR_MSG:+$ERR_MSG; }$RAW_ERR"
    [ "$EXIT_CODE" -ne 0 ] && FAILED=$((FAILED + 1))

    printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_escape "$ID")" "$(csv_escape "$URL")" "$EXIT_CODE" "$DURATION_MS" \
        "$(csv_escape "$VERIFIED")" "$(csv_escape "$VULNS")" "$(csv_escape "$ERR_MSG")" >> "$CSV"
    echo "    exit=$EXIT_CODE  ${DURATION_MS}ms  verified=${VERIFIED:-?}  vulns=${VULNS:-?}"
done

if [ "$DRY_RUN" -eq 1 ]; then
    exit 0
fi

echo ""
echo "完成：$INDEX/$TOTAL 个目标（失败 $FAILED）→ $RUN_DIR"
echo "  raw     : $RAW_DIR"
echo "  summary : $CSV"

if [ -n "$TRUTH" ]; then
    [ -f "$TRUTH" ] || fail "truth 文件不存在：$TRUTH"
    if [ -n "$NODE_BIN" ]; then
        echo ""
        echo "评分：node benchmark/score.mjs"
        "$NODE_BIN" "$BENCH_DIR/score.mjs" --raw "$RAW_DIR" --truth "$TRUTH" --out "$RUN_DIR/score" || exit 1
    else
        echo "提示：未找到 node，评分请手动运行 node benchmark/score.mjs --raw \"$RAW_DIR\" --truth \"$TRUTH\" --out \"$RUN_DIR/score\""
    fi
else
    echo ""
    echo "下一步评分（示例）："
    echo "  node benchmark/score.mjs --raw \"$RAW_DIR\" --truth <ground-truth.json> --out \"$RUN_DIR/score\""
fi

[ "$FAILED" -eq 0 ] || exit 1
exit 0
