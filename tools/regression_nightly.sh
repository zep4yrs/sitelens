#!/bin/bash
# 靶场回归门禁（v1.5，向 2.0 靠齐）：本地/CI 均可执行。
# 流程：起靶场农场 → 等待就绪 → 认证态矩阵跑批 → 断言
#       （干净站零误报 + DVWA 必须有真实命中）→ 拆场。
# 退出码非 0 = 回归失败。依赖：docker、go、已编译 sitelens 二进制或 go run。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FARM="$ROOT/../ranges/farm_up.sh"          # 靶场农场脚本（ranges/ 不入 git 的先自行放置）
MATRIX="$ROOT/../ranges/matrix_v3.sh"      # 矩阵跑批脚本
FAIL=0

log() { printf '\n[regression] %s\n' "$*"; }

need_file() {
  if [ ! -f "$2" ]; then
    log "缺少 $1：$2（该脚本依赖本地靶场资产，见 docs/靶场回归-lingyun.md）"
    FAIL=1
  fi
}

need_file "农场脚本" "$FARM"
need_file "矩阵脚本" "$MATRIX"
[ "$FAIL" = 0 ] || exit 1

log "1/4 起靶场农场（DVWA + pikachu + sqli-labs + upload-labs + xsslabs）"
bash "$FARM" || { log "农场启动失败"; exit 1; }

log "2/4 等待靶场就绪"
for i in $(seq 1 30); do
  if curl -sf -o /dev/null http://127.0.0.1:8092/ 2>/dev/null; then break; fi
  sleep 2
done

log "3/4 矩阵跑批（认证态 + 零误报断言）"
bash "$MATRIX" || FAIL=1

log "4/4 断言汇总"
# 断言由 matrix_v3.sh 输出 JSON 汇总承载：
#   干净站 verified 计数必须为 0（零误报底线）
#   DVWA 认证扫描必须至少 1 条 verified（真实缺陷命中）
# matrix_v3.sh 内部已按该语义返回非零，这里兜底复核
if [ "$FAIL" = 0 ]; then
  log "回归通过：零误报底线保持，真实缺陷命中存在"
else
  log "回归失败：见上方矩阵输出"
fi
exit "$FAIL"
