#!/bin/bash
# SiteLens 本地发版（v3.0.1 起为唯一发版路径）。
#
# 交付线（v5.1.0 起）：**Wails 壳**（desktop-wails/）。Electron 壳（desktop/）
# 保留为历史形态，不再作为发版产物——切换原因见 README「交付形态」与
# docs/开发文档-4.0.md §26.25（分发体积 11.9MB 单文件 vs ~100MB 安装包）。
#
# 为什么本地发版：CI 跑在 Linux（golang 镜像），跨平台构建的 Windows 产物
# 曾在无 GOOS 时被误打成 Linux ELF（v3.0.0 真实事故）。本地构建 + PE 魔数校验
# 能在打包前后即时验证，不依赖 CI 平台假设。CI 的 tag 流水线已停用（见 .cnb.yml）。
#
# 用法：
#   tools/release_local.sh              # 构建 + 校验 + 打包（不发布）
#   tools/release_local.sh --publish    # 再上传 CNB Release（需 CNB_TOKEN）
#
# 前置：Go 1.26+、makensis（Linux 上打 NSIS 需 wine+xvfb-run，见 tools/ci_nsis_exe.sh）。
# 产物：dist/release/SiteLens-Setup-<ver>.exe
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

# 版本号单一来源：desktop-wails/version.go（已退役 Electron 壳的 package.json
# 见 .archive/desktop-electron/，不再是版本权威）。
VER="$(grep -oP 'const Version = "\K[0-9.]+' "$ROOT/desktop-wails/version.go" | head -1)"
TAG="v$VER"
echo "== SiteLens 本地发版（Wails 线）：$VER（tag $TAG）=="

# 1) 构建壳 + 引擎载荷（脚本内置 PE 魔数校验 + 壳/引擎版本一致性硬闸）。
echo "== [1/4] 构建壳与引擎载荷 =="
bash "$ROOT/tools/wails_build.sh"

STAGE="$ROOT/dist/wails/SiteLens"
[ -f "$STAGE/sitelens.exe" ] || { echo "× 壳产物缺失：$STAGE/sitelens.exe" >&2; exit 1; }
# 5.2 起引擎与 CLI 拆成两个二进制：引擎产物名是 sitelens-engine.exe
[ -f "$STAGE/engine/sitelens-engine.exe" ] || { echo "× 引擎产物缺失：$STAGE/engine/sitelens-engine.exe" >&2; exit 1; }

# 2) 平台复验（双保险：构建脚本已校验，这里再独立确认一次产物布局）。
echo "== [2/4] 校验产物为 Windows PE =="
for f in "$STAGE/sitelens.exe" "$STAGE/engine/sitelens-engine.exe"; do
  head2="$(head -c2 "$f")"
  [ "$head2" = "MZ" ] || { echo "× $f 非 Windows PE（文件头非 MZ）" >&2; exit 1; }
done
echo "  ✓ 壳 + 引擎 PE 头正确"

# 3) 打包 NSIS 安装包（复用 desktop-wails/installer/installer.nsi；Linux 上经 ci_nsis_exe.sh
#    套 xvfb-run，无 display driver 时 32 位引导程序必秒退）。
echo "== [3/4] 打包安装包 =="
mkdir -p "$ROOT/dist/release"
OUTFILE="$ROOT/dist/release/SiteLens-Setup-$VER.exe"
bash "$ROOT/tools/ci_nsis_exe.sh" \
  -DVERSION="$VER" \
  -DSRCDIR="$ROOT/dist/wails" \
  -DSTAGEDIR="SiteLens" \
  -DOUTFILE="$OUTFILE" \
  "$ROOT/desktop-wails/installer/installer.nsi"
[ -s "$OUTFILE" ] || { echo "× 未产出安装包：$OUTFILE" >&2; exit 1; }
echo "  ✓ 安装包：$OUTFILE（$(stat -c%s "$OUTFILE" 2>/dev/null || wc -c <"$OUTFILE") bytes）"

# 4) 可选：上传 CNB Release（版本 release 三件套）。
if [ "$PUBLISH" = "1" ]; then
  echo "== [4/4] 上传 CNB Release =="
  : "${CNB_TOKEN:?需要 CNB_TOKEN 环境变量（CNB 访问令牌）}"
  export SITLENS_TAG="$TAG"
  BODY="$ROOT/docs/release-$VER/release-body-$VER.md"
[ -f "$BODY" ] || BODY="$ROOT/tools/release-body-$VER.md"
  [ -f "$BODY" ] && export SITLENS_BODY_FILE="$BODY"
  bash "$ROOT/tools/release_upload.sh" "$OUTFILE"
  echo "  ✓ 已上传（含发行说明：${SITLENS_BODY_FILE:-无}）"
else
  echo "== [4/4] 跳过上传（加 --publish 启用；需 CNB_TOKEN）=="
fi

echo "== 完成：$TAG =="
