#!/bin/bash
# SiteLens 本地发版（v3.0.1 起为唯一发版路径）。
#
# 为什么改成本地发版：CI 跑在 Linux（golang 镜像），而 build-engine.js 曾执行
# 不带 GOOS 的 go build —— 打出的「sitelens.exe」实为 Linux ELF，装进 Windows
# 安装包后引擎永远起不来（v3.0.0 真实事故）。本地在 Windows 上构建产物必为 PE，
# 且能在打包前后即时验证。CI 的 tag 流水线已停用（见 .cnb.yml）。
#
# 用法：
#   tools/release_local.sh              # 构建 + 校验 + 打包（不发布）
#   tools/release_local.sh --publish    # 再上传 CNB Release（需 CNB_TOKEN）
#
# 前置：Go 1.26+、Node 18+、npm；desktop 依赖已安装（npm ci）。
# 产物：desktop/release/SiteLens-Setup-<ver>.exe（+ .blockmap + latest.yml）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DESKTOP="$ROOT/desktop"
PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

cd "$DESKTOP"
VER="$(node -p "require('./package.json').version")"
TAG="v$VER"
echo "== SiteLens 本地发版：$VER（tag $TAG）=="

# 1) 引擎载荷：显式 GOOS=windows + PE 魔数校验（build-engine.js 内置硬闸）。
echo "== [1/4] 构建引擎载荷 =="
node build-engine.js

# 2) 产物平台复验（双保险：脚本已校验，这里再独立确认一次）。
echo "== [2/4] 校验引擎为 Windows PE =="
head2="$(head -c2 "$DESKTOP/engine/sitelens.exe")"
if [ "$head2" != "MZ" ]; then
  echo "× 引擎产物不是 Windows PE（文件头非 MZ）。当前构建机：$(uname -s)"
  echo "  修复：确保 GOOS=windows GOARCH=amd64（build-engine.js 已设；若手动构建请自行指定）"
  exit 1
fi
echo "  ✓ PE 头正确"
"$DESKTOP/engine/sitelens.exe" -version

# 3) 打包 NSIS 安装包（跳过 exe 图标改写/签名，与 CI 同参）。
echo "== [3/4] 打包安装包 =="
npx electron-builder --win nsis --publish never -c.win.signAndEditExecutable=false

EXE="$DESKTOP/release/SiteLens-Setup-$VER.exe"
[ -f "$EXE" ] || { echo "× 未产出安装包：$EXE"; exit 1; }
echo "  ✓ 安装包：$EXE（$(stat -c%s "$EXE" 2>/dev/null || wc -c <"$EXE") bytes）"

# 4) 可选：上传 CNB Release（版本 release 三件套）。
if [ "$PUBLISH" = "1" ]; then
  echo "== [4/4] 上传 CNB Release =="
  : "${CNB_TOKEN:?需要 CNB_TOKEN 环境变量（CNB 访问令牌）}"
  export SITLENS_TAG="$TAG"
  BODY="$ROOT/tools/release-body-$VER.md"
  [ -f "$BODY" ] && export SITLENS_BODY_FILE="$BODY"
  bash "$ROOT/tools/release_upload.sh" \
    "$EXE" \
    "$EXE.blockmap" \
    "$DESKTOP/release/latest.yml"
  echo "  ✓ 已上传（含发行说明：${SITLENS_BODY_FILE:-无}）"
else
  echo "== [4/4] 跳过上传（加 --publish 启用；需 CNB_TOKEN）=="
fi

echo "== 完成：$TAG =="
cat <<EOF

后续（更新源，唯一来源在 GitHub desktop-stable）：
  1) 把三件套上传到 GitHub desktop-stable release：
     SiteLens-Setup-$VER.exe / .exe.blockmap / latest.yml
  2) 用户端「设置 → 检查更新」即可增量（blockmap）或全量升级。
EOF
