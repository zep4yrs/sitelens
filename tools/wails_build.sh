#!/bin/bash
# 构建 Wails 桌面壳（正式交付线，v5.1.0 起）。
#
# 产物布局（安装器 staging）：
#   dist/wails/SiteLens/
#     sitelens.exe         ← Wails 壳（注意：安装器里就叫 sitelens.exe，
#                             与引擎同名会冲突，故壳落 dist 时重命名，见下）
#     engine/sitelens.exe  ← 引擎单二进制
#     engine/data/...      ← 只读资产（NVD/情报/指纹/字典/ML 资产/onnxruntime.dll）
#
# 为什么壳与引擎都叫 sitelens.exe：安装器快捷方式/注册表 DisplayIcon 指向
# $INSTDIR\sitelens.exe（installer.nsi），托盘/任务管理器也认这个名字。壳是
# 用户直接启动的入口，引擎在 engine/ 子目录里、由壳拉起，两者不同目录不冲突。
#
# 平台约束：产物必须是 Windows PE（v3.0.0 真实事故：CI 在 Linux 上打出 ELF
# 装进 Windows 包后引擎永不启动）。本脚本显式 GOOS=windows + PE 魔数校验，
# 且校验在打包前——错平台直接失败，不进安装包。
#
# 用法：tools/wails_build.sh [--engine-only]
#   默认：构建壳 + 引擎 + 暂存载荷到 dist/wails/SiteLens/
#   --engine-only：只构建引擎与载荷（发版脚本前置校验用）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/wails/SiteLens"
SHELL_OUT="$ROOT/dist/wails/SiteLens"
ENGINE_DIR="$OUT/engine"
# staging 根：installer.nsi 以 -DSRCDIR 为源根，同时取 installer/notice.txt
# （许可页）与 <STAGEDIR>/*（程序体）。故这里把 installer/ 一并暂存到
# dist/wails/ 下，安装器源根 = dist/wails。
STAGE_ROOT="$ROOT/dist/wails"

need() { command -v "$1" >/dev/null 2>&1 || { echo "× 缺少 $1，请先安装" >&2; exit 1; }; }
need go

echo "== 构建 Wails 桌面壳 =="
rm -rf "$STAGE_ROOT"
mkdir -p "$ENGINE_DIR/data"

# 许可页素材：安装器取 ${SRCDIR}/installer/notice.txt，随源根暂存。
mkdir -p "$STAGE_ROOT/installer"
cp "$ROOT/installer/notice.txt" "$STAGE_ROOT/installer/notice.txt"

# 1) 壳：CGO_ENABLED=0 纯 Go（Wails v3 + WebView2，无需 C 工具链）。
#    -H windowsgui：GUI 子系统，不弹控制台窗口。
#    -s -w：去符号/调试信息（11.9MB 单文件量级）。
( cd "$ROOT/desktop-wails" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -ldflags "-s -w -H windowsgui" -o "$SHELL_OUT/sitelens.exe" . )

# 2) 引擎：复用 desktop/build-engine.js 的构建与硬闸（PE 校验 / ML 资产硬闸 /
#    onnxruntime.dll 装箱），保证两条壳共用同一份引擎产物契约。
#    产物落 desktop/engine/，再拷进 staging 的 engine/。
echo "== 构建引擎载荷（复用 desktop/build-engine.js）=="
( cd "$ROOT/desktop" && node build-engine.js )
cp -r "$ROOT/desktop/engine/." "$ENGINE_DIR/"

# 3) PE 魔数校验（壳 + 引擎都要过——错平台二进制进包是 v3.0.0 事故的根因）。
for f in "$SHELL_OUT/sitelens.exe" "$ENGINE_DIR/sitelens.exe"; do
  head2="$(head -c2 "$f")"
  if [ "$head2" != "MZ" ]; then
    echo "× $f 不是 Windows PE（文件头非 MZ，当前平台 $(uname -s)）" >&2
    echo "  修复：跨平台构建 Windows PE 必须 GOOS=windows GOARCH=amd64" >&2
    exit 1
  fi
done
echo "  ✓ 壳与引擎均为 Windows PE"

# 4) 版本一致性硬闸：壳 Version（version.go）必须等于引擎版本
#    （internal/server.Version）。两处都是源码常量，直接 grep 比对——
#    跨平台构建时引擎 PE 在 Linux 上跑不了，不能靠执行二进制取版本。
#    这是 5.0.0 发布时「README 下载入口停在 4.0.1」那类漂移的结构性防线。
SHELL_VER="$(grep -oP 'const Version = "\K[0-9.]+' "$ROOT/desktop-wails/version.go" | head -1)"
ENGINE_VER="$(grep -oP 'const Version = "\K[0-9.]+' "$ROOT/internal/server/server.go" | head -1)"
echo "  壳版本=$SHELL_VER 引擎版本=$ENGINE_VER"
if [ -z "$SHELL_VER" ] || [ -z "$ENGINE_VER" ]; then
  echo "× 版本号读取失败（壳=$SHELL_VER 引擎=$ENGINE_VER）" >&2
  exit 1
fi
if [ "$SHELL_VER" != "$ENGINE_VER" ]; then
  echo "× 壳版本（desktop-wails/version.go=$SHELL_VER）与引擎版本（$ENGINE_VER）不一致" >&2
  exit 1
fi

echo "== 完成：$OUT =="
du -sh "$OUT" 2>/dev/null || true
