#!/bin/bash
# 构建并打包 Wails 桌面壳（Linux / macOS）。
#
# Windows 交付线见 tools/wails_build.sh（NSIS + PE 校验）。本脚本只负责
# POSIX 平台：构建壳（需 CGO）+ 引擎 + 只读资产，并产出可直接分发的包：
#   Linux  → dist/wails/<os>-<arch>/SiteLens/ + .deb（有 dpkg-deb 时）
#   macOS  → SiteLens.app + .dmg（有 hdiutil 时）
#
# 平台依赖：
#   Linux：gcc / pkg-config / libgtk-3-dev / libwebkit2gtk-4.1-dev / libx11-dev
#   macOS：Xcode Command Line Tools（Cocoa/WebKit 为系统框架，无需额外装）
#
# 用法：
#   tools/wails_build_unix.sh              # 当前平台
#   tools/wails_build_unix.sh --no-package # 只构建、不打包
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"   # linux / darwin
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "× 不支持的架构：$ARCH_RAW" >&2; exit 1 ;;
esac
PKG=1
for a in "$@"; do [ "$a" = "--no-package" ] && PKG=0; done
if [ "$OS" != "linux" ] && [ "$OS" != "darwin" ]; then
  echo "× 本脚本只处理 Linux/macOS（当前 $(uname -s)）；Windows 用 tools/wails_build.sh" >&2
  exit 1
fi

OUT="$ROOT/dist/wails/${OS}-${ARCH}/SiteLens"
ENGINE_DIR="$OUT/engine"
need() { command -v "$1" >/dev/null 2>&1 || { echo "× 缺少 $1，请先安装" >&2; exit 1; }; }
need go

echo "== 构建 Wails 桌面壳（${OS}/${ARCH}）=="
rm -rf "$ROOT/dist/wails/${OS}-${ARCH}"
mkdir -p "$ENGINE_DIR/data"

# 1) 壳：POSIX 平台必须开 CGO（Wails 的 GTK/Cocoa 后端是 cgo）。
( cd "$ROOT/desktop-wails" && \
  CGO_ENABLED=1 GOOS="$OS" GOARCH="$ARCH" \
  go build -tags gtk3 -trimpath -ldflags "-s -w" -o "$OUT/sitelens-wails" . )

# 2) 引擎：与壳同平台同架构（CGO 关掉，纯 Go 单文件）。
( cd "$ROOT" && \
  CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" \
  go build -trimpath -ldflags "-s -w" -o "$ENGINE_DIR/sitelens-engine" ./cmd/sitelens-engine )

# 3) 只读资产：优先用 Windows 线已暂存的 build/engine/data（内容与平台无关），
#    没有则从仓库 data/ 拷（开发机/CI 直接构建时）。
if [ -d "$ROOT/build/engine/data" ]; then
  cp -R "$ROOT/build/engine/data/." "$ENGINE_DIR/data/"
else
  cp -R "$ROOT/data/." "$ENGINE_DIR/data/"
fi
rm -rf "$ENGINE_DIR/data/state"   # 不把开发机扫描历史打进包

# 4) 版本一致性硬闸（与 Windows 线同口径：壳 Version == 引擎 Version）。
SHELL_VER="$(grep -oE 'const Version = "[0-9.]+"' "$ROOT/desktop-wails/version.go" | head -1 | grep -oE '[0-9.]+')"
ENGINE_VER="$(grep -oE 'const Version = "[0-9.]+"' "$ROOT/internal/server/server.go" | head -1 | grep -oE '[0-9.]+')"
if [ -z "$SHELL_VER" ] || [ -z "$ENGINE_VER" ]; then
  echo "× 版本号读取失败（壳=$SHELL_VER 引擎=$ENGINE_VER）" >&2
  exit 1
fi
if [ "$SHELL_VER" != "$ENGINE_VER" ]; then
  echo "× 壳版本 $SHELL_VER ≠ 引擎版本 $ENGINE_VER，拒绝打包" >&2
  exit 1
fi
echo "  ✓ 壳版本=$SHELL_VER 引擎版本=$ENGINE_VER"

# 5) 平台包魔数校验：防「错平台二进制进包」（v3.0.0 ELF 装进 Windows 包事故）。
check_magic() {
  local f="$1" want="$2" desc="$3"
  local got
  got="$(head -c4 "$f" | od -An -tx1 | tr -d ' \n')"
  if [ "$got" != "$want" ]; then
    echo "× $f 不是 $desc（magic=$got，期望 $want）" >&2
    exit 1
  fi
}
if [ "$OS" = "linux" ]; then
  check_magic "$OUT/sitelens-wails" "7f454c46" "Linux ELF"
  check_magic "$ENGINE_DIR/sitelens-engine" "7f454c46" "Linux ELF"
else
  # Mach-O 64 位小端：arm64 与 x86_64 都是 cffaedfe（fat/大端另行处理）
  for f in "$OUT/sitelens-wails" "$ENGINE_DIR/sitelens-engine"; do
    m="$(head -c4 "$f" | od -An -tx1 | tr -d ' \n')"
    case "$m" in
      cffaedfe|cefaedfe) ;;
      *) echo "× $f 不是 Mach-O（magic=$m）" >&2; exit 1 ;;
    esac
  done
fi
echo "  ✓ 壳与引擎平台匹配（${OS}/${ARCH}）"

if [ "$PKG" = "0" ]; then
  echo "== 完成（未打包）：$OUT =="
  exit 0
fi

# 6) 打包
if [ "$OS" = "linux" ]; then
  # .deb：依赖 webkit2gtk-4.1 运行时（Ubuntu 24.04+/Debian 12+）
  need dpkg-deb
  DEB_ROOT="$ROOT/dist/wails/${OS}-${ARCH}/deb"
  rm -rf "$DEB_ROOT"
  mkdir -p "$DEB_ROOT/DEBIAN" "$DEB_ROOT/opt/sitelens"
  cp -R "$OUT/." "$DEB_ROOT/opt/sitelens/"
  cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: sitelens
Version: $SHELL_VER
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: SiteLens
Depends: libgtk-3-0, libwebkit2gtk-4.1-0
Description: SiteLens 站点透视桌面端
EOF
  dpkg-deb --build --root-owner-group "$DEB_ROOT" "$ROOT/dist/wails/SiteLens_${SHELL_VER}_${ARCH}.deb" >/dev/null
  echo "  ✓ deb: dist/wails/SiteLens_${SHELL_VER}_${ARCH}.deb"
else
  # .app bundle + dmg（macOS 本机才可执行）
  APP="$ROOT/dist/wails/${OS}-${ARCH}/SiteLens.app"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  cp "$OUT/sitelens-wails" "$APP/Contents/MacOS/sitelens-wails"
  cp -R "$OUT/engine" "$APP/Contents/MacOS/engine"
  if [ -f "$ROOT/desktop-wails/assets/icon.png" ]; then
    cp "$ROOT/desktop-wails/assets/icon.png" "$APP/Contents/Resources/icon.png"
  fi
  cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>SiteLens</string>
  <key>CFBundleDisplayName</key><string>SiteLens 站点透视</string>
  <key>CFBundleIdentifier</key><string>top.feng-qiao.sitelens</string>
  <key>CFBundleVersion</key><string>$SHELL_VER</string>
  <key>CFBundleShortVersionString</key><string>$SHELL_VER</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>sitelens-wails</string>
  <key>CFBundleIconFile</key><string>icon.png</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
  echo "  ✓ app: $APP"
  if command -v hdiutil >/dev/null 2>&1; then
    hdiutil create -volname "SiteLens" -srcfolder "$APP" -ov -format UDZO \
      "$ROOT/dist/wails/SiteLens_${SHELL_VER}_${ARCH}.dmg" >/dev/null
    echo "  ✓ dmg: dist/wails/SiteLens_${SHELL_VER}_${ARCH}.dmg"
  fi
fi
echo "== 完成：$OUT =="
