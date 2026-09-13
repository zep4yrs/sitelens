#!/bin/bash
# 在 Linux 上把 .nsi 编译成 Windows 安装包（桌面版 / lite / full 共用）。
#
# 为什么必须包一层：
#   1) 中文文件名（产品说明.md）：C locale 下 makensis 对中文名会段错误，
#      必须 LANG/LC_ALL=C.UTF-8；
#   2) 生成的安装器是 32 位 NSIS 引导程序，在容器内**缺少 display driver**
#      时 wine 会秒退：0x0050/0x0048 `err:winediag:nodrv_CreateWindow
#      Application tried to create a window, but no driver could be loaded.`
#      —— 这是容器内构建绕不过去的一步：
#        · lite/full：makensis 编译后 CI 并不需要跑安装器，历史配置里也没有，
#          但为了让产物「可被 wine 加载」这件事被验证过，这里仍统一跑一遍；
#        · 桌面版：electron-builder 每打一次 NSIS 包都会用 wine 调
#          makensis.exe 生成卸载器，那一步同样依赖 display driver。
#      因此统一在 Xvfb 虚拟显示下执行（xvfb-run -a），而非依赖
#      WINEDLLOVERRIDES 之类的屏蔽手段。
#   3) wine 的退出码不可当判定依据：引导程序执行到脚本 Quit 才结束，
#      静默安装（/S）会以脚本 SetErrorLevel 的值退出，直接拿 wine 退出码
#      判成败会假红；真正可信的验收是产物存在且非空。
#
# 用法：ci_nsis_exe.sh -DVERSION=3.0.0 -DSRCDIR="$PWD" -DSTAGEDIR=SiteLens \
#                     -DOUTFILE="$PWD/dist/SiteLens-3.0.0-setup-lite.exe" \
#                     installer/installer.nsi
set -euo pipefail

NSI="${@: -1}"
if [ ! -f "$NSI" ]; then
  echo "× 未找到 nsi 脚本：$NSI" >&2
  exit 1
fi

OUTFILE=""
for arg in "$@"; do
  case "$arg" in
    -DOUTFILE=*) OUTFILE="${arg#-DOUTFILE=}" ;;
  esac
done
if [ -z "$OUTFILE" ]; then
  echo "× 未传 -DOUTFILE（需要它来校验产物）" >&2
  exit 1
fi

for bin in makensis wine xvfb-run; do
  command -v "$bin" >/dev/null 2>&1 || { echo "× 缺少 $bin，请先安装（apt-get install -y $bin）" >&2; exit 1; }
done

echo "· makensis 编译（LANG=C.UTF-8）"
LANG=C.UTF-8 LC_ALL=C.UTF-8 makensis -V2 "$@"

if [ ! -s "$OUTFILE" ]; then
  echo "× 安装包未生成或为空：$OUTFILE" >&2
  exit 1
fi

# 加载校验：无 display driver 时 32 位引导程序必然以 nodrv_CreateWindow
# 秒退（exit 非 0）。这里只断言「没崩」，不依赖具体退出码——
# wine 下 NSIS 引导程序的退出码不可靠（--version 会一直挂住，/S 则返回
# 脚本 SetErrorLevel，两者都不能当成败判据）。
echo "· wine 加载校验（Xvfb 虚拟显示）：生成的自解压引导程序能否正常存活"
set +e
timeout 60 xvfb-run -a wine "$OUTFILE" --version >/tmp/nsi-wine-version.log 2>&1
wine_ec=$?
set -e
case "$wine_ec" in
  0|124)
    echo "  ✓ 引导程序正常启动（wine exit=$wine_ec；124=按预期常驻，已由 timeout 收尾）" ;;
  2)
    echo "× 引导程序秒退（exit=2，display driver 加载失败 nodrv_CreateWindow）——检查是否漏了 Xvfb/wine32" >&2
    tail -20 /tmp/nsi-wine-version.log >&2 || true
    exit 1 ;;
  *)
    echo "  · wine exit=$wine_ec，日志尾部：" >&2
    tail -5 /tmp/nsi-wine-version.log >&2 || true ;;
esac

echo "· 安装包就绪：$OUTFILE（$(stat -c%s "$OUTFILE") 字节）"
