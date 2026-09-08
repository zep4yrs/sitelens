"""构建 SiteLens 图形安装器：csc 编译 WinForms 向导 -> 拼接 zip -> Setup.exe。

用法：python tools/build_installer.py <zip 路径> <输出 exe 路径>
依赖：仅 Windows 自带 .NET Framework 4 csc.exe（无第三方工具）。
"""
import pathlib
import struct
import subprocess
import sys

CSC_CANDIDATES = [
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
]
ROOT = pathlib.Path(__file__).resolve().parent.parent


def find_csc():
    for c in CSC_CANDIDATES:
        if pathlib.Path(c).exists():
            return c
    raise SystemExit("未找到 csc.exe（.NET Framework 4）")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    zip_path = pathlib.Path(sys.argv[1])
    out_exe = pathlib.Path(sys.argv[2])
    src = ROOT / "tools" / "installer_gui.cs"
    stub = ROOT / "tmp_installer_stub.exe"

    csc = find_csc()
    subprocess.run([
        csc, "-nologo", "-optimize", "-target:winexe",
        "-r:System.IO.Compression.FileSystem.dll", "-r:System.IO.Compression.dll",
        f"-out:{stub}", str(src),
    ], check=True)

    stub_bytes = stub.read_bytes()
    zip_bytes = zip_path.read_bytes()
    out_exe.write_bytes(stub_bytes + zip_bytes + struct.pack("<Q", len(zip_bytes)))
    stub.unlink(missing_ok=True)
    print(f"OK {out_exe} ({out_exe.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
