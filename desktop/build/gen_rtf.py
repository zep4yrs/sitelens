# 从 license.txt 生成 NSIS 许可协议页用的 RTF 文件
# 非 ASCII 字符转 Unicode 转义，任何系统代码页下不乱码
import io, os

# license.txt 当前是 UTF-16 LE 编码（此前被重编码过）
raw = open("desktop/build/license.txt", "rb").read()
if raw[:2] == b"\xff\xfe":
    text = raw[2:].decode("utf-16-le")
elif raw[:3] == b"\xef\xbb\xbf":
    text = raw[3:].decode("utf-8")
else:
    text = raw.decode("utf-8")

def rtf_escape(s):
    out = []
    for ch in s:
        cp = ord(ch)
        if cp > 127:
            out.append("\\u%d?" % cp)
        elif ch in "{}\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)

lines = []
lines.append("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil\\fcharset134 Microsoft YaHei;}}")
lines.append("\\fs16")
body = rtf_escape(text)
lines.append(body.replace("\n", "\\par\n"))
lines.append("}")
rtf = "\n".join(lines)

out_path = os.path.join("desktop", "build", "license.rtf")
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="ascii") as f:
    f.write(rtf)
print("license.rtf:", os.path.getsize(out_path), "bytes")

