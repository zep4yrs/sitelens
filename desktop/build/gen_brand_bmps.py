# -*- coding: utf-8 -*-
"""生成 NSIS 安装器/卸载器品牌侧栏图（164x314，24 位 BMP）。

NSIS MUI2 侧栏要求：未压缩 24 位 BMP，尺寸恰好 164x314。
品牌资产原样使用：assets/logo.png 的深色 glyph 不做任何改色/变形，
放在浅色圆角底板上保证可见（改的是底板，不是 logo）。
文案与工作台一致：mono 品牌名 + 绿点、深底 #0f172a + 品牌绿 #22c55e。
"""
from PIL import Image, ImageDraw, ImageFont
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
W, H = 164, 314
BG = (15, 23, 42)        # #0f172a
FG = (241, 245, 249)     # #f1f5f9
MUTE = (148, 163, 184)   # #94a3b8
GREEN = (34, 197, 94)    # #22c55e
LINE = (30, 41, 59)      # #1e293b
CHIP = (248, 250, 252)   # #f8fafc logo 底板（浅色，衬托深色 glyph）


def font(name, size):
    try:
        return ImageFont.truetype(name, size)
    except OSError:
        return ImageFont.load_default()


MSYH = r"C:\Windows\Fonts\msyh.ttc"
CONS = r"C:\Windows\Fonts\consola.ttf"


def base_canvas():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # 顶部品牌绿发丝线 + 底部细线点缀，避免大面积纯色空旷
    d.line([(0, 0), (W, 0)], fill=GREEN, width=3)
    for y in range(H - 46, H, 12):
        d.line([(14, y), (W - 14, y)], fill=LINE, width=1)
    return img, d


def draw_logo(img, d):
    """logo 原样居中放在浅色圆角底板上（不缩放不透明度处理以外不动像素）。"""
    logo_path = os.path.join(ROOT, "assets", "logo.png")
    chip_w, chip_h = 108, 108
    chip_x, chip_y = (W - chip_w) // 2, 40
    d.rounded_rectangle([chip_x, chip_y, chip_x + chip_w, chip_y + chip_h],
                        radius=22, fill=CHIP)
    if os.path.exists(logo_path):
        src = Image.open(logo_path).convert("RGBA")
        # 仅按底板等比缩入（内容不裁切、不改色）
        src.thumbnail((chip_w - 20, chip_h - 20), Image.LANCZOS)
        img.paste(src, (chip_x + (chip_w - src.width) // 2,
                        chip_y + (chip_h - src.height) // 2), src)
    return chip_y + chip_h


def sidebar(kind):
    img, d = base_canvas()
    y = draw_logo(img, d)
    # 品牌名（mono）+ 呼吸点
    f_brand = font(CONS, 26)
    tw = d.textlength("sitelens", font=f_brand)
    d.text(((W - tw - 12) / 2, y + 14), "sitelens", font=f_brand, fill=FG)
    bx = (W - tw - 12) / 2 + tw + 5
    d.ellipse([bx, y + 30, bx + 6, y + 36], fill=GREEN)
    # 中文副题 / 模式文案
    f_sub = font(MSYH, 13)
    sub = "站点透视 v3.0.0" if kind == "install" else "卸载 SiteLens"
    tw = d.textlength(sub, font=f_sub)
    d.text(((W - tw) / 2, y + 50), sub, font=f_sub, fill=MUTE)
    # 说明短语（两行内）
    f_tip = font(MSYH, 11)
    tips = ["深度指纹识别 · 漏洞情报", "扫描 · 指纹 · 情报"] if kind == "install" \
        else ["扫描历史默认保留", "也可选择一并清除"]
    ty = y + 84
    for tip in tips:
        tw = d.textlength(tip, font=f_tip)
        d.text(((W - tw) / 2, ty), tip, font=f_tip, fill=MUTE)
        ty += 20
    out = os.path.join(HERE, ("installerSidebar.bmp" if kind == "install"
                              else "uninstallerSidebar.bmp"))
    img.save(out, format="BMP")  # RGB → 24 位未压缩
    print("wrote", out)


if __name__ == "__main__":
    sidebar("install")
    sidebar("uninstall")
