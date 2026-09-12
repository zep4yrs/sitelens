# -*- coding: utf-8 -*-
# 从品牌 logo 生成桌面版图标：多尺寸 ico（Windows）+ 512px png（托盘/extraResources）。
# 用法：python build/make_icon.py  （须装 Pillow）
from PIL import Image
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LOGO = os.path.normpath(os.path.join(HERE, "..", "..", "assets", "logo.png"))
SIZES = [16, 24, 32, 48, 64, 128, 256]

im = Image.open(LOGO).convert("RGBA")
im.resize((512, 512), Image.LANCZOS).save(os.path.join(HERE, "icon.png"))
im.save(os.path.join(HERE, "icon.ico"), sizes=[(s, s) for s in SIZES])
print("icon.png(512) + icon.ico(" + ",".join(str(s) for s in SIZES) + ") ->", HERE)
