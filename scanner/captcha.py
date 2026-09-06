# -*- coding: utf-8 -*-
"""验证码识别（仅授权测试用途）：分级能力框架。

能力等级：
- calc    数字/算术：OCR 识别题面 → 解析四则运算 → 计算答案（无 OCR 时若题面
          在页面文本里也可由调用方传入文本解析）
- digits  字符/数字识别：OCR 分类输出
- click   点选：OCR 检测模型返回目标框（按 x 排序给出坐标序列）
- slider  滑块：缺口横向偏移检测（ddddocr slide_match，退化为纯 PIL 列差）

OCR 依赖 ddddocr（本地 onnx 推理，无网络请求）；未安装时 calc 仍支持
"页面文本算术"路径，其余能力报 capability 缺失。
"""
import io
import re

try:
    import ddddocr  # noqa: F401（仅探测可选依赖可用性；使用点均函数内局部 import）
    _AVAILABLE = True
except Exception:
    _AVAILABLE = False

_ocr = None
_det = None


def capability():
    """返回当前可用能力说明"""
    return {"ocr": _AVAILABLE, "click": _AVAILABLE, "slider": _AVAILABLE}


def _get_ocr():
    global _ocr
    if _ocr is None:
        import ddddocr
        _ocr = ddddocr.DdddOcr(show_ad=False)
    return _ocr


def ocr_image(image_bytes):
    """整图分类识别（数字/字母/短文本）"""
    if not _AVAILABLE:
        raise RuntimeError("OCR 依赖 ddddocr 未安装")
    return _get_ocr().classification(image_bytes)


_CALC_RE = re.compile(
    r"(-?\d+)\s*([+\-*x×÷/])\s*(-?\d+)")


def solve_calc_text(text):
    """算术题面 → 答案（支持 +-×÷）；解析失败返回 None"""
    m = _CALC_RE.search(text or "")
    if not m:
        return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    if op in ("+",):
        return a + b
    if op in ("-",):
        return a - b
    if op in ("*", "x", "×"):
        return a * b
    if op in ("/", "÷"):
        return a // b if b and a % b == 0 else (a / b if b else None)
    return None


def solve_calc_image(image_bytes):
    """算术型图片验证码：OCR 题面 → 计算答案"""
    text = ocr_image(image_bytes)
    answer = solve_calc_text(text)
    return answer, text


def detect_click_boxes(image_bytes):
    """点选式验证码：返回目标框 [[x1,y1,x2,y2], ...]（按 x 从小到大）"""
    if not _AVAILABLE:
        raise RuntimeError("点选检测依赖 ddddocr 未安装")
    global _det
    if _det is None:
        import ddddocr
        _det = ddddocr.DdddOcr(det=True, show_ad=False)
    boxes = _det.detection(image_bytes)
    return sorted(boxes, key=lambda b: b[0])


def click_coordinates(image_bytes, max_points=6):
    """点选框 → 提交用坐标序列（每框取中心，按 x 排序）"""
    return [[round((b[0] + b[2]) / 2), round((b[1] + b[3]) / 2)]
            for b in detect_click_boxes(image_bytes)[:max_points]]


def slider_gap_column_diff(bg_bytes, slide_bytes):
    """滑块缺口检测的纯 PIL 兜底：按列亮度差找缺口左边缘"""
    from PIL import Image
    bg = Image.open(io.BytesIO(bg_bytes)).convert("L")
    sl = Image.open(io.BytesIO(slide_bytes)).convert("L")
    bg_w, bg_h = bg.size
    sl_w, sl_h = sl.size
    bg_px, sl_px = bg.load(), sl.load()
    best_x, best_diff = 0, None
    for x in range(bg_w - sl_w + 1):
        diff = 0
        for sx in range(sl_w):
            for y in range(0, min(sl_h, bg_h), 4):
                diff += abs(bg_px[x + sx, y] - sl_px[sx, y])
        if best_diff is None or diff < best_diff:
            best_diff = diff
            best_x = x
    return best_x


def slider_gap(bg_bytes, slide_bytes):
    """滑块缺口偏移：优先 ddddocr slide_match，失败退化为列差法"""
    if _AVAILABLE:
        try:
            import ddddocr
            res = ddddocr.DdddOcr(det=False, show_ad=False).slide_match(
                slide_bytes, bg_bytes, simple_target=True)
            if res and res.get("target"):
                return res["target"][0]        # 缺口左边缘 x
        except Exception:
            pass
    return slider_gap_column_diff(bg_bytes, slide_bytes)


def find_captcha_img(html, base_url, hint="captcha|code|verify|valid"):
    """登录页 HTML 里定位验证码图片地址（按 img src 关键字匹配）"""
    import re as _re
    from urllib.parse import urljoin
    out = []
    for m in _re.finditer(r"<img[^>]+src=[\"']([^\"']+)[\"']", html, _re.I):
        src = m.group(1)
        if _re.search(hint, src, _re.I):
            out.append(urljoin(base_url, src))
    return out
