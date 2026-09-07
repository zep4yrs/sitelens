# -*- coding: utf-8 -*-
"""ddddocr HTTP sidecar：给 Go 版 SiteLens 提供验证码识别能力。

用法：python tools/ocr_server.py [port]     # 默认 127.0.0.1:9898
接口：POST /ocr    body = 验证码图片字节 → {"code": "识别文本"}
      GET  /health → {"ok": true}
Go 侧配置 loginbrute.captcha_ocr_url: "http://127.0.0.1:9898/ocr" 即启用。
仅监听本机——识别服务无鉴权，不要暴露到外网。
"""
import sys

try:
    from flask import Flask, request, jsonify
    import ddddocr
except ImportError as e:
    print("缺少依赖：%s（pip install flask ddddocr）" % e)
    sys.exit(1)

app = Flask(__name__)
_ocr = ddddocr.DdddOcr(show_ad=False)


@app.post("/ocr")
def ocr_route():
    img = request.get_data()
    if not img:
        return jsonify(error="empty body"), 400
    try:
        text = _ocr.classification(img)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc)), 500
    return jsonify(code=text)


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9898
    print("ddddocr sidecar 监听 127.0.0.1:%d" % port)
    app.run("127.0.0.1", port, threaded=True)
