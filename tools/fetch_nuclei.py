# -*- coding: utf-8 -*-
"""下载 Nuclei 社区模板库，只解包 http/ 类别（我们只做 HTTP 检测）。

用法：python tools/fetch_nuclei.py
模板落在 data/nuclei/http/，随后运行 python tools/import_nuclei.py 入库。
数据源固定为 projectdiscovery 官方仓库（https 字面量，无用户输入参与）。
"""
import io
import urllib.request
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "nuclei"


def main():
    (OUT / "http").mkdir(parents=True, exist_ok=True)
    print("下载 nuclei-templates（约 40MB）...")
    raw = urllib.request.urlopen(
        "https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main",
        timeout=180,
    ).read()
    print("下载完成:", len(raw) // 1024 // 1024, "MB")
    z = zipfile.ZipFile(io.BytesIO(raw))
    base = (OUT / "http").resolve()
    kept = 0
    for info in z.infolist():
        name = info.filename
        if "/http/" in name and name.endswith((".yaml", ".yml")) and not name.endswith("/"):
            target = (OUT / "http" / Path(name).name).resolve()
            if not target.is_relative_to(base):        # 防路径穿越
                continue
            target.write_bytes(z.read(info))
            kept += 1
    print("提取 http 模板:", kept, "个 →", OUT / "http")


if __name__ == "__main__":
    main()
