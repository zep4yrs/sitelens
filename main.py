# -*- coding: utf-8 -*-
"""SiteLens 命令行入口。

用法：
  python main.py scan <url> [--full]      扫描（--full 启用全部主动模块）
  python main.py stats                    指纹库与历史统计
  python main.py serve                    启动 Web 服务
  python tools/jwt_check.py               离线 JWT 密钥字典校验（另行使用）
"""
import sys

from scanner.db import Database, KnowledgeBase, load_env
from scanner.engine import ScannerEngine


def _progress(done, total, msg):
    print("[%3d%%] %s" % (done, msg))


def cmd_scan(url, full=False):
    options = {"deep": True}
    if full:
        options.update({"active_fp": True, "dir_scan": True,
                        "subdomain": True, "service_probe": True})
    engine = ScannerEngine(progress=_progress, options=options)
    result = engine.scan(url)
    print("\n站点：%s（%s）" % (result.host, result.title or "-"))
    print("技术栈 %d 项：" % len(result.technologies))
    for t in sorted(result.technologies, key=lambda x: -x.confidence):
        cats = ",".join(engine.registry.category_name(c) for c in t.categories)
        ver = (" " + t.version) if t.version else ""
        print("  %-30s %-16s %3d%%  [%s]" % (t.name + ver, "", t.confidence, cats))
    sec = result.security
    print("安全响应头：%s（%d 分）" % (sec.grade, sec.score))
    print("漏洞情报：%d 条" % len(result.vulnerabilities))
    db = Database(load_env())
    from scanner.db import ScanStore
    print("已存入历史：#%d" % ScanStore(db).save_scan(result, options=options))


def cmd_stats():
    kb = KnowledgeBase(Database(load_env()))
    s = kb.stats()
    print("类别 %d | 精编指纹 %d | TscanPlus 指纹 %d | 漏洞情报 %d" % (
        s["categories"], s["curated"], s["tscan"], s["vulns"]))
    print("漏洞等级分布：", s["vuln_by_severity"])
    print("历史：", ScanStats())


def ScanStats():
    from scanner.db import ScanStore
    return ScanStore(Database(load_env())).history_stats()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "scan" and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2], full="--full" in sys.argv)
    elif cmd == "stats":
        cmd_stats()
    elif cmd == "audit" and len(sys.argv) >= 3:
        from scanner.audit import run_audit
        r = run_audit(sys.argv[2])
        print("文件 %d | 代码行 %d | 发现 %d（高危 %d / 中危 %d / 低危 %d）" % (
            r["files"], r["lines"], len(r["findings"]),
            r["by_severity"]["high"], r["by_severity"]["medium"], r["by_severity"]["low"]))
        for f in r["findings"][:40]:
            print("  [%s] %s:%s %s -> %s" % (f["severity"], f["file"], f["line"], f["title"], f["advice"]))
    elif cmd == "serve":
        import app  # noqa: F401
        app.app.run(host="127.0.0.1", port=5000, threaded=True)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
