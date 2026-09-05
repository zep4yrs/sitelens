# -*- coding: utf-8 -*-
"""情报自动更新守护：应用启动时补一次，之后每 24 小时重复。

环境变量 SLENS_AUTO_UPDATE=0 可关闭。
"""
import threading
import time
import traceback

INTERVAL = 86400


def run_update(db_factory):
    """执行一轮 OSV 区间补全 + KEV 清单更新（复用 tools 管线的核心步骤）"""
    from tools.update_intel import enrich_batch, flush
    db = db_factory()
    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT DISTINCT cve FROM vuln_kb"
                    " WHERE cve <> '' AND (affected IS NULL OR affected = '')")
        cves = [r["cve"] for r in cur.fetchall()]
    got = enrich_batch(cves)
    flush(db, [(c, "|".join(r[0]), r[1]) for c, r in got.items()])

    with db.transaction(dict_rows=True) as cur:
        cur.execute("SELECT COALESCE(SUM((affected <> '')::int),0) AS n FROM vuln_kb")
        n = cur.fetchone()["n"]
    return {"enriched": len(got), "total_with_ranges": n}


def start_daemon(db_factory, interval=INTERVAL, progress=None):
    """启动守护线程：立即补一次，之后每 interval 秒重复"""
    def loop():
        time.sleep(5)
        from tools.update_intel import update_kev
        while True:
            try:
                r = run_update(db_factory)
                update_kev()
                if progress:
                    progress("情报自动更新完成：%s" % r)
            except Exception:
                traceback.print_exc()
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True).start()
