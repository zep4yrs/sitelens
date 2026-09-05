"""扫描历史存储：SQLite 单文件库。

表 scans 保存每次扫描的完整结果 JSON。
路径默认 data/sitelens.db（自动建目录）。
外部输入一律经 ? 占位符绑定，不在任何 SQL 中拼接变量。
"""
import json
import os
import sqlite3


class ScanStore:
    """历史存储（封装：SQL 细节不外泄）"""

    def __init__(self, db_path="data/sitelens.db"):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            host        TEXT    NOT NULL,
            title       TEXT    DEFAULT '',
            status      INTEGER DEFAULT 0,
            security_grade TEXT DEFAULT '',
            security_score INTEGER DEFAULT 0,
            tech_count  INTEGER DEFAULT 0,
            techs_json  TEXT    DEFAULT '[]',
            duration    REAL    DEFAULT 0,
            scanned_at  TEXT    DEFAULT '',
            error       TEXT    DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
        CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scanned_at);
        """)
        self._conn.commit()

    def save_scan(self, result):
        """保存一次扫描结果，返回记录 id"""
        d = result.to_dict()
        cur = self._conn.execute(
            "INSERT INTO scans (url, host, title, status, security_grade,"
            " security_score, tech_count, techs_json, duration, scanned_at, error)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                d["url"], d["host"], d["title"], d["status"],
                (d["security"] or {}).get("grade", ""), (d["security"] or {}).get("score", 0),
                len(d["technologies"]), json.dumps(d["technologies"], ensure_ascii=False),
                d["duration"], d["scanned_at"], d["error"],
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_scans(self, limit=100, host=None):
        """最近扫描列表（概要字段，不含完整证据）"""
        if host is None:
            rows = self._conn.execute(
                "SELECT id, url, host, title, status, security_grade, security_score,"
                " tech_count, duration, scanned_at, error"
                " FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, url, host, title, status, security_grade, security_score,"
                " tech_count, duration, scanned_at, error"
                " FROM scans WHERE host = ? ORDER BY id DESC LIMIT ?",
                (host, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id):
        """按 id 取完整记录；不存在返回 None"""
        row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["technologies"] = json.loads(d.pop("techs_json") or "[]")
        return d

    def delete_scan(self, scan_id):
        """删除一条历史，返回是否删除成功"""
        cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def history_stats(self):
        """历史统计（扫描数 / 站点数 / 平均技术数）"""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT host) AS hosts,"
            " IFNULL(AVG(tech_count),0) AS avg_techs FROM scans"
        ).fetchone()
        return {"scans": row["n"], "hosts": row["hosts"], "avg_techs": round(row["avg_techs"], 1)}
