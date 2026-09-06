# -*- coding: utf-8 -*-
"""PostgreSQL 存储层：SiteLens 的唯一持久化组件。

设计要点：
1. 连接参数读 .env（SLENS_DB_*）或环境变量，代码中不出现明文口令；
2. 所有 SQL 一律为调用点内联字面量，外部输入全部经 %s 占位符绑定；
   模糊匹配用 similarity()/position() 函数实现，不拼接任何 SQL 片段；
3. 知识库表（指纹/漏洞情报）启动时一次载入内存做匹配——扫描是 CPU 密集型
   字符串运算，驻内存比逐条查询快几个量级；数据库负责持久化与检索；
4. 向量检索：pgvector 不可用时退化为 trgm 预筛 + Python 余弦重排（零扩展
   依赖）；后续若安装 pgvector，vuln_kb.embedding 可平移为 vector 类型
   （迁移 SQL 见 docs/开发文档.md）。
"""
import json
import os
import re
import threading

import psycopg2
import psycopg2.pool
from psycopg2.extras import Json, RealDictCursor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = "sitelens"


def load_env():
    """读取项目 .env（SLENS_DB_*），环境变量优先"""
    conf = {}
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        for line in open(path, encoding="utf8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    conf.update({k: v for k, v in os.environ.items() if k.startswith("SLENS_DB_")})
    return conf


_STOPWORDS = {"api", "app", "web", "server", "service", "cloud", "panel", "manager",
              "system", "proxy", "framework", "library", "script", "cms", "cdn",
              "kit", "pro", "plus", "soft", "the", "and"}


def product_keywords(product, side="lookup"):
    """产品名 → 匹配关键词集合。

    lookup（技术名→漏洞）：多词产品只按完整短语匹配，杜绝 "api"/"google"
    这类泛词造成的大量误报；单词产品用词本身。
    index（漏洞产品名建索引）：短语之外再收录显著单词（>=4 字符且非停用词），
    让 "WebLogic" 能命中 "Oracle WebLogic"。
    """
    if not product:
        return set()
    p = product.lower().strip()
    kws = {p, re.sub(r"[.\-_ ]+", "", p)}
    words = [w for w in re.split(r"[.\-_ ]+", p) if w]
    if len(words) == 1:
        kws.add(words[0])
    elif side == "index":
        for w in words:
            if len(w) >= 4 and w not in _STOPWORDS:
                kws.add(w)
    return {k for k in kws if len(k) >= 3}


class Database:
    """PostgreSQL 连接池与 schema 初始化"""

    def __init__(self, conf=None):
        c = conf or load_env()
        self._params = dict(
            host=c.get("SLENS_DB_HOST", "127.0.0.1"),
            port=int(c.get("SLENS_DB_PORT", "5432")),
            user=c.get("SLENS_DB_USER", "postgres"),
            password=c.get("SLENS_DB_PASSWORD", ""),
            dbname=c.get("SLENS_DB_NAME", DB_NAME),
            connect_timeout=5,
        )
        self._pool = None
        self._lock = threading.Lock()
        with self._lock:
            self._pool = psycopg2.pool.SimpleConnectionPool(1, 8, **self._params)
        self.ensure_schema()

    def _get(self):
        return self._pool.getconn()

    def _put(self, conn, commit=False):
        if commit:
            conn.commit()
        self._pool.putconn(conn)

    def ensure_schema(self):
        """建表（幂等）。DDL 为单个内联字面量；pg_trgm 无权限时降级不阻塞。"""
        conn = self._get()
        try:
            with conn.cursor() as cur:
                try:
                    cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
                    conn.commit()
                except psycopg2.Error:
                    conn.rollback()
                try:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS categories (
                            id   TEXT PRIMARY KEY,
                            name TEXT NOT NULL,
                            icon TEXT DEFAULT '',
                            ord  INT DEFAULT 0);
                        CREATE TABLE IF NOT EXISTS technologies (
                            name    TEXT PRIMARY KEY,
                            cats    TEXT[] NOT NULL,
                            conf    INT DEFAULT 70,
                            website TEXT DEFAULT '',
                            rules   JSONB NOT NULL);
                        CREATE TABLE IF NOT EXISTS tscan_fingerprints (
                            name   TEXT PRIMARY KEY,
                            cat    TEXT DEFAULT 'misc',
                            groups JSONB NOT NULL);
                        CREATE TABLE IF NOT EXISTS fingerdir (
                            product TEXT PRIMARY KEY,
                            spec    JSONB NOT NULL);
                        CREATE TABLE IF NOT EXISTS service_fp (
                            id      SERIAL PRIMARY KEY,
                            service TEXT,
                            pattern TEXT,
                            product TEXT,
                            version TEXT DEFAULT '',
                            soft    BOOL DEFAULT FALSE);
                        CREATE TABLE IF NOT EXISTS vuln_kb (
                            id        SERIAL PRIMARY KEY,
                            src       TEXT,
                            name      TEXT,
                            product   TEXT DEFAULT '',
                            cve       TEXT DEFAULT '',
                            type      TEXT DEFAULT '',
                            severity  TEXT DEFAULT 'medium',
                            ref       TEXT DEFAULT '',
                            descr     TEXT DEFAULT '',
                            embedding DOUBLE PRECISION[] DEFAULT NULL);
                        ALTER TABLE vuln_kb ADD COLUMN IF NOT EXISTS affected TEXT DEFAULT '';
                        ALTER TABLE vuln_kb ADD COLUMN IF NOT EXISTS cvss_vec TEXT DEFAULT '';
                        ALTER TABLE vuln_kb ADD COLUMN IF NOT EXISTS sources TEXT DEFAULT '';
                        ALTER TABLE vuln_kb ADD COLUMN IF NOT EXISTS cvss_score REAL DEFAULT 0;
                        ALTER TABLE vuln_kb ADD COLUMN IF NOT EXISTS cvss_sev TEXT DEFAULT '';
                        ALTER TABLE vuln_kb ADD COLUMN IF NOT EXISTS cvss_vector_txt TEXT DEFAULT '';
                        CREATE TABLE IF NOT EXISTS cve_ms (
                            id SERIAL PRIMARY KEY,
                            cve TEXT, component TEXT, title TEXT,
                            severity TEXT, impact TEXT, date TEXT);
                        CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, date_added TEXT DEFAULT '', ransomware TEXT DEFAULT '');
                        CREATE INDEX IF NOT EXISTS idx_vulnkb_cve ON vuln_kb(cve);
                        CREATE INDEX IF NOT EXISTS idx_vulnkb_sev ON vuln_kb(severity);
                        CREATE INDEX IF NOT EXISTS idx_vulnkb_prod_trgm
                            ON vuln_kb USING gin (product gin_trgm_ops);
                        CREATE TABLE IF NOT EXISTS scans (
                            id             BIGSERIAL PRIMARY KEY,
                            url            TEXT NOT NULL,
                            host           TEXT NOT NULL,
                            title          TEXT DEFAULT '',
                            status         INT DEFAULT 0,
                            security_grade TEXT DEFAULT '',
                            security_score INT DEFAULT 0,
                            tech_count     INT DEFAULT 0,
                            vuln_count     INT DEFAULT 0,
                            duration       REAL DEFAULT 0,
                            options        JSONB DEFAULT '{}'::jsonb,
                            result         JSONB NOT NULL,
                            scanned_at     TIMESTAMPTZ DEFAULT now());
                        CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
                        CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scanned_at);
                        CREATE TABLE IF NOT EXISTS scan_techs (
                            scan_id BIGINT NOT NULL,
                            name    TEXT NOT NULL,
                            cats    TEXT[] NOT NULL,
                            conf    INT,
                            version TEXT);
                        CREATE INDEX IF NOT EXISTS idx_scan_techs_name ON scan_techs(name);
                        CREATE TABLE IF NOT EXISTS jobs (
                            id         TEXT PRIMARY KEY,
                            kind       TEXT DEFAULT 'scan',
                            status     TEXT DEFAULT 'pending',
                            progress   INT DEFAULT 0,
                            message    TEXT DEFAULT '',
                            total      INT DEFAULT 1,
                            done       INT DEFAULT 0,
                            payload    JSONB DEFAULT '{}'::jsonb,
                            created_at TIMESTAMPTZ DEFAULT now(),
                            updated_at TIMESTAMPTZ DEFAULT now());
                        ALTER TABLE jobs ADD COLUMN IF NOT EXISTS result JSONB;
                    """)
                    conn.commit()
                except psycopg2.Error:
                    conn.rollback()
                    raise
        finally:
            self._put(conn)

    def transaction(self, dict_rows=False):
        """上下文管理器：yield 游标，成功提交、异常回滚。

        SQL 一律写成调用点内的字面量，外部输入只经占位符绑定。
        dict_rows=True 时游标返回 dict 行（按列名取值）。
        """
        return _Tx(self, dict_rows)


class _Tx:
    """事务上下文（供 Database.transaction 使用）"""

    def __init__(self, db, dict_rows=False):
        self._db = db
        self._dict_rows = dict_rows
        self._conn = None

    def __enter__(self):
        self._conn = self._db._get()
        if self._dict_rows:
            return self._conn.cursor(cursor_factory=RealDictCursor)
        return self._conn.cursor()

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            self._db._put(self._conn)
        return False


class KnowledgeBase:
    """知识库加载器：启动时从 PG 载入指纹与漏洞情报到内存索引"""

    def __init__(self, db):
        self.db = db
        self.categories = {}          # id -> {name, icon, ord}
        self.fingerprints = []        # 自建指纹列表
        self.by_name = {}
        self.tscan = []               # tscan 指纹 [{name, cat, groups}]
        self.fingerdir = {}           # 主动路径指纹
        self.vuln_index = {}          # lower(产品关键词) -> [vuln]
        self.vuln_all = []            # 全量漏洞情报（检索/统计用）
        self.load()

    def load(self):
        self.categories = {}
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT id, name, icon, ord FROM categories ORDER BY ord")
            for r in cur.fetchall():
                self.categories[r["id"]] = dict(r)
        self.fingerprints = []
        self.by_name = {}
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT name, cats, conf, website, rules FROM technologies")
            for r in cur.fetchall():
                fp = {"name": r["name"], "cats": list(r["cats"]), "conf": r["conf"],
                      "website": r["website"] or "", "rules": r["rules"]}
                self.fingerprints.append(fp)
                self.by_name[fp["name"]] = fp
        self.tscan = []
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT name, cat, groups FROM tscan_fingerprints")
            for r in cur.fetchall():
                self.tscan.append({"name": r["name"], "cat": r["cat"], "groups": r["groups"]})
        self.fingerdir = {}
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT product, spec FROM fingerdir")
            for r in cur.fetchall():
                self.fingerdir[r["product"]] = r["spec"]
        self.vuln_all = []
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT id, src, name, product, cve, type, severity, ref, descr, affected FROM vuln_kb")
            for r in cur.fetchall():
                self.vuln_all.append(dict(r))
        self.vuln_index = {}
        for v in self.vuln_all:
            for kw in product_keywords(v["product"], side="index"):
                self.vuln_index.setdefault(kw, []).append(v)

    def stats(self):
        """指纹库规模（前端展示 / 答辩）"""
        per_cat = {}
        for fp in self.fingerprints:
            for c in fp["cats"]:
                per_cat[c] = per_cat.get(c, 0) + 1
        for t in self.tscan:
            per_cat[t["cat"]] = per_cat.get(t["cat"], 0) + 1
        sev = {}
        for v in self.vuln_all:
            sev[v["severity"]] = sev.get(v["severity"], 0) + 1
        return {
            "categories": len(self.categories),
            "technologies": len(self.fingerprints) + len(self.tscan),
            "curated": len(self.fingerprints),
            "tscan": len(self.tscan),
            "vulns": len(self.vuln_all),
            "vuln_by_severity": sev,
            "per_category": per_cat,
        }

    def category_name(self, cat_id):
        cat = self.categories.get(cat_id)
        return cat["name"] if cat else cat_id

    def vulns_for(self, tech_name):
        """按技术名取漏洞情报（内存索引，扫描主路径）"""
        out, seen = [], set()
        for kw in product_keywords(tech_name):
            for v in self.vuln_index.get(kw, []):
                if v["id"] not in seen:
                    seen.add(v["id"])
                    out.append(v)
        return out

    def search_vulns(self, text, limit=30):
        """漏洞情报混合检索：trgm 相似度（GIN 索引）粗筛 → 语义向量余弦重排。

        embedding 为 256 维哈希 TF-IDF（scanner/embedding.py），pgvector 可用后
        可改为库内 <=> 排序（迁移 SQL 见 docs/开发文档.md）。
        """
        from .embedding import cosine, embed_text
        rows = []
        try:
            with self.db.transaction(dict_rows=True) as cur:
                cur.execute(
                    "SELECT id, src, name, product, cve, type, severity, ref, descr,"
                    " similarity(product, %s) AS sim FROM vuln_kb"
                    " WHERE similarity(product, %s) > 0.15"
                    "    OR position(lower(%s) in lower(name)) > 0"
                    " ORDER BY sim DESC LIMIT 120",
                    (text, text, text))
                rows = [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            # pg_trgm 扩展不可用时降级为包含匹配，不阻塞检索
            with self.db.transaction(dict_rows=True) as cur:
                cur.execute(
                    "SELECT id, src, name, product, cve, type, severity, ref, descr"
                    " FROM vuln_kb"
                    " WHERE position(lower(%s) in lower(product)) > 0"
                    "    OR position(lower(%s) in lower(name)) > 0"
                    " ORDER BY id DESC LIMIT 120",
                    (text, text))
                rows = [dict(r) for r in cur.fetchall()]
        if not rows:
            return []
        ids = [r["id"] for r in rows]
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT id, embedding FROM vuln_kb WHERE id = ANY(%s)", (ids,))
            vecs = {r["id"]: r["embedding"] for r in cur.fetchall()}
        qvec = embed_text(text)
        for r in rows:
            sim = cosine(qvec, vecs.get(r["id"]) or [])
            r["sim"] = round(max(r["sim"], 0) * 0.4 + sim * 0.6, 4)   # 混合得分
        rows.sort(key=lambda r: -r["sim"])
        return rows[:limit]


class ScanStore:
    """扫描历史与结果（PG）"""

    def __init__(self, db):
        self.db = db

    def save_scan(self, result, options=None):
        """保存一次扫描：主表 + 技术明细表，返回记录 id"""
        d = result.to_dict()
        sec = d.get("security") or {}
        with self.db.transaction() as cur:
            cur.execute(
                "INSERT INTO scans (url, host, title, status, security_grade,"
                " security_score, tech_count, vuln_count, duration, options, result)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (
                    d["url"], d["host"], d["title"], d["status"],
                    sec.get("grade", ""), sec.get("score", 0),
                    len(d["technologies"]), len(d.get("vulnerabilities") or []),
                    d["duration"], Json(options or {}), Json(d),
                ),
            )
            scan_id = cur.fetchone()[0]
            for t in d["technologies"]:
                cur.execute(
                    "INSERT INTO scan_techs (scan_id, name, cats, conf, version)"
                    " VALUES (%s,%s,%s,%s,%s)",
                    (scan_id, t["name"], t["categories"], t["confidence"], t["version"]),
                )
        return scan_id

    def list_scans(self, limit=100, tech=None):
        """历史列表；tech 参数支持「哪些站用了 X 技术」检索"""
        with self.db.transaction(dict_rows=True) as cur:
            if tech:
                cur.execute(
                    "SELECT s.id, s.url, s.host, s.title, s.status, s.security_grade,"
                    " s.security_score, s.tech_count, s.vuln_count, s.duration, s.scanned_at"
                    " FROM scans s JOIN scan_techs t ON t.scan_id = s.id"
                    " WHERE position(lower(%s) in lower(t.name)) > 0"
                    " ORDER BY s.id DESC LIMIT %s",
                    (tech, limit))
            else:
                cur.execute(
                    "SELECT id, url, host, title, status, security_grade, security_score,"
                    " tech_count, vuln_count, duration, scanned_at FROM scans"
                    " ORDER BY id DESC LIMIT %s",
                    (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_scan(self, scan_id):
        """按 id 取完整结果"""
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
            row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["result"] = d["result"] if isinstance(d["result"], dict) else json.loads(d["result"] or "{}")
        return d

    def delete_scan(self, scan_id):
        """删除一条历史（含技术明细）"""
        with self.db.transaction() as cur:
            cur.execute("DELETE FROM scan_techs WHERE scan_id = %s", (scan_id,))
            cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        return True

    def history_stats(self):
        """历史统计"""
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute(
                "SELECT COUNT(*) AS scans, COUNT(DISTINCT host) AS hosts,"
                " COALESCE(ROUND(AVG(tech_count)::numeric, 1), 0) AS avg_techs FROM scans")
            row = cur.fetchone()
        return {"scans": row["scans"], "hosts": row["hosts"], "avg_techs": float(row["avg_techs"])}

    def top_techs(self, limit=10):
        """历史扫描中最常见技术 TOP N"""
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute(
                "SELECT name, COUNT(*) AS n FROM scan_techs"
                " GROUP BY name ORDER BY n DESC, name LIMIT %s",
                (limit,))
            return [dict(r) for r in cur.fetchall()]


class JobStore:
    """扫描任务表（异步扫描 / 批量扫描的进度与状态）"""

    def __init__(self, db):
        self.db = db

    def create(self, job_id, kind="scan", payload=None, total=1):
        with self.db.transaction() as cur:
            cur.execute(
                "INSERT INTO jobs (id, kind, status, total, payload)"
                " VALUES (%s,%s,'pending',%s,%s) ON CONFLICT (id) DO NOTHING",
                (job_id, kind, total, Json(payload or {})),
            )

    def update(self, job_id, status=None, progress=None, message=None, done=None, result=None):
        from psycopg2.extras import Json
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE jobs SET"
                " status    = COALESCE(%s, status),"
                " progress  = COALESCE(%s, progress),"
                " message   = COALESCE(%s, message),"
                " done      = COALESCE(%s, done),"
                " result    = COALESCE(%s, result),"
                " updated_at = now()"
                " WHERE id = %s",
                (status, progress, message, done,
                 Json(result) if result is not None else None, job_id),
            )

    def get(self, job_id):
        with self.db.transaction(dict_rows=True) as cur:
            cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
            row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        for key in ("payload", "result"):
            if d.get(key) is not None and not isinstance(d[key], dict):
                d[key] = json.loads(d[key] or "{}")
        return d
