# -*- coding: utf-8 -*-
"""资产导入管线：把「漏洞收集」包全部资产导入 PostgreSQL。

输入：漏洞收集(2).zip（TscanPlus/afrog/xray POC、web 指纹库、nmap 服务指纹、
      FingerDir 主动指纹、目录/子域名字典、JWT 字典、CVE 知识库 CSV）
输出（PG 表）：categories / technologies（内置精编指纹，首次自动播种）
              tscan_fingerprints / fingerdir / service_fp / vuln_kb(含语义向量)
输出（文件）：data/wordlists/（目录/子域名字典）、data/import-report.txt

合规说明：
- POC 只提取元数据（名称/CVE/产品/等级/参考链接），攻击载荷一律不落盘；
- 弱口令/WebShell/红队配置仅存档 data/asset-extras/，不接入任何功能。

用法：在项目根目录执行  python tools/import_assets.py
"""
import csv
import io
import os
import re
import sys
import zipfile
from pathlib import Path

import psycopg2.extras
import yaml

ROOT = Path(__file__).resolve().parents[1]      # 项目根（tools/ 的上级）
WL_DIR = ROOT / "data" / "wordlists"
EXTRAS_DIR = ROOT / "data" / "asset-extras"
ZIP_PATH = Path("漏洞收集(2).zip")   # 本地资产包路径：放到项目根目录，或改为你的实际路径

sys.path.insert(0, str(ROOT))

from scanner.db import Database, KnowledgeBase, load_env  # noqa: E402
from scanner.embedding import embed_text                  # noqa: E402
from scanner.registry import Registry                     # noqa: E402

report = []


def log(msg):
    print(msg)
    report.append(msg)


def safe_extract_target(base_dir, zip_name):
    """zip 条目落盘路径：剥目录 + resolve + 边界校验（防路径穿越）。

    返回的 Path 已限定在 base_dir 内，调用方用 write_bytes 落盘。
    """
    target = (Path(base_dir) / Path(zip_name).name).resolve()
    base = Path(base_dir).resolve()
    if not target.is_relative_to(base):
        raise ValueError("zip 条目路径非法：%s" % zip_name)
    return target


# ---------------------------------------------------------------- tscan 指纹
CAT_KEYWORDS = [
    (("nginx", "apache", "iis", "tomcat", "openresty", "tengine", "caddy", "litespeed", "jetty", "weblogic", "websphere", "jboss", "undertow"), "web-server"),
    (("wordpress", "drupal", "joomla", "typecho", "halo", "dedecms", "empire", "ghost", "typo3", "craft", "umbraco", "mediawiki", "confluence", "dokuwiki"), "cms"),
    (("mysql", "redis", "mongodb", "postgres", "pgsql", "oracle", "sqlserver", "mssql", "elasticsearch", "memcached", "influxdb", "clickhouse", "tidb"), "database"),
    (("phpmyadmin", "adminer", "adminmongo", "mongo-express"), "db-manager"),
    (("spring", "laravel", "django", "flask", "thinkphp", "codeigniter", "rails", "express", "gin", "beego", "struts", "fastjson", "jackson"), "web-framework"),
    (("react", "vue", "angular", "next", "nuxt", "svelte", "webpack", "vite", "bootstrap", "jquery", "element", "antd", "ant-design"), "js-framework"),
    (("shopify", "magento", "prestashop", "opencart", "woocommerce", "ecshop", "shopxo", "crmeb"), "ecommerce"),
    (("grafana", "kibana", "zabbix", "prometheus", "nagios", "cacti", "metabase", "superset", "skywalking", "sonarqube", "jenkins", "gitlab", "gitea"), "dashboard"),
    (("router", "switch", "firewall", "vpn", "gateway", "netgear", "tplink", "tp-link", "huawei", "h3c", "ruijie", "锐捷", "交换机", "路由器", "深信服", "sangfor", "hillstone", "山石", "juniper", "cisco", "思科", "fortinet", "fortigate", "pfsense", "openwrt", "mikrotik"), "network-device"),
    (("camera", "dvr", "nvr", "hikvision", "海康", "dahua", "大华", "uniview", "宇视", "监控", "ipc", "webcam", "surveillance"), "camera"),
    (("oa", "通达", "泛微", "weaver", "ecology", "致远", "seeyon", "landray", "蓝凌", "tongda", "用友", "yonyou", "金蝶", "kingdee", "erp", "crm", "hrm"), "oa"),
    (("waf", "safedog", "安全狗", "云锁", "yunsuo", "imperva", "incapsula", "akamai", "f5", "big-ip", "长亭", "雷池", "safe3", "知道创宇"), "waf"),
    (("panel", "面板", "cpanel", "plesk", "bt.cn", "baota", "宝塔", "1panel", "aapanel", "webmin", "vesta"), "host-panel"),
    (("mail", "smtp", "imap", "webmail", "postfix", "exchange", "coremail", "tmail", "umail", "winwebmail"), "email"),
    (("nacos", "consul", "etcd", "zookeeper", "eureka", "apollo", "sentinel", "dubbo", "kafka", "rabbitmq", "rocketmq", "activemq", "minio", "fastdfs", "nexus", "artifactory"), "middleware"),
    (("harbor", "rancher", "kubernetes", "k8s", "docker", "portainer"), "devops"),
]


def guess_category(name):
    low = name.lower()
    for keywords, cat in CAT_KEYWORDS:
        for kw in keywords:
            if kw in low:
                return cat
    return "misc"


def parse_tscan_expr(expr):
    """解析 TscanPlus 表达式：a="x" && b!="y" || c="z" → OR 组列表。

    返回 (groups, skipped_banner)。每组是 [(field, negated, value)]。
    """
    groups = []
    skipped_banner = 0
    for or_part in re.split(r"\s*\|\|\s*", expr):
        conds = []
        ok = True
        for token in re.split(r"\s*&&\s*", or_part):
            m = re.match(r'(\w+)\s*(!=|=)\s*"(.*)"\s*$', token.strip(), re.S)
            if not m:
                ok = False
                break
            field, op, value = m.group(1), m.group(2), m.group(3)
            if field == "banner":          # 服务层横幅，web 上下文不评估
                skipped_banner += 1
                ok = False
                break
            if field not in ("body", "title", "header", "icon_hash"):
                ok = False
                break
            conds.append({"f": field, "n": op == "!=", "v": value})
        if ok and conds:
            groups.append(conds)
    return groups, skipped_banner


def import_tscan_fp(db, z):
    """web 产品指纹库 → tscan_fingerprints 表"""
    data = yaml.safe_load(
        z.read("指纹库/web产品指纹库_3130产品_3601规则.yaml").decode("utf8", errors="replace"))
    out = []
    n_groups = n_conds = skipped = 0
    for product, rules in (data or {}).items():
        groups = []
        for expr in rules or []:
            g, sk = parse_tscan_expr(str(expr))
            skipped += sk
            for item in g:
                groups.append(item)
                n_groups += 1
                n_conds += len(item)
        if groups:
            out.append({"name": product, "cat": guess_category(product), "groups": groups})
    with db.transaction() as cur:
        cur.execute("DELETE FROM tscan_fingerprints")
        psycopg2.extras.execute_batch(cur,
            "INSERT INTO tscan_fingerprints (name, cat, groups) VALUES (%s,%s,%s)",
            [(t["name"], t["cat"], psycopg2.extras.Json(t["groups"])) for t in out])
    log(f"[tscan指纹] 产品 {len(out)}，OR组 {n_groups}，条件 {n_conds}，跳过 banner 条件 {skipped}")


def import_fingerdir(db, z):
    """主动路径指纹 → fingerdir 表"""
    data = yaml.safe_load(z.read("指纹库/FingerDir.yaml").decode("utf8", errors="replace"))
    out = {}
    total = 0
    for product, spec in (data or {}).items():
        if not isinstance(spec, dict) or not spec.get("paths"):
            continue
        m = spec.get("matchers") or {}
        out[product] = {
            "paths": list(spec["paths"])[:6],
            "status": m.get("status") or [200],
            "body_contains": m.get("body_contains") or [],
            "body_not_contains": m.get("body_not_contains") or [],
            "content_type": m.get("content_type") or [],
            "header_contains": m.get("header_contains") or [],
        }
        total += min(len(spec["paths"]), 6)
    with db.transaction() as cur:
        cur.execute("DELETE FROM fingerdir")
        psycopg2.extras.execute_batch(cur,
            "INSERT INTO fingerdir (product, spec) VALUES (%s,%s)",
            [(p, psycopg2.extras.Json(s)) for p, s in out.items()])
    log(f"[主动指纹] 产品 {len(out)}，路径 {total} 条")


def import_service_fp(db, z):
    """nmap 风格服务指纹 → service_fp 表"""
    text = z.read("指纹库/服务指纹库_nmap风格_11951match.txt").decode("utf8", errors="replace")
    pat = re.compile(r'^(soft)?match\s+(\S+)\s+m([|@#~%])(.*?)\3(.*)$')
    extra = re.compile(r'([pviod])/([^/]*)/')
    rows = []
    bad = 0
    for line in text.splitlines():
        m = pat.match(line.strip())
        if not m:
            continue
        soft, service, delim, pattern, rest = m.groups()
        fields = dict(extra.findall(rest))
        py_pattern = pattern.replace("\\0", "\\x00")
        try:
            re.compile(py_pattern, re.I)
        except re.error:
            bad += 1
            continue
        rows.append((service, py_pattern, fields.get("p", service), fields.get("v", ""), bool(soft)))
    with db.transaction() as cur:
        cur.execute("DELETE FROM service_fp")
        psycopg2.extras.execute_batch(cur,
            "INSERT INTO service_fp (service, pattern, product, version, soft)"
            " VALUES (%s,%s,%s,%s,%s)", rows)
    log(f"[服务指纹] 规则 {len(rows)} 条，跳过编译失败 {bad} 条")


# ---------------------------------------------------------------- POC → 漏洞情报
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TYPE_MAP = {
    "rce": "远程代码执行", "deserialization": "反序列化", "directory_traversal": "目录遍历",
    "file_upload": "文件上传", "file_read": "任意文件读取", "unauthorized_access": "未授权访问",
    "ssrf": "SSRF", "sqli": "SQL注入", "sql_injection": "SQL注入", "xss": "XSS",
    "logical": "逻辑漏洞", "info_leak": "信息泄露", "password": "弱口令", "bypass": "绕过",
    "spoof": "欺骗", "csrf": "CSRF", "xxe": "XXE", "other": "其他", "cve": "CVE漏洞",
}


def norm_sev(s, name=""):
    s = (s or "").lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    low = name.lower()
    if "rce" in low or "代码执行" in low:
        return "critical"
    if any(k in low for k in ("traversal", "upload", "deserial", "sqli", "注入")):
        return "high"
    return "medium"


def product_from_poc_name(name):
    """yaml-poc-<vendor>-<product>-<type>-<id> → 产品关键词串"""
    m = re.match(r"yaml-poc-([a-z0-9_]+)-([a-z0-9_.]+)-", name, re.I)
    if m:
        return (m.group(1) + " " + m.group(2)).replace("_", " ")
    return ""


def extract_poc_meta(name, data):
    """从单个 POC yaml（afrog/xray/tscan 兼容）提取元数据，不碰 rules/payload"""
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    poc_name = str(data.get("name") or info.get("name") or data.get("id") or name)
    cve_m = CVE_RE.search(poc_name + " " + str(data.get("id") or ""))
    sev = info.get("severity") or data.get("severity") or ""
    product = ""
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = tags.split(",")
    tags = [t.strip() for t in tags if t.strip()]
    generic = {"cve", "vuln", "poc", str(cve_m.group(0).lower()) if cve_m else ""}
    prod_tags = [t for t in tags if t.lower() not in generic and not t.lower().startswith("cve")]
    if prod_tags:
        product = " ".join(prod_tags[:3])
    else:
        product = product_from_poc_name(poc_name)
    vtype = ""
    low = poc_name.lower()
    for k, v in TYPE_MAP.items():
        if k in low:
            vtype = v
            break
    if not vtype and prod_tags:
        vtype = TYPE_MAP.get(prod_tags[-1].lower(), "")
    ref = ""
    links = []
    detail = data.get("detail") or {}
    if isinstance(detail, dict):
        links = detail.get("links") or []
    if not links:
        links = info.get("reference") or info.get("links") or []
    for l in links or []:
        if "nvd.nist.gov" in str(l):
            ref = str(l)
            break
    ref = ref or (str(links[0]) if links else "")
    desc = str(info.get("description") or "")[:400]
    return {
        "src": "afrog" if "afrog" in name else ("xray" if "xray" in name else "tscan"),
        "name": poc_name[:160],
        "product": product[:80],
        "cve": cve_m.group(0).upper() if cve_m else "",
        "type": vtype,
        "severity": norm_sev(sev, poc_name),
        "ref": ref[:200],
        "desc": desc,
    }


def import_vulnkb(db, z):
    """POC 元数据 → vuln_kb 表（含语义向量）。PG text 不收 NUL，先清洗。"""
    def nz(s):
        return str(s).replace("\x00", "").replace("\r", " ")
    src_dirs = {
        "POC库/afrog-完整POC_1642个/": "afrog",
        "POC库/xray-完整POC_860个/": "xray",
        "POC库/TscanPlus-完整POC_9039个/": "tscan",
    }
    counts = {"afrog": 0, "xray": 0, "tscan": 0, "skip": 0}
    rows = []
    for n in z.namelist():
        src = None
        for d, tag in src_dirs.items():
            if n.startswith(d) and n.endswith((".yaml", ".yml")):
                src = tag
                break
        if not src:
            continue
        try:
            data = yaml.safe_load(z.read(n).decode("utf8", errors="replace"))
        except Exception:
            counts["skip"] += 1
            continue
        meta = extract_poc_meta(n, data)
        if meta and (meta["product"] or meta["cve"]):
            counts[src] += 1
            vec_text = " ".join([meta["product"], meta["name"], meta["type"], meta["desc"][:160]])
            rows.append((nz(meta["src"]), nz(meta["name"]), nz(meta["product"]), nz(meta["cve"]),
                         nz(meta["type"]), nz(meta["severity"]), nz(meta["ref"]), nz(meta["desc"]),
                         embed_text(nz(vec_text))))
        else:
            counts["skip"] += 1
    with db.transaction() as cur:
        cur.execute("DELETE FROM vuln_kb")
        psycopg2.extras.execute_batch(cur,
            "INSERT INTO vuln_kb (src, name, product, cve, type, severity, ref, descr, embedding)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", rows, page_size=500)
    log(f"[漏洞情报] 导入 {len(rows)} 条（afrog {counts['afrog']} / xray {counts['xray']} /"
        f" tscan {counts['tscan']}，跳过 {counts['skip']}）")


def import_cve_csv(db, z):
    """微软安全公告 CSV → cve_ms 表（去重索引）"""
    with db.transaction() as cur:
        cur.execute("DROP TABLE IF EXISTS cve_ms")
        cur.execute("CREATE TABLE cve_ms ("
                    " id SERIAL PRIMARY KEY,"
                    " cve TEXT, component TEXT, title TEXT,"
                    " severity TEXT, impact TEXT, date TEXT)")
        rows = []
        seen = set()
        with z.open("CVE知识库/CheckKB-CVEs_Windows安全公告_135MB.csv") as f:
            reader = csv.DictReader(io.TextIOWrapper(f, encoding="utf8", errors="replace"))
            for r in reader:
                key = (r.get("CVE"), r.get("AffectedComponent"), r.get("Title"))
                if key in seen or not key[0]:
                    continue
                seen.add(key)
                rows.append((key[0], key[1] or "", (r.get("Title") or "")[:200],
                             r.get("Severity") or "", r.get("Impact") or "",
                             r.get("DatePosted") or ""))
                if len(rows) >= 5000:
                    psycopg2.extras.execute_batch(cur,
                        "INSERT INTO cve_ms (cve, component, title, severity, impact, date)"
                        " VALUES (%s,%s,%s,%s,%s,%s)", rows, page_size=1000)
                    rows = []
        if rows:
            psycopg2.extras.execute_batch(cur,
                "INSERT INTO cve_ms (cve, component, title, severity, impact, date)"
                " VALUES (%s,%s,%s,%s,%s,%s)", rows, page_size=1000)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_ms_comp ON cve_ms(component)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_ms_cve ON cve_ms(cve)")
    with db.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS n, COUNT(DISTINCT cve) AS c FROM cve_ms")
        n, c = cur.fetchone()
    log(f"[CVE索引] 去重后 {n} 行，覆盖 {c} 个 CVE")


# ---------------------------------------------------------------- 字典
def read_zip_lines(z, zipname, limit=None):
    with z.open(zipname) as f:
        lines = [l.strip() for l in f.read().decode("utf8", errors="ignore").splitlines()]
    lines = [l for l in lines if l and not l.startswith("#")]
    return lines[:limit] if limit else lines


def import_wordlists(z):
    """字典资产：全量存档 + 精选默认表（目录探测/子域名模块用）。

    zip 解包防路径穿越：条目剥目录后经 safe_extract_target 校验边界，
    用 Path.write_bytes 落盘。
    """
    WL_DIR.mkdir(parents=True, exist_ok=True)
    full = WL_DIR / "full"
    full.mkdir(parents=True, exist_ok=True)
    copied = 0
    for i in z.infolist():
        n = i.filename
        if any(k in n for k in ("字典/目录字典DirDict/", "字典/子域名字典SubDict/",
                                "字典/4xx绕过模块/", "JWT字典", "弱口令字典")) and not n.endswith("/"):
            safe_extract_target(full, n).write_bytes(z.read(n))
            copied += 1
    log(f"[字典] 全量资产 {copied} 个 → data/wordlists/full/")

    merged = []
    for zipname, limit in [
        ("字典/目录字典DirDict/dir-9.6k.txt", 900),
        ("字典/目录字典DirDict/admindir-1.2w.txt", 300),
        ("字典/目录字典DirDict/editor-4.5k.txt", 150),
        ("字典/目录字典DirDict/Backup-5.7k.txt", 150),
        ("字典/目录字典DirDict/spring-0.4k.txt", None),
        ("字典/目录字典DirDict/xiaotc-phpmyadmin-6.4k.txt", 80),
    ]:
        merged.extend(read_zip_lines(z, zipname, limit))
    seen = set()
    dedup = [p for p in merged if not (p in seen or seen.add(p))]
    (WL_DIR / "dir_default.txt").write_text("\n".join(dedup), encoding="utf8")
    log(f"[目录默认表] {len(dedup)} 条")

    subs = read_zip_lines(z, "字典/子域名字典SubDict/submin.txt") + \
        read_zip_lines(z, "字典/子域名字典SubDict/subnames-9.5w.txt", 800)
    seen = set()
    subs = [p for p in subs if not (p in seen or seen.add(p))]
    (WL_DIR / "subs_default.txt").write_text("\n".join(subs), encoding="utf8")
    log(f"[子域默认表] {len(subs)} 条")

    EXTRAS_DIR.mkdir(parents=True, exist_ok=True)
    for n in z.namelist():
        if "红队配置/" in n and not n.endswith("/"):
            safe_extract_target(EXTRAS_DIR, n).write_bytes(z.read(n))
    (EXTRAS_DIR / "_说明.txt").write_text(
        "弱口令字典/WebShell字典/红队命令/组件下载 仅作资料存档，未接入 SiteLens 任何自动化"
        "功能——对未授权目标进行口令爆破或 WebShell 探测属于攻击行为。如需在授权测试中使用，"
        "请自行取出并配合专业工具。\n", encoding="utf8")
    log("[存档] 红队配置 → data/asset-extras/（不接入功能）")


def main():
    log("== SiteLens 资产导入 ==")
    db = Database(load_env())
    reg = Registry(kb=KnowledgeBase(db))
    st = reg.stats()
    log(f"[内置库] 类别 {st['categories']}，精编指纹 {st['curated']}")

    z = zipfile.ZipFile(str(ZIP_PATH))
    import_tscan_fp(db, z)
    import_fingerdir(db, z)
    import_service_fp(db, z)
    import_vulnkb(db, z)
    import_cve_csv(db, z)
    import_wordlists(z)
    (ROOT / "data" / "import-report.txt").write_text("\n".join(report), encoding="utf8")
    log("== 完成，报告见 data/import-report.txt ==")


if __name__ == "__main__":
    main()
