# -*- coding: utf-8 -*-
"""本地源码静态审计引擎（规则驱动 SAST-lite）。

用法：run_audit(目录或文件路径) → 按规则扫描文本源码，返回发现列表。
规则覆盖：危险函数、SQL 拼接、弱哈希、硬编码密钥、反序列化、
路径穿越、命令注入、XSS、调试残留。跳过 vendor/依赖与二进制文件。

定位是「辅助人工复查的线索」而非漏洞判决——每条发现都带行号与修复建议。
"""
import re
from pathlib import Path

from . import taint

# (id, 严重度, 语言, 标题, 正则, 修复建议)
AUDIT_RULES = [
    ("PY-EVAL", "high", "py", "使用 eval 动态执行", r"\beval\s*\(",
     "改用 ast.literal_eval 或显式解析，eval 可执行任意代码"),
    ("PY-EXEC", "high", "py", "使用 exec 动态执行", r"\bexec\s*\(",
     "避免 exec；确需动态执行时严格白名单校验输入"),
    ("PY-PICKLE", "high", "py", "反序列化 pickle/yaml.load", r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)",
     "pickle 只用于可信数据；yaml.load 必须 Loader=yaml.SafeLoader"),
    ("PY-OSPOPEN", "high", "py", "os.system/popen 命令注入", r"os\.(system|popen)\s*\(",
     "改用 subprocess + 参数列表（shell=False），禁止拼接命令"),
    ("PY-SQLFMT", "high", "py", "SQL 字符串拼接/format", r"execute\s*\(\s*[fF]?['\"](SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*%|\bexecute\s*\(\s*[fF][\"']",
     "全部改占位符 %s 参数绑定，禁止 f-string/format 拼 SQL"),
    ("PY-MD5", "medium", "py", "弱哈希 MD5/SHA1（安全用途）", r"hashlib\.(md5|sha1)\s*\(",
     "口令存储改 bcrypt/argon2；完整性校验改 SHA-256"),
    ("PY-SECRET", "high", "py", "疑似硬编码密钥/口令", r"(password|passwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]{8,}['\"]",
     "凭据移入环境变量或密钥服务，代码不出现字面量"),
    ("PY-DEBUG", "low", "py", "调试残留 debug=True/断点", r"debug\s*=\s*True|set_trace\s*\(",
     "生产关闭 debug；提交前移除断点"),
    ("PY-TEMPFILE", "low", "py", "临时文件可预测（tempfile 名猜用）", r"tempfile\.(mktemp|NamedTemporaryFile)\s*\(",
     "mktemp 有竞态，改 mkstemp"),
    ("PY-RAND", "medium", "py", "安全场景使用随机库 random", r"\brandom\.(random|randint|choice)\s*\(",
     "令牌/密钥类用途改 secrets 模块"),
    ("JS-EVAL", "high", "js", "eval/new Function 动态执行", r"\beval\s*\(|new\s+Function\s*\(",
     "改 JSON.parse 或显式逻辑，eval 是 XSS 注入终点"),
    ("JS-INNERHTML", "medium", "js", "innerHTML 直接赋值（XSS 风险）", r"\.innerHTML\s*=",
     "改 textContent；必须插入 HTML 时先做消毒（DOMPurify）"),
    ("JS-SECRET", "high", "js", "前端疑似硬编码密钥", r"(apikey|api_key|secret|access_token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "前端密钥天然泄露，改服务端代理"),
    ("PHP-CMD", "high", "php", "命令执行函数", r"\b(system|exec|shell_exec|passthru|popen)\s*\(",
     "禁用或严格白名单校验后调用"),
    ("PHP-INCLUDE", "medium", "php", "动态包含（文件包含风险）", r"(include|require)\s*\(?\s*\$",
     "包含路径固定化，禁止变量拼接"),
    ("GEN-IP", "low", "*", "源码含内网 IP 地址", r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])",
     "确认是否应暴露内部拓扑信息"),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".idea", "venv", ".venv",
             "vendor", "dist", "build", "__pycache__", "data", "reference",
             ".mimosa", "server.log"}
TEXT_EXT = {".py", ".js", ".php", ".java", ".go", ".rb", ".html", ".css", ".json",
            ".yaml", ".yml", ".md", ".txt", ".sql", ".sh", ".env", ".ini", ".cfg"}
MAX_SIZE = 1_000_000


def run_audit(root, progress=None):
    """审计目录/单文件，返回 {findings, files, lines, by_severity}"""
    progress = progress or (lambda done, total, msg: None)
    root = Path(root)
    if not root.exists():
        raise ValueError("路径不存在：%s" % root)
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in TEXT_EXT
        and not (set(p.parts) & SKIP_DIRS))
    findings = []
    total_lines = 0
    for i, fp in enumerate(files):
        try:
            if fp.stat().st_size > MAX_SIZE:
                continue
            text = fp.read_text(encoding="utf8", errors="ignore")
        except OSError:
            continue
        total_lines += text.count("\n") + 1
        lines = text.splitlines()
        for rule_id, sev, lang, title, pattern, advice in AUDIT_RULES:
            if lang != "*" and lang != fp.suffix.lstrip(".").lower():
                continue
            for ln, line in enumerate(lines, 1):
                m = re.search(pattern, line, re.I)
                if m:
                    findings.append({
                        "rule": rule_id, "severity": sev, "title": title,
                        "file": str(fp), "line": ln,
                        "snippet": line.strip()[:160],
                        "match": m.group(0)[:60], "advice": advice,
                    })
        progress(i + 1, len(files), fp.name)
    # Python 文件追加污点数据流分析（TAINT 规则族）
    for fp in files:
        if fp.suffix.lower() == ".py":
            for f in taint.analyze_file(fp):
                findings.append({"rule": "TAINT-" + f["sink"], "severity": f["severity"],
                                 "title": f["title"], "file": f["file"], "line": f["line"],
                                 "snippet": "", "match": "", "advice": f["advice"]})
    sev_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 3), f["file"], f["line"]))
    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f["severity"]] += 1
    return {"findings": findings, "files": len(files), "lines": total_lines,
            "by_severity": by_sev}
