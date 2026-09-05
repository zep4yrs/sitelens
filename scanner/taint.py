# -*- coding: utf-8 -*-
"""轻量污点分析：Python 源码 source → sink 数据流追踪（M8 源码审计升级）。

source（不可信输入）：input() / request.args|form|values|cookies|data|json / sys.argv
sink（危险执行点）：eval / exec / os.system / os.popen / pickle.loads /
                    yaml.load / subprocess 系列
追踪：同函数内变量赋值链 + 字符串拼接/格式化传播。命中即报
「污点数据流入危险函数」——真正的数据流线索，比单行正则准。
"""
import ast

SOURCE_FUNCS = {"input", "raw_input"}
SINKS = {"eval", "exec", "os.system", "os.popen", "pickle.loads",
         "yaml.load", "subprocess.call", "subprocess.run", "subprocess.Popen"}
SEV_BY_SINK = {"eval": "high", "exec": "high", "os.system": "high",
               "os.popen": "high", "pickle.loads": "high", "yaml.load": "high",
               "subprocess.call": "high", "subprocess.run": "medium",
               "subprocess.Popen": "high"}


def _call_name(node):
    """Call 节点的完整点分函数名（os.system / subprocess.run / eval ...）"""
    parts = []
    n = node.func
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    return ".".join(reversed(parts))


def _is_source(node):
    """表达式是否为污点源"""
    if isinstance(node, ast.Call):
        if _call_name(node) in SOURCE_FUNCS:
            return True
        base = node.func
        if isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name) and base.id in ("request", "sys"):
            return True
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        base = node
        while isinstance(base, (ast.Attribute, ast.Subscript)):
            base = base.value
        if isinstance(base, ast.Name) and base.id in ("request", "sys"):
            return True
    return False


def _tainted(node, tainted):
    """表达式是否携带污点（递归子表达式）"""
    if node is None:
        return False
    if _is_source(node):
        return True
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    return any(_tainted(c, tainted) for c in ast.iter_child_nodes(node))


def analyze_file(path):
    """单个 py 文件 → 污点发现列表"""
    from pathlib import Path as _P
    path = _P(path)
    try:
        tree = ast.parse(path.read_text(encoding="utf8"))
    except (SyntaxError, ValueError, OSError):
        return []
    hits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            continue
        tainted = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and _tainted(node.value, tainted):
                for tgt in node.targets:
                    for name in ast.walk(tgt):
                        if isinstance(name, ast.Name):
                            tainted.add(name.id)
            if isinstance(node, ast.Call):
                sink = _call_name(node)
                if sink not in SINKS:
                    continue
                args_tainted = any(_tainted(a, tainted) for a in node.args)
                kw_tainted = any(_tainted(kw.value, tainted) for kw in node.keywords)
                shell_tainted = any(kw.arg == "shell" and _tainted(kw.value, tainted)
                                    for kw in node.keywords)
                if args_tainted or kw_tainted:
                    hits.append({"file": str(path), "line": node.lineno,
                                 "sink": sink, "title": "污点数据流入危险函数: " + sink,
                                 "severity": SEV_BY_SINK.get(sink, "medium"),
                                 "advice": "对来源做白名单校验，禁止未净化输入进入 " + sink})
                elif shell_tainted and sink.startswith("subprocess"):
                    hits.append({"file": str(path), "line": node.lineno,
                                 "sink": sink, "title": "shell=True 且参数含污点",
                                 "severity": SEV_BY_SINK.get(sink, "medium"),
                                 "advice": "改 shell=False + 参数列表"})
    return hits
