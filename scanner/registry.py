# -*- coding: utf-8 -*-
"""指纹注册表：加载校验自建指纹与 TscanPlus 指纹（数据存 PostgreSQL）。

校验规则：
- 类别引用必须存在于 categories 表；
- 正则字段（headers/cookies/meta/html-html/scripts）必须可编译；
- dom 字段是 CSS 选择器（交给 BeautifulSoup），不做正则编译。
"""
import re

from .db import Database, KnowledgeBase, load_env
from .fingerprints.builtin_fp import CATEGORIES as BUILTIN_CATEGORIES


def validate_fingerprints(fingerprints, category_ids):
    """启动期校验指纹数据，返回错误列表（空列表 = 通过）"""
    errors = []
    for fp in fingerprints:
        name = fp.get("name", "?")
        for cat in fp.get("cats", []):
            if category_ids is not None and cat not in category_ids:
                errors.append("%s: 未知类别 %s" % (name, cat))
        for field, rule in (fp.get("rules") or {}).items():
            patterns = []
            if isinstance(rule, dict):
                for key, value in rule.items():
                    values = value if isinstance(value, list) else [value]
                    for v in values:
                        # html/dom 是 CSS 选择器，不做正则编译
                        if not (field == "html" and key == "dom"):
                            patterns.append(v)
            elif isinstance(rule, list):
                patterns = rule
            for p in patterns:
                try:
                    re.compile(p, re.I)
                except re.error as e:
                    errors.append("%s(%s): 正则错误 %s -> %s" % (name, field, p, e))
    return errors


class Registry:
    """引擎用的统一指纹入口：自建指纹 + TscanPlus 指纹 + 主动指纹。

    数据源是 PostgreSQL（KnowledgeBase 载入内存），本类只做校验与转发，
    保证 engine 依赖稳定接口、与存储实现解耦。
    """

    def __init__(self, kb=None, validate=True):
        self.kb = kb or KnowledgeBase(Database(load_env()))
        kb = self.kb

        if not kb.fingerprints:
            # 空库（首次部署）：把内置精编指纹写入数据库后重新加载
            self._seed_builtin()
        self.fingerprints = kb.fingerprints
        self.by_name = kb.by_name
        self.tscan = kb.tscan
        self.fingerdir = kb.fingerdir
        self.categories = kb.categories
        if validate:
            errors = validate_fingerprints(self.fingerprints, set(self.categories))
            tscan_as_fp = [{"name": t["name"], "cats": [t["cat"]], "rules": {}} for t in self.tscan]
            errors += validate_fingerprints(tscan_as_fp, set(self.categories))
            if errors:
                raise ValueError("指纹库校验失败：\n" + "\n".join(errors[:20]))

    def _seed_builtin(self):
        """首次部署：写入类别与自建指纹"""
        from psycopg2.extras import Json
        with self.kb.db.transaction() as cur:
            for ord_, (cat_id, name, icon) in enumerate(BUILTIN_CATEGORIES):
                cur.execute(
                    "INSERT INTO categories (id, name, icon, ord) VALUES (%s,%s,%s,%s)"
                    " ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, icon=EXCLUDED.icon,"
                    " ord=EXCLUDED.ord",
                    (cat_id, name, icon, ord_))
            for fp in _builtin_fingerprints():
                cur.execute(
                    "INSERT INTO technologies (name, cats, conf, website, rules)"
                    " VALUES (%s,%s,%s,%s,%s) ON CONFLICT (name) DO UPDATE"
                    " SET cats=EXCLUDED.cats, conf=EXCLUDED.conf,"
                    " website=EXCLUDED.website, rules=EXCLUDED.rules",
                    (fp["name"], fp["cats"], fp["conf"], fp["website"], Json(fp["rules"])))
        self.kb.load()

    def category_name(self, cat_id):
        return self.kb.category_name(cat_id)

    def stats(self):
        return self.kb.stats()

    def vulns_for(self, tech_name):
        return self.kb.vulns_for(tech_name)

    def search_vulns(self, text, limit=30):
        return self.kb.search_vulns(text, limit=limit)


def _builtin_fingerprints():
    from .fingerprints.builtin_fp import FINGERPRINTS
    return FINGERPRINTS
