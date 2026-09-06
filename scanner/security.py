"""安全响应头评估：SiteLens 的「安全」检测类。

对照 securityheaders.com 的思路，检查 7 个安全响应头是否配置，
按重要性加权打分并给出 A-F 等级与中文修复建议。
"""

# (头名, 权重, 说明, 修复建议)
CHECK_ITEMS = [
    ("strict-transport-security", 20,
     "强制 HTTPS（HSTS）", "添加 Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", 20,
     "内容安全策略（CSP）防 XSS", "添加 Content-Security-Policy，先 report-only 观察再强制"),
    ("x-frame-options", 10,
     "防点击劫持", "添加 X-Frame-Options: SAMEORIGIN 或用 CSP frame-ancestors"),
    ("x-content-type-options", 10,
     "禁止 MIME 嗅探", "添加 X-Content-Type-Options: nosniff"),
    ("referrer-policy", 10,
     "控制引用来源泄露", "添加 Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", 10,
     "限制摄像头/麦克风等能力", "添加 Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    ("cross-origin-opener-policy", 10,
     "跨窗口隔离（COOP）", "添加 Cross-Origin-Opener-Policy: same-origin"),
    ("cross-origin-resource-policy", 10,
     "跨域资源隔离（CORP）", "添加 Cross-Origin-Resource-Policy: same-origin"),
]


class SecurityReport:
    """一次安全响应头评估的结果（封装）"""

    GRADE_STEPS = [(90, "A+"), (80, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]

    def __init__(self):
        self.__items = []       # {header, present, value, weight, note, advice}
        self.__score = 0

    def assess(self, evidence):
        """按检查清单逐项评估响应头"""
        total = sum(w for _, w, _, _ in CHECK_ITEMS)
        earned = 0
        for header, weight, note, advice in CHECK_ITEMS:
            value = evidence.header(header)
            present = bool(value)
            if present:
                earned += weight
            self.__items.append({
                "header": header,
                "present": present,
                "value": value[:120],
                "weight": weight,
                "note": note,
                "advice": advice,
            })
        self.__score = round(earned / total * 100)

    @property
    def score(self):
        return self.__score

    @property
    def grade(self):
        for floor, grade in self.GRADE_STEPS:
            if self.__score >= floor:
                return grade
        return "F"

    @property
    def items(self):
        return list(self.__items)

    def to_dict(self):
        return {"score": self.__score, "grade": self.grade, "items": self.__items}


def assess_security(evidence):
    """评估入口：返回 SecurityReport 并作为技术项「安全响应头」呈现在结果里"""
    report = SecurityReport()
    report.assess(evidence)
    return report
