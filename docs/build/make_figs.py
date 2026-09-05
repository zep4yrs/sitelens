# -*- coding: utf-8 -*-
"""实训报告插图生成：架构图 / 类图 / 扫描流程 / 三级判定 / MoE 路由。输出 PNG 到 docs/build/img/"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from pathlib import Path

OUT = Path(__file__).resolve().parent / "img"
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

INK = "#1a1a1a"      # 主文字
PAPER = "#ffffff"    # 背景
BLUE = "#2563eb"     # 主色
BLUE_L = "#dbeafe"   # 主色浅底
SLATE = "#64748b"    # 次级
GREEN = "#16a34a"
GREEN_L = "#dcfce7"
ORANGE = "#d97706"
ORANGE_L = "#fef3c7"
GRAY_L = "#f1f5f9"


def box(ax, x, y, w, h, text, fc=BLUE_L, ec=BLUE, fs=10.5, weight="normal", tc=None, lw=1.2):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                       fc=fc, ec=ec, lw=lw)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            color=tc or INK, weight=weight, linespacing=1.5)


def arrow(ax, x1, y1, x2, y2, color=SLATE, lw=1.4, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=14, color=color, lw=lw))


def new_ax(w, h):
    fig, ax = plt.subplots(figsize=(w, h), dpi=200)
    ax.set_xlim(0, 10); ax.set_ylim(0, 10)
    ax.axis("off")
    fig.patch.set_facecolor(PAPER)
    return fig, ax


# ============ 图 3-1 系统总体架构 ============
fig, ax = new_ax(8.6, 6.9)
ax.set_title("SiteLens 系统总体架构", fontsize=13, weight="bold", color=INK, pad=10)
# 每层 = 若干行，每行若干格 (文本, 宽度)
L = [
    ("展示层", BLUE, GRAY_L, SLATE, [
        [("首页 index.html", 1.75), ("扫描工作台 app.html", 1.75), ("源码审计 / 批量", 1.75), ("历史 / 情报库 / API 文档", 2.05)],
    ]),
    ("应用层", BLUE, GRAY_L, SLATE, [
        [("Flask 页面路由", 2.2), ("REST API（14 组接口）", 2.6), ("异步任务队列（3 并发）", 2.8)],
    ]),
    ("核心层", BLUE, BLUE_L, BLUE, [
        [("目标校验\ntarget.py", 1.72), ("采集·解析·爬取\nfetcher·evidence·crawler", 2.42), ("指纹检测 ×7\ndetectors", 1.72)],
        [("验证引擎\nchecks + Nuclei 模板路由", 2.86), ("情报关联·网络层·源码审计\nvuln·netsec·audit·taint", 3.0)],
    ]),
    ("数据层", BLUE, GRAY_L, SLATE, [
        [("PostgreSQL 18（sitelens 库）", 2.9), ("指纹库 / 漏洞情报 / KEV / CVE", 3.0), ("scans / scan_techs / jobs", 1.96)],
    ]),
]
y = 9.15
for name, ec_, fc_, _lbl, rows in L:
    n_rows = len(rows)
    row_h = 0.52 if any(len(t) > 14 for r in rows for t, _ in r) or n_rows > 1 else 0.62
    hgt = n_rows * (row_h + 0.14) + 0.14
    box(ax, 0.3, y - hgt, 1.5, hgt, name, fc=BLUE, ec=BLUE, tc="white", fs=11.5, weight="bold")
    ry = y - 0.14
    for r in rows:
        total_w = sum(w for _, w in r)
        x = 2.1 + (7.3 - total_w) / 2
        for text, w in r:
            box(ax, x, ry - row_h, w, row_h, text, fc=fc_, ec=ec_, fs=8.4)
            x += w + 0.12
        ry -= row_h + 0.14
    if name != "数据层":
        arrow(ax, 5.2, y - hgt, 5.2, y - hgt - 0.26)
    y = y - hgt - 0.26
plt.tight_layout()
fig.savefig(OUT / "arch.png", bbox_inches="tight", facecolor=PAPER)
plt.close(fig)

# ============ 图 3-2 核心类图（OOP 四特性） ============
fig, ax = new_ax(8.6, 6.8)
ax.set_title("核心类关系图（封装 / 继承 / 多态 / 组合）", fontsize=13, weight="bold", color=INK, pad=10)
# 实体类（封装）
box(ax, 0.3, 8.35, 2.6, 1.25, "«entity» ScanTarget\n-__host / -__scheme\n+url / +validate()",
    fc=GRAY_L, ec=SLATE, fs=8.8)
box(ax, 3.3, 8.35, 2.6, 1.25, "«entity» PageEvidence\n-__html / -__headers\n+set_title() 受控写入",
    fc=GRAY_L, ec=SLATE, fs=8.8)
box(ax, 6.3, 8.35, 2.6, 1.25, "«entity» ScanResult\n-__technologies[]\n+add_technology() 去重合并",
    fc=GRAY_L, ec=SLATE, fs=8.8)
ax.text(5.0, 9.85, "封装：实体类私有属性 + 只读 property", fontsize=9.5, color=SLATE, ha="center")
# 引擎（组合）
box(ax, 2.9, 6.15, 4.2, 1.15, "ScannerEngine（组合根）\n+scan(target, options)\n-run_detectors() 统一调度",
    fc=BLUE, ec=BLUE, tc="white", fs=10, weight="bold")
for xx in (0.9, 3.3, 6.1, 8.5):
    arrow(ax, 5.0, 6.15, xx, 5.35, lw=1.1)
comps = [
    ("Fetcher\n组合 RateLimiter", 0.25, GRAY_L, SLATE),
    ("SiteCrawler\n组合 Fetcher", 2.65, GRAY_L, SLATE),
    ("Registry\n指纹知识库索引", 5.05, GRAY_L, SLATE),
    ("VulnMatcher\n组合 KnowledgeBase", 7.45, GRAY_L, SLATE),
]
for t, x, fc_, ec_ in comps:
    box(ax, x, 4.45, 2.1, 0.9, t, fc=fc_, ec=ec_, fs=8.8)
ax.text(5.0, 4.05, "组合：Engine 拥有 Fetcher / Crawler / Registry / VulnMatcher", fontsize=9.5, color=SLATE, ha="center")
# 继承体系
box(ax, 3.4, 2.5, 3.2, 0.95, "«abstract» BaseDetector\n#detect(evidence, signals)*\n#_match_fingerprint()*",
    fc=GREEN_L, ec=GREEN, fs=9)
subs = ["Header\nDetector", "Cookie\nDetector", "Meta\nDetector", "Html\nDetector", "Script\nDetector",
        "Tscan\nDetector", "Bundle\nDetector"]
for i, s in enumerate(subs):
    x = 0.35 + i * 1.36
    box(ax, x, 0.7, 1.22, 0.85, s, fc=GREEN_L, ec=GREEN, fs=8)
    arrow(ax, 5.0, 2.5, x + 0.61, 1.55, color=GREEN, lw=1.0)
ax.text(5.0, 2.15, "继承 + 多态：7 个子类统一 detect() 接口，新增检测器零改引擎", fontsize=9.5, color=SLATE, ha="center")
plt.tight_layout()
fig.savefig(OUT / "classes.png", bbox_inches="tight", facecolor=PAPER)
plt.close(fig)

# ============ 图 4-1 扫描主流程 ============
fig, ax = new_ax(8.2, 7.6)
ax.set_title("扫描引擎主流程", fontsize=13, weight="bold", color=INK, pad=10)
steps = [
    ("① 目标校验", "协议白名单 / 主机黑名单 / DNS 解析逐 IP 校验（SSRF 防护）", BLUE_L, BLUE),
    ("② 采集", "requests 会话：限速 0.4s / UA 自报 / 超时重试 → PageEvidence", BLUE_L, BLUE),
    ("③ 解析", "BeautifulSoup 拆解 meta / script / DOM / class 证据", BLUE_L, BLUE),
    ("④ 深度爬取（可选）", "同域 BFS ≤4 页，robots.txt 遵循，合并证据", GRAY_L, SLATE),
    ("⑤ 指纹检测", "7 检测器多态运行 ×2850 指纹 → 去重合并置信度", BLUE_L, BLUE),
    ("⑥ 安全评分", "8 项安全响应头加权 → A+–F + 中文修复建议", BLUE_L, BLUE),
    ("⑦ 验证与关联", "Nuclei 模板路由验证 + 情报三级判定 + DAST（可选）", ORANGE_L, ORANGE),
    ("⑧ 持久化", "ScanStore.save_scan → scans / scan_techs，支持导出与 diff", GREEN_L, GREEN),
]
y = 9.35
prev_cy = None
for name, desc, fc_, ec_ in steps:
    box(ax, 0.4, y - 0.72, 2.35, 0.6, name, fc=ec_, ec=ec_, tc="white" if fc_ != GRAY_L else INK, fs=9.6, weight="bold")
    box(ax, 3.0, y - 0.78, 6.55, 0.72, desc, fc=fc_, ec=ec_, fs=8.6)
    if prev_cy is not None:
        arrow(ax, 1.55, prev_cy, 1.55, y, lw=1.3)
    prev_cy = y - 0.72
    y -= 1.18
plt.tight_layout()
fig.savefig(OUT / "flow_main.png", bbox_inches="tight", facecolor=PAPER)
plt.close(fig)

# ============ 图 4-2 情报三级判定流程 ============
fig, ax = new_ax(8.0, 5.6)
ax.set_title("漏洞情报三级判定流程（VulnMatcher.match）", fontsize=13, weight="bold", color=INK, pad=10)
box(ax, 3.35, 9.0, 3.3, 0.62, "识别出的技术 + 版本号", fc=BLUE_L, ec=BLUE, fs=10)
box(ax, 3.35, 7.6, 3.3, 0.62, "匹配 vuln_kb 漏洞情报\n（产品名 trgm 模糊 + 精选区间）", fc=BLUE_L, ec=BLUE, fs=9.2)
arrow(ax, 5.0, 9.0, 5.0, 8.22)
# 分支
box(ax, 0.35, 5.4, 2.9, 1.15, "confirmed\n版本落在 OSV 受影响区间\n（如 Next.js 13.5.1 → CVE-2025-29927）",
    fc=ORANGE_L, ec=ORANGE, fs=8.6)
box(ax, 3.55, 5.4, 2.9, 1.15, "possible\n同名产品但无版本号\n仅提示，不下结论", fc=GRAY_L, ec=SLATE, fs=8.6)
box(ax, 6.75, 5.4, 2.9, 1.15, "excluded\n有版本但落在区间外\n直接过滤，不输出", fc=GREEN_L, ec=GREEN, fs=8.6)
arrow(ax, 4.1, 7.6, 1.8, 6.55)
arrow(ax, 5.0, 7.6, 5.0, 6.55)
arrow(ax, 5.9, 7.6, 8.2, 6.55)
ax.text(1.8, 4.95, "命中 KEV 在野利用清单 → 红标提醒", fontsize=9, color="white",
        bbox=dict(boxstyle="round,pad=0.35", fc="#dc2626", ec="none"))
box(ax, 1.7, 3.0, 6.6, 0.85,
    "version_cmp.version_in()：语义化版本比较\n支持 >=8.3,<8.3.7 / 2.x / * 区间语法",
    fc=BLUE, ec=BLUE, tc="white", fs=8.8)
for xx in (1.8, 5.0, 8.2):
    arrow(ax, xx, 5.4, 5.0, 3.85, lw=1.0)
box(ax, 3.15, 1.6, 3.7, 0.62, "按严重度排序输出情报面板", fc=GRAY_L, ec=SLATE, fs=9.5)
arrow(ax, 5.0, 3.0, 5.0, 2.22)
plt.tight_layout()
fig.savefig(OUT / "verdict.png", bbox_inches="tight", facecolor=PAPER)
plt.close(fig)

# ============ 图 4-3 MoE 式模板路由 ============
fig, ax = new_ax(8.2, 5.4)
ax.set_title("MoE 式 Nuclei 模板三路调度（select_nuclei）", fontsize=13, weight="bold", color=INK, pad=10)
box(ax, 3.3, 9.05, 3.4, 0.66, "已识别技术 tags + 目标上下文\n（title / 指纹名）", fc=BLUE_L, ec=BLUE, fs=9)
arrow(ax, 5.0, 9.05, 5.0, 8.5)
box(ax, 0.3, 7.05, 2.9, 1.35, "① tag 硬匹配置顶\n识别出 WordPress →\nWP 专项模板优先激活", fc=GREEN_L, ec=GREEN, fs=8.8)
box(ax, 3.55, 7.05, 2.9, 1.35, "② 语义向量路由\nTF-IDF 哈希向量余弦排序\n（内容寻址，tags 缺失也可浮出）", fc=BLUE_L, ec=BLUE, fs=8.8)
box(ax, 6.8, 7.05, 2.9, 1.35, "③ 轮转游标兜底\n无语义信号时游标轮转\n保证 2613 模板长期全覆盖", fc=ORANGE_L, ec=ORANGE, fs=8.8)
arrow(ax, 4.2, 8.5, 1.75, 8.4)
arrow(ax, 5.0, 8.5, 5.0, 8.4)
arrow(ax, 5.8, 8.5, 8.25, 8.4)
box(ax, 1.5, 5.3, 7.0, 0.75, "合并取 Top-K（默认 80 条/轮）→ 每轮只激活小子集（Expert 路由思想）",
    fc=BLUE, ec=BLUE, tc="white", fs=9.2)
for xx in (1.75, 5.0, 8.25):
    arrow(ax, xx, 7.05, 5.0, 6.05, lw=1.0)
box(ax, 1.5, 3.7, 7.0, 0.75, "run_nuclei 逐条执行：GET → 软 404 基线比对 → 匹配 → 二次重放确认",
    fc=GRAY_L, ec=SLATE, fs=9.2)
arrow(ax, 5.0, 5.3, 5.0, 4.45)
box(ax, 3.0, 2.25, 4.0, 0.62, "命中 → 「已验证漏洞」入库", fc=ORANGE, ec=ORANGE, tc="white", fs=9.5, weight="bold")
arrow(ax, 5.0, 3.7, 5.0, 2.87)
plt.tight_layout()
fig.savefig(OUT / "moe.png", bbox_inches="tight", facecolor=PAPER)
plt.close(fig)

print("OK", [p.name for p in OUT.glob("*.png")])
