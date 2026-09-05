"""SiteLens 站点透视 —— 网站技术指纹识别系统核心包。

分层结构（与考核要求对应）：
- models.py   实体封装（封装）
- target.py   目标校验：URL 解析 + SSRF 防护（封装）
- fetcher.py  HTTP 采集（requests，限速/重试/超时）
- evidence.py 页面证据收集（BeautifulSoup 解析）
- crawler.py  同域浅爬取，提高检出率
- detectors/  检测器继承体系（继承 + 多态）
- engine.py   扫描引擎：组合各组件完成一次完整扫描（组合）
- security.py 安全响应头评分（"安全"检测类）
- registry.py 指纹库加载与检测器注册
- storage.py  SQLite 扫描历史
- exporters.py JSON / CSV / 宽表 CSV 导出
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
