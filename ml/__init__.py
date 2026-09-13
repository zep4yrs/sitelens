"""SiteLens 5.0 ML 预训练流水线（docs/开发文档-5.0-ML预训练.md）。

只读消费 SiteLens 3.0 真实历史数据（data/state/history.json 等），
不修改 3.0/4.0 任何扫描行为。全链路：Dataset → Feature → Label →
Leakage Check → Split → Baseline → ML → Evaluation → Model Manifest。
"""

__version__ = "5.0.0-ml.1"
