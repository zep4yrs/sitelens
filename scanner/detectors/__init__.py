# -*- coding: utf-8 -*-
"""检测器包：按证据源划分的五个检测器子类 + TscanPlus 表达式检测器。

Engine 通过 build_detectors() 拿到全部检测器实例，
以统一接口多态调用，新增检测器不影响引擎代码。
"""
from .base import (
    BaseDetector,
    CookieDetector,
    HeaderDetector,
    HtmlDetector,
    MetaDetector,
    ScriptDetector,
)
from .bundle_detector import BundleDetector
from .tscan_detector import TscanDetector


def build_detectors(fingerprints, tscan_fingerprints=None, fetcher=None):
    """工厂：实例化全部检测器（组合进引擎）"""
    detectors = [
        HeaderDetector(fingerprints),
        CookieDetector(fingerprints),
        MetaDetector(fingerprints),
        HtmlDetector(fingerprints),
        ScriptDetector(fingerprints),
    ]
    if tscan_fingerprints:
        detectors.append(TscanDetector(tscan_fingerprints))
    if fetcher is not None:
        detectors.append(BundleDetector(fetcher))
    return detectors


__all__ = [
    "BaseDetector",
    "BundleDetector",
    "HeaderDetector",
    "CookieDetector",
    "MetaDetector",
    "HtmlDetector",
    "ScriptDetector",
    "TscanDetector",
    "build_detectors",
]
