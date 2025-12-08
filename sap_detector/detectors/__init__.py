"""
SPA Detection Tool - Detectors Package
Exportiert alle Detector-Klassen für einfachen Import
"""

from .detection_result import DetectionResult
from .history_api_detector import HistoryAPIDetector
from .network_activity_detector import NetworkActivityDetector
from .dom_rewriting_detector import DOMRewritingDetector
from .title_change_detector import TitleChangeDetector
from .clickable_element_detector import ClickableElementDetector

__all__ = [
    'DetectionResult',
    'HistoryAPIDetector',
    'NetworkActivityDetector',
    'DOMRewritingDetector',
    'TitleChangeDetector',
    'ClickableElementDetector',
]