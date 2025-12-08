"""
SPA Detection Tool - Analyzer Package
"""
from .analyzer import SPAAnalyzer, SPAAnalysisResult
from .cookie_handler import CookieHandler
from .interaction_strategy import InteractionStrategy
from .weights import SIGNAL_WEIGHTS

__all__ = [
    'SPAAnalyzer',
    'SPAAnalysisResult',
    'CookieHandler',
    'InteractionStrategy',
    'SIGNAL_WEIGHTS',
]
