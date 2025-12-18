"""
SPA Detection Tool - Analyzer Package
Exportiert Haupt-Analyzer und Helper-Klassen
"""

from .analyzer import SPAAnalyzer, SPAAnalysisResult
from .cookie_handler import CookieHandler
from .interaction_strategy import InteractionStrategy
from .weights import SIGNAL_WEIGHTS
from .state_independent_model import StateIndependentModel  # 
from .model_guided_strategy import ModelGuidedStrategy      # 

__all__ = [
    'SPAAnalyzer',
    'SPAAnalysisResult',
    'CookieHandler',
    'InteractionStrategy',
    'SIGNAL_WEIGHTS',
    'StateIndependentModel',    # 
    'ModelGuidedStrategy',      #
]
