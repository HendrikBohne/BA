"""
SPA Detection Tool - Analyzer Package (v4)
Mit Hard Signal Gating und Anti-Signal für Full Navigation
"""

from .analyzer import SPAAnalyzer, SPAAnalysisResult
from .cookie_handler import CookieHandler
from .interaction_strategy import InteractionStrategy
from .weights import SIGNAL_WEIGHTS, GATING_MULTIPLIER_NO_HARD_SIGNAL, ANTI_SIGNAL_PENALTY_PER_NAVIGATION
from .state_independent_model import StateIndependentModel
from .model_guided_strategy import ModelGuidedStrategy

__all__ = [
    'SPAAnalyzer',
    'SPAAnalysisResult',
    'CookieHandler',
    'InteractionStrategy',
    'SIGNAL_WEIGHTS',
    'GATING_MULTIPLIER_NO_HARD_SIGNAL',
    'ANTI_SIGNAL_PENALTY_PER_NAVIGATION',
    'StateIndependentModel',
    'ModelGuidedStrategy',
]
