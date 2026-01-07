"""
DOM XSS Trigger Strategies - Strategies Package
Exportiert alle Interaktionsstrategien
"""

from .base_strategy import (
    BaseStrategy,
    ActionCandidate,
    ActionResult,
    StrategyResult,
    XSS_PAYLOADS
)
from .random_walk import RandomWalkStrategy
from .model_guided import ModelGuidedStrategy
from .dom_maximizer import DOMMaximizerStrategy

# Registry aller verfügbaren Strategien
STRATEGIES = {
    'random_walk': RandomWalkStrategy,
    'model_guided': ModelGuidedStrategy,
    'dom_maximizer': DOMMaximizerStrategy,
}

__all__ = [
    'BaseStrategy',
    'ActionCandidate',
    'ActionResult',
    'StrategyResult',
    'XSS_PAYLOADS',
    'RandomWalkStrategy',
    'ModelGuidedStrategy',
    'DOMMaximizerStrategy',
    'STRATEGIES',
]
