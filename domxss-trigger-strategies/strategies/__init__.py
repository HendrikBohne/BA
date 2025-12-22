"""
DOM XSS Trigger Strategies - Strategies Package
"""

from .base_strategy import (
    BaseStrategy,
    ActionCandidate,
    ActionResult,
    StrategyResult
)
from .random_walk import RandomWalkStrategy
from .model_guided import ModelGuidedStrategy, StateIndependentModel
from .dom_maximizer import DOMMaximizerStrategy

__all__ = [
    'BaseStrategy',
    'ActionCandidate', 
    'ActionResult',
    'StrategyResult',
    'RandomWalkStrategy',
    'ModelGuidedStrategy',
    'DOMMaximizerStrategy',
    'StateIndependentModel',
    'STRATEGIES'
]

# Strategie-Registry
STRATEGIES = {
    'random_walk': RandomWalkStrategy,
    'model_guided': ModelGuidedStrategy,
    'dom_maximizer': DOMMaximizerStrategy,
}
