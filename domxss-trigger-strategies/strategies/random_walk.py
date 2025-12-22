"""
DOM XSS Trigger Strategies - Random Walk Strategy
Strategie 1: Zufällige Auswahl von Aktionen (Baseline)
"""
import random
import logging
from typing import List, Optional

from .base_strategy import BaseStrategy, ActionCandidate, ActionResult

logger = logging.getLogger(__name__)


class RandomWalkStrategy(BaseStrategy):
    """
    Random Walk Strategie - Baseline für Vergleiche.
    
    Wählt zufällig aus allen verfügbaren Candidates mit
    leichter Priorisierung von Input-Feldern und Links.
    """
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.prefer_inputs_ratio = self.config.get('prefer_inputs_ratio', 0.4)
        self.prefer_links_ratio = self.config.get('prefer_links_ratio', 0.3)
        
    @property
    def name(self) -> str:
        return "Random Walk"
    
    async def select_next_action(
        self, 
        candidates: List[ActionCandidate]
    ) -> Optional[ActionCandidate]:
        """
        Wählt zufällig einen Candidate.
        
        Priorisierung:
        - 40%: Input-Felder (XSS-relevant)
        - 30%: Links (Navigation)
        - 30%: Alles andere
        """
        if not candidates:
            return None
        
        # Kategorisiere
        inputs = [c for c in candidates if c.element_type == 'input' or c.is_form]
        links = [c for c in candidates if c.element_type == 'link']
        others = [c for c in candidates if c not in inputs and c not in links]
        
        roll = random.random()
        
        if roll < self.prefer_inputs_ratio and inputs:
            selected = random.choice(inputs)
            logger.debug(f"[Random] Input: {selected.text[:30]}")
            
        elif roll < (self.prefer_inputs_ratio + self.prefer_links_ratio) and links:
            # Bevorzuge unbesuchte Links
            unvisited = [l for l in links if l.id not in self.executed_candidates]
            selected = random.choice(unvisited if unvisited else links)
            logger.debug(f"[Random] Link: {selected.text[:30]}")
            
        else:
            selected = random.choice(candidates)
            logger.debug(f"[Random] Other: {selected.text[:30]}")
        
        return selected
    
    async def on_action_completed(
        self, 
        action: ActionCandidate, 
        result: ActionResult,
        new_candidates: List[ActionCandidate]
    ):
        """Random Walk braucht kein Model-Update"""
        pass
