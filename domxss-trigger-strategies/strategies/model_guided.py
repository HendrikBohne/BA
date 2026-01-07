"""
DOM XSS Trigger Strategies - Model-Guided Strategy
Lernt Beziehungen zwischen Aktionen für intelligentere Exploration
"""
import random
import logging
from typing import List, Optional, Dict, Set
from playwright.async_api import Page

from .base_strategy import BaseStrategy, ActionCandidate

logger = logging.getLogger(__name__)


class ModelGuidedStrategy(BaseStrategy):
    """
    Model-Guided Random Walk Strategie.
    
    Basiert auf dem Paper "Improving Behavioral Program Analysis with Environment Models"
    Lernt welche Aktionen zu neuen Kandidaten führen und priorisiert diese.
    """
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        
        # Model: Welche Kandidaten führen zu welchen neuen Kandidaten?
        self.successor_map: Dict[str, Set[str]] = {}
        self.last_candidates: List[str] = []
        self.last_action: Optional[str] = None
        
        # Gewichtung für Model vs Random
        self.w_model = self.config.get('w_model', 25.0)
    
    @property
    def name(self) -> str:
        return "Model-Guided"
    
    def _update_model(self, current_candidates: List[ActionCandidate]):
        """Aktualisiert das Successor-Model"""
        if self.last_action:
            current_ids = {c.id for c in current_candidates}
            new_candidates = current_ids - set(self.last_candidates)
            
            if new_candidates:
                if self.last_action not in self.successor_map:
                    self.successor_map[self.last_action] = set()
                self.successor_map[self.last_action].update(new_candidates)
                logger.debug(f"Model: {self.last_action[:30]} → {len(new_candidates)} neue Kandidaten")
        
        self.last_candidates = [c.id for c in current_candidates]
    
    def _calculate_weight(self, candidate: ActionCandidate) -> float:
        """Berechnet Gewicht basierend auf Model"""
        base_weight = candidate.priority
        
        # Bonus für Inputs (XSS-relevant)
        if candidate.has_input:
            base_weight *= 3.0
        
        # Bonus wenn dieser Kandidat zu neuen Kandidaten führt
        if candidate.id in self.successor_map:
            successors = self.successor_map[candidate.id]
            unvisited = len(successors - self.visited_candidates)
            if unvisited > 0:
                base_weight *= (1 + (unvisited / 10.0) * self.w_model)
        
        # Malus wenn oft besucht
        visit_count = self.candidate_history.get(candidate.id, 0)
        if visit_count > 0:
            base_weight /= (1 + visit_count * 0.5)
        
        return base_weight
    
    async def select_next_action(
        self,
        candidates: List[ActionCandidate],
        page: Page
    ) -> Optional[ActionCandidate]:
        """
        Wählt Kandidaten basierend auf Model-Gewichtung.
        Priorisiert Inputs für XSS-Testing.
        """
        if not candidates:
            return None
        
        # Update Model mit aktuellen Kandidaten
        self._update_model(candidates)
        
        # Priorisiere unbesuchte Inputs
        unvisited_inputs = [c for c in candidates 
                          if c.has_input and c.id not in self.visited_candidates]
        if unvisited_inputs:
            selected = random.choice(unvisited_inputs)
            self.last_action = selected.id
            return selected
        
        # Berechne Gewichte für alle Kandidaten
        weights = [self._calculate_weight(c) for c in candidates]
        total = sum(weights)
        
        if total == 0:
            selected = random.choice(candidates)
            self.last_action = selected.id
            return selected
        
        # Gewichtete Zufallsauswahl
        r = random.uniform(0, total)
        cumsum = 0
        for i, w in enumerate(weights):
            cumsum += w
            if r <= cumsum:
                selected = candidates[i]
                self.last_action = selected.id
                return selected
        
        selected = random.choice(candidates)
        self.last_action = selected.id
        return selected
