"""
DOM XSS Trigger Strategies - Random Walk Strategy (Fixed v3)
Zufällige Auswahl von Aktionen mit XSS-Payload Injection
"""
import random
import logging
from typing import List, Optional
from playwright.async_api import Page

from .base_strategy import BaseStrategy, ActionCandidate

logger = logging.getLogger(__name__)


class RandomWalkStrategy(BaseStrategy):
    """
    Random Walk Strategie (Baseline).
    
    Wählt zufällig interagierbare Elemente aus.
    Priorisiert Input-Felder für XSS-Testing.
    Klickt auf onclick-Links um dynamische Inhalte zu laden.
    """
    
    @property
    def name(self) -> str:
        return "Random Walk"
    
    async def select_next_action(
        self,
        candidates: List[ActionCandidate],
        page: Page
    ) -> Optional[ActionCandidate]:
        """
        Wählt zufällig einen Kandidaten aus.
        Priorisiert: 1. Inputs, 2. onclick-Links/Buttons, 3. normale Links
        """
        if not candidates:
            return None
        
        # Kategorisiere
        inputs = [c for c in candidates if c.has_input]
        clickables = [c for c in candidates if c.has_event_handler and not c.has_input]
        links = [c for c in candidates if c.element_type == 'link' and not c.has_event_handler]
        
        # 1. HÖCHSTE PRIORITÄT: Unbesuchte Inputs
        unvisited_inputs = [c for c in inputs if c.id not in self.visited_candidates]
        if unvisited_inputs:
            selected = random.choice(unvisited_inputs)
            logger.debug(f"Wähle unbesuchten Input: {selected.text}")
            return selected
        
        # 2. Besuchte Inputs nochmal (anderer Payload) - 30% Chance
        if inputs and random.random() < 0.3:
            selected = random.choice(inputs)
            logger.debug(f"Wähle Input erneut: {selected.text}")
            return selected
        
        # 3. Unbesuchte onclick-Elemente (laden oft dynamische Inhalte!)
        unvisited_clickables = [c for c in clickables if c.id not in self.visited_candidates]
        if unvisited_clickables:
            selected = random.choice(unvisited_clickables)
            logger.debug(f"Wähle unbesuchtes onclick: {selected.text}")
            return selected
        
        # 4. Unbesuchte Links
        unvisited_links = [c for c in links if c.id not in self.visited_candidates]
        if unvisited_links:
            selected = random.choice(unvisited_links)
            logger.debug(f"Wähle unbesuchten Link: {selected.text}")
            return selected
        
        # 5. Fallback: Gewichtete Zufallsauswahl aus allen
        weights = []
        for c in candidates:
            w = c.priority
            # Malus für oft besuchte
            visits = self.candidate_history.get(c.id, 0)
            if visits > 0:
                w /= (1 + visits * 0.5)
            weights.append(max(0.1, w))
        
        total = sum(weights)
        if total == 0:
            return random.choice(candidates)
        
        r = random.uniform(0, total)
        cumsum = 0
        for i, w in enumerate(weights):
            cumsum += w
            if r <= cumsum:
                return candidates[i]
        
        return random.choice(candidates)
