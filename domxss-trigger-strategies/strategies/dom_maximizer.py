"""
DOM XSS Trigger Strategies - DOM Maximizer Strategy
Maximiert die DOM-Größe durch Lazy-Loading und versteckte Inhalte
"""
import random
import logging
from typing import List, Optional, Dict
from playwright.async_api import Page

from .base_strategy import BaseStrategy, ActionCandidate

logger = logging.getLogger(__name__)


class DOMMaximizerStrategy(BaseStrategy):
    """
    DOM Maximizer Strategie.
    
    Ziel: Maximiere die Anzahl der DOM-Elemente durch:
    - Triggern von Lazy-Loading
    - Expandieren von versteckten Inhalten (Accordions, Tabs, etc.)
    - Klicken auf "Load More" Buttons
    
    Priorisiert außerdem Inputs für XSS-Testing.
    """
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.max_dom_seen = 0
        self.dom_growing_candidates: Dict[str, int] = {}
    
    @property
    def name(self) -> str:
        return "DOM Maximizer"
    
    async def _trigger_lazy_loading(self, page: Page):
        """Scrollt die Seite um Lazy-Loading zu triggern"""
        try:
            await page.evaluate("""
                async () => {
                    const scrollStep = window.innerHeight / 2;
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, scrollStep);
                        await new Promise(r => setTimeout(r, 200));
                    }
                    window.scrollTo(0, 0);
                }
            """)
            logger.info("[DOM-Max] Triggering lazy-loading...")
        except Exception as e:
            logger.debug(f"Lazy-loading scroll error: {e}")
    
    async def _expand_hidden_content(self, page: Page):
        """Klickt auf Expander, Tabs, Accordions etc."""
        try:
            await page.evaluate("""
                () => {
                    // Click on collapsed/expandable elements
                    const expanders = document.querySelectorAll(
                        'details:not([open]), ' +
                        '[aria-expanded="false"], ' +
                        '[data-toggle], ' +
                        '.accordion-header:not(.active), ' +
                        '.tab:not(.active), ' +
                        '[class*="expand"], ' +
                        '[class*="collapse"]:not(.show)'
                    );
                    expanders.forEach(el => {
                        try { el.click(); } catch(e) {}
                    });
                }
            """)
            logger.info("[DOM-Max] Expanding hidden content...")
        except Exception as e:
            logger.debug(f"Expand error: {e}")
    
    async def execute(self, page: Page, url: str):
        """Überschreibt execute um initial Lazy-Loading zu triggern"""
        # Initiales Lazy-Loading
        await self._trigger_lazy_loading(page)
        await self._expand_hidden_content(page)
        
        # Dann normale Strategie ausführen
        return await super().execute(page, url)
    
    def _calculate_dom_weight(self, candidate: ActionCandidate) -> float:
        """Berechnet Gewicht basierend auf DOM-Wachstum-Potenzial"""
        base_weight = candidate.priority
        
        # HÖCHSTE PRIORITÄT: Inputs für XSS
        if candidate.has_input:
            base_weight *= 5.0
        
        # Bonus wenn dieser Kandidat DOM-Wachstum verursacht hat
        if candidate.id in self.dom_growing_candidates:
            growth = self.dom_growing_candidates[candidate.id]
            if growth > 0:
                base_weight *= (1 + growth / 5.0)
        
        # Bonus für "Load More" artige Buttons
        text_lower = candidate.text.lower()
        if any(kw in text_lower for kw in ['more', 'load', 'show', 'expand', 'next', 'continue']):
            base_weight *= 2.0
        
        # Bonus für Tabs, Accordions etc.
        if any(kw in candidate.selector.lower() for kw in ['tab', 'accordion', 'expand', 'collapse']):
            base_weight *= 1.5
        
        # Malus für oft besuchte Kandidaten die kein DOM-Wachstum bringen
        visit_count = self.candidate_history.get(candidate.id, 0)
        if visit_count > 0 and candidate.id not in self.dom_growing_candidates:
            base_weight /= (1 + visit_count)
        
        return base_weight
    
    async def select_next_action(
        self,
        candidates: List[ActionCandidate],
        page: Page
    ) -> Optional[ActionCandidate]:
        """
        Wählt Kandidaten die DOM-Wachstum maximieren.
        Priorisiert trotzdem Inputs für XSS-Testing.
        """
        if not candidates:
            return None
        
        # 1. HÖCHSTE PRIORITÄT: Unbesuchte Inputs
        unvisited_inputs = [c for c in candidates 
                          if c.has_input and c.id not in self.visited_candidates]
        if unvisited_inputs:
            return random.choice(unvisited_inputs)
        
        # 2. Bereits besuchte Inputs mit neuem Payload (30% Chance)
        visited_inputs = [c for c in candidates if c.has_input]
        if visited_inputs and random.random() < 0.3:
            return random.choice(visited_inputs)
        
        # 3. DOM-Wachstum maximieren
        weights = [self._calculate_dom_weight(c) for c in candidates]
        total = sum(weights)
        
        if total == 0:
            return random.choice(candidates)
        
        # Gewichtete Auswahl
        r = random.uniform(0, total)
        cumsum = 0
        for i, w in enumerate(weights):
            cumsum += w
            if r <= cumsum:
                return candidates[i]
        
        return random.choice(candidates)
    
    async def perform_action(self, candidate: ActionCandidate, page: Page):
        """Überschreibt perform_action um DOM-Wachstum zu tracken"""
        result = await super().perform_action(candidate, page)
        
        # Tracke DOM-Wachstum
        if result.success and result.dom_change > 0:
            self.dom_growing_candidates[candidate.id] = result.dom_change
            logger.info(f"[DOM-Max] +{result.dom_change} elements from: {candidate.text[:20] or candidate.selector}")
        
        return result
