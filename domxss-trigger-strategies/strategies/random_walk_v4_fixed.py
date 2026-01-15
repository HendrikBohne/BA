"""
DOM XSS Trigger Strategies - Random Walk Strategy (v4 - Robust)

Verbesserungen v4:
- Nutzt robuste BaseStrategy-Methoden
- Bessere Fehlerbehandlung
- Unterscheidung kritische/nicht-kritische Fehler
- Wartet auf stabilen DOM nach Aktionen
- Gibt StrategyResult zurück
"""
import asyncio
import random
import logging
from typing import Dict, Any, List
from playwright.async_api import Page

from .base_strategy import BaseStrategy, ActionCandidate, StrategyResult

logger = logging.getLogger(__name__)


class RandomWalkStrategy(BaseStrategy):
    """
    Random Walk Strategie mit intelligenter Priorisierung.
    
    Priorisierung:
    1. Unbesuchte Input-Felder (höchste Priorität - XSS-Payloads)
    2. Besuchte Inputs (niedrigere Priorität - andere Payloads testen)
    3. Unbesuchte onclick-Elemente (laden dynamische Inhalte)
    4. Unbesuchte Links/Buttons
    5. Gewichtete Zufallsauswahl aus Rest
    """
    
    def __init__(self, config: dict = None):
        config = config or {}
        passive = config.get('passive', False)
        super().__init__(name="random_walk", passive=passive)
        self.config = config
    
    async def run(self, page: Page, max_actions: int = 50) -> StrategyResult:
        """Führt Random Walk aus"""
        
        logger.info(f"🚀 Starte Random Walk")
        logger.info(f"   URL: {page.url}")
        logger.info(f"   Max Actions: {max_actions}")
        
        # Initiale DOM-Größe
        self.initial_dom_size = await self.get_dom_size(page)
        self.current_dom_size = self.initial_dom_size
        
        start_time = asyncio.get_event_loop().time()
        
        action_count = 0
        consecutive_failures = 0
        max_consecutive_failures = 5
        
        while action_count < max_actions and self.should_continue():
            try:
                # Hole aktuelle Candidates
                candidates = await self.get_action_candidates(page)
                
                if not candidates:
                    logger.debug("Keine Candidates gefunden, warte...")
                    await asyncio.sleep(1)
                    consecutive_failures += 1
                    self.record_error(critical=False)
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.warning("Keine interaktiven Elemente gefunden, breche ab")
                        break
                    continue
                
                # Wähle nächste Aktion
                candidate = self._select_candidate(candidates)
                
                if not candidate:
                    consecutive_failures += 1
                    self.record_error(critical=False)
                    continue
                
                # Führe Aktion aus
                prev_dom_size = self.current_dom_size
                result = await self.perform_action(page, candidate)
                
                if result.success:
                    action_count += 1
                    self.actions_performed += 1
                    consecutive_failures = 0
                    self.reset_error_count()
                    
                    # Markiere als besucht
                    self.visited_selectors.add(candidate.selector)
                    
                    # Warte auf DOM-Stabilität
                    await self.wait_for_stable_dom(page, timeout=1.0)
                    
                    # Update DOM-Größe
                    self.current_dom_size = await self.get_dom_size(page)
                    dom_change = self.current_dom_size - prev_dom_size
                    
                    # Log
                    element_type = candidate.type
                    label = candidate.label[:20] if candidate.label else candidate.selector[:20]
                    payload_marker = " 💉" if element_type == 'input' else ""
                    
                    logger.info(f"✅ {element_type}: '{label}' ({dom_change:+d} DOM){payload_marker}")
                    
                else:
                    consecutive_failures += 1
                    self.record_error(critical=False)
                    logger.debug(f"Aktion fehlgeschlagen: {candidate.selector[:30]}")
                
                # Kurze Pause zwischen Aktionen
                await asyncio.sleep(random.uniform(0.3, 0.8))
                
            except Exception as e:
                error_msg = str(e).lower()
                
                # Kritischer Fehler?
                if 'context was destroyed' in error_msg or 'target closed' in error_msg:
                    logger.debug(f"Navigation/Context-Wechsel erkannt, warte...")
                    await self.wait_for_page_ready(page)
                else:
                    logger.debug(f"Unerwarteter Fehler: {e}")
                    self.record_error(critical=False, message=str(e))
                    consecutive_failures += 1
                
                await asyncio.sleep(0.5)
        
        # Finale Statistiken
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        logger.info(f"\n✅ Random Walk abgeschlossen:")
        logger.info(f"   Aktionen: {self.actions_performed}/{action_count + consecutive_failures}")
        logger.info(f"   Inputs gefüllt: {self.inputs_filled}")
        logger.info(f"   Payloads injiziert: {self.payloads_injected}")
        logger.info(f"   DOM: {self.initial_dom_size} → {self.current_dom_size}")
        logger.info(f"   Zeit: {duration:.1f}s")
        
        return self.get_result(duration)
    
    def _select_candidate(self, candidates: List[ActionCandidate]) -> ActionCandidate:
        """
        Wählt den nächsten Kandidaten basierend auf Priorisierung.
        """
        if not candidates:
            return None
        
        # Kategorisiere Candidates
        unvisited_inputs = []
        visited_inputs = []
        unvisited_onclick = []
        unvisited_links = []
        unvisited_buttons = []
        other = []
        
        for c in candidates:
            selector = c.selector
            element_type = c.type
            is_visited = selector in self.visited_selectors
            
            if element_type == 'input':
                if not is_visited:
                    unvisited_inputs.append(c)
                else:
                    visited_inputs.append(c)
            elif element_type == 'onclick' or c.has_onclick:
                if not is_visited:
                    unvisited_onclick.append(c)
            elif element_type == 'link':
                if not is_visited:
                    unvisited_links.append(c)
            elif element_type == 'button':
                if not is_visited:
                    unvisited_buttons.append(c)
            else:
                if not is_visited:
                    other.append(c)
        
        # Priorisierte Auswahl
        
        # 1. Unbesuchte Inputs (höchste Priorität)
        if unvisited_inputs:
            return random.choice(unvisited_inputs)
        
        # 2. Besuchte Inputs (30% Chance - andere Payloads testen)
        if visited_inputs and random.random() < 0.3:
            return random.choice(visited_inputs)
        
        # 3. Unbesuchte onclick-Elemente (laden oft dynamische Inhalte)
        if unvisited_onclick:
            return random.choice(unvisited_onclick)
        
        # 4. Unbesuchte Links
        if unvisited_links:
            return random.choice(unvisited_links)
        
        # 5. Unbesuchte Buttons
        if unvisited_buttons:
            return random.choice(unvisited_buttons)
        
        # 6. Andere unbesuchte Elemente
        if other:
            return random.choice(other)
        
        # 7. Fallback: Zufällig aus allen
        return random.choice(candidates)
