"""
DOM XSS Trigger Strategies - Model-Guided Strategy (v4)
Lernt Beziehungen zwischen Aktionen für intelligentere Exploration

Angepasst an BaseStrategy v4 mit run() Methode
"""
import asyncio
import random
import logging
from typing import List, Optional, Dict, Set
from playwright.async_api import Page

from .base_strategy import BaseStrategy, ActionCandidate, StrategyResult

logger = logging.getLogger(__name__)


class ModelGuidedStrategy(BaseStrategy):
    """
    Model-Guided Random Walk Strategie.
    
    Basiert auf dem Paper "Improving Behavioral Program Analysis with Environment Models"
    Lernt welche Aktionen zu neuen Kandidaten führen und priorisiert diese.
    """
    
    def __init__(self, config: dict = None):
        super().__init__(name="model_guided")
        self.config = config or {}
        
        # Model: Welche Kandidaten führen zu welchen neuen Kandidaten?
        self.successor_map: Dict[str, Set[str]] = {}
        self.last_candidates: List[str] = []
        self.last_action: Optional[str] = None
        
        # Gewichtung für Model vs Random
        self.w_model = self.config.get('w_model', 25.0)
        
        # Visit-History pro Kandidat
        self.candidate_history: Dict[str, int] = {}
    
    def _get_candidate_id(self, candidate: ActionCandidate) -> str:
        """Erstellt eine eindeutige ID für einen Kandidaten"""
        return f"{candidate.type}:{candidate.selector}"
    
    def _update_model(self, current_candidates: List[ActionCandidate]):
        """Aktualisiert das Successor-Model"""
        if self.last_action:
            current_ids = {self._get_candidate_id(c) for c in current_candidates}
            new_candidates = current_ids - set(self.last_candidates)
            
            if new_candidates:
                if self.last_action not in self.successor_map:
                    self.successor_map[self.last_action] = set()
                self.successor_map[self.last_action].update(new_candidates)
                logger.debug(f"Model: {self.last_action[:30]} → {len(new_candidates)} neue Kandidaten")
        
        self.last_candidates = [self._get_candidate_id(c) for c in current_candidates]
    
    def _calculate_weight(self, candidate: ActionCandidate) -> float:
        """Berechnet Gewicht basierend auf Model"""
        base_weight = 1.0
        candidate_id = self._get_candidate_id(candidate)
        
        # Bonus für Inputs (XSS-relevant)
        if candidate.type == 'input':
            base_weight *= 3.0
        
        # Bonus wenn dieser Kandidat zu neuen Kandidaten führt
        if candidate_id in self.successor_map:
            successors = self.successor_map[candidate_id]
            unvisited = len(successors - self.visited_selectors)
            if unvisited > 0:
                base_weight *= (1 + (unvisited / 10.0) * self.w_model)
        
        # Malus wenn oft besucht
        visit_count = self.candidate_history.get(candidate_id, 0)
        if visit_count > 0:
            base_weight /= (1 + visit_count * 0.5)
        
        return base_weight
    
    def _select_candidate(self, candidates: List[ActionCandidate]) -> Optional[ActionCandidate]:
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
                          if c.type == 'input' and c.selector not in self.visited_selectors]
        if unvisited_inputs:
            selected = random.choice(unvisited_inputs)
            self.last_action = self._get_candidate_id(selected)
            return selected
        
        # Berechne Gewichte für alle Kandidaten
        weights = [self._calculate_weight(c) for c in candidates]
        total = sum(weights)
        
        if total == 0:
            selected = random.choice(candidates)
            self.last_action = self._get_candidate_id(selected)
            return selected
        
        # Gewichtete Zufallsauswahl
        r = random.uniform(0, total)
        cumsum = 0
        for i, w in enumerate(weights):
            cumsum += w
            if r <= cumsum:
                selected = candidates[i]
                self.last_action = self._get_candidate_id(selected)
                return selected
        
        selected = random.choice(candidates)
        self.last_action = self._get_candidate_id(selected)
        return selected
    
    async def run(self, page: Page, max_actions: int = 50) -> StrategyResult:
        """Führt Model-Guided Random Walk aus"""
        
        logger.info(f"🚀 Starte Model-Guided Random Walk")
        logger.info(f"   URL: {page.url}")
        logger.info(f"   Max Actions: {max_actions}")
        logger.info(f"   w_model: {self.w_model}")
        
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
                
                # Wähle nächste Aktion (Model-basiert)
                candidate = self._select_candidate(candidates)
                
                if not candidate:
                    consecutive_failures += 1
                    self.record_error(critical=False)
                    continue
                
                candidate_id = self._get_candidate_id(candidate)
                
                # Update History
                self.candidate_history[candidate_id] = self.candidate_history.get(candidate_id, 0) + 1
                
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
        
        logger.info(f"\n✅ Model-Guided Random Walk abgeschlossen:")
        logger.info(f"   Aktionen: {self.actions_performed}")
        logger.info(f"   Inputs gefüllt: {self.inputs_filled}")
        logger.info(f"   Payloads injiziert: {self.payloads_injected}")
        logger.info(f"   DOM: {self.initial_dom_size} → {self.current_dom_size}")
        logger.info(f"   Model-Einträge: {len(self.successor_map)}")
        logger.info(f"   Zeit: {duration:.1f}s")
        
        return self.get_result(duration)
