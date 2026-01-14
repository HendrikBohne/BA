"""
DOM XSS Trigger Strategies - DOM Maximizer Strategy (v4)
Maximiert die DOM-Größe durch Lazy-Loading und versteckte Inhalte

Angepasst an BaseStrategy v4 mit run() Methode
"""
import asyncio
import random
import logging
from typing import List, Optional, Dict
from playwright.async_api import Page

from .base_strategy import BaseStrategy, ActionCandidate, StrategyResult

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
    
    def __init__(self, config: dict = None):
        super().__init__(name="dom_maximizer")
        self.config = config or {}
        self.max_dom_seen = 0
        self.dom_growing_candidates: Dict[str, int] = {}
        self.candidate_history: Dict[str, int] = {}
    
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
            logger.info("[DOM-Max] Lazy-loading getriggert")
        except Exception as e:
            logger.debug(f"Lazy-loading scroll error: {e}")
    
    async def _expand_hidden_content(self, page: Page):
        """Klickt auf Expander, Tabs, Accordions etc."""
        try:
            expanded = await page.evaluate("""
                () => {
                    let count = 0;
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
                        try { 
                            el.click(); 
                            count++;
                        } catch(e) {}
                    });
                    return count;
                }
            """)
            if expanded > 0:
                logger.info(f"[DOM-Max] {expanded} versteckte Elemente expandiert")
        except Exception as e:
            logger.debug(f"Expand error: {e}")
    
    def _get_candidate_id(self, candidate: ActionCandidate) -> str:
        """Erstellt eine eindeutige ID für einen Kandidaten"""
        return f"{candidate.type}:{candidate.selector}"
    
    def _calculate_dom_weight(self, candidate: ActionCandidate) -> float:
        """Berechnet Gewicht basierend auf DOM-Wachstum-Potenzial"""
        base_weight = 1.0
        candidate_id = self._get_candidate_id(candidate)
        
        # HÖCHSTE PRIORITÄT: Inputs für XSS
        if candidate.type == 'input':
            base_weight *= 5.0
        
        # Bonus wenn dieser Kandidat DOM-Wachstum verursacht hat
        if candidate_id in self.dom_growing_candidates:
            growth = self.dom_growing_candidates[candidate_id]
            if growth > 0:
                base_weight *= (1 + growth / 5.0)
        
        # Bonus für "Load More" artige Buttons
        text_lower = candidate.label.lower() if candidate.label else ""
        if any(kw in text_lower for kw in ['more', 'load', 'show', 'expand', 'next', 'continue', 'mehr', 'laden']):
            base_weight *= 2.0
        
        # Bonus für Tabs, Accordions etc.
        selector_lower = candidate.selector.lower()
        if any(kw in selector_lower for kw in ['tab', 'accordion', 'expand', 'collapse', 'toggle']):
            base_weight *= 1.5
        
        # Malus für oft besuchte Kandidaten die kein DOM-Wachstum bringen
        visit_count = self.candidate_history.get(candidate_id, 0)
        if visit_count > 0 and candidate_id not in self.dom_growing_candidates:
            base_weight /= (1 + visit_count)
        
        return base_weight
    
    def _select_candidate(self, candidates: List[ActionCandidate]) -> Optional[ActionCandidate]:
        """
        Wählt Kandidaten die DOM-Wachstum maximieren.
        Priorisiert trotzdem Inputs für XSS-Testing.
        """
        if not candidates:
            return None
        
        # 1. HÖCHSTE PRIORITÄT: Unbesuchte Inputs
        unvisited_inputs = [c for c in candidates 
                          if c.type == 'input' and c.selector not in self.visited_selectors]
        if unvisited_inputs:
            return random.choice(unvisited_inputs)
        
        # 2. Bereits besuchte Inputs mit neuem Payload (30% Chance)
        visited_inputs = [c for c in candidates if c.type == 'input']
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
    
    async def run(self, page: Page, max_actions: int = 50) -> StrategyResult:
        """Führt DOM Maximizer Strategie aus"""
        
        logger.info(f"🚀 Starte DOM Maximizer")
        logger.info(f"   URL: {page.url}")
        logger.info(f"   Max Actions: {max_actions}")
        
        # Initiales Lazy-Loading und Expansion
        await self._trigger_lazy_loading(page)
        await asyncio.sleep(1)
        await self._expand_hidden_content(page)
        await asyncio.sleep(1)
        
        # Initiale DOM-Größe
        self.initial_dom_size = await self.get_dom_size(page)
        self.current_dom_size = self.initial_dom_size
        self.max_dom_seen = self.initial_dom_size
        
        logger.info(f"   Initiale DOM-Größe: {self.initial_dom_size}")
        
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
                
                # Wähle nächste Aktion (DOM-Wachstum priorisiert)
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
                    
                    # Tracke DOM-Wachstum pro Kandidat
                    if dom_change > 0:
                        self.dom_growing_candidates[candidate_id] = dom_change
                    
                    # Update max
                    if self.current_dom_size > self.max_dom_seen:
                        self.max_dom_seen = self.current_dom_size
                    
                    # Log
                    element_type = candidate.type
                    label = candidate.label[:20] if candidate.label else candidate.selector[:20]
                    payload_marker = " 💉" if element_type == 'input' else ""
                    growth_marker = f" 📈" if dom_change > 10 else ""
                    
                    logger.info(f"✅ {element_type}: '{label}' ({dom_change:+d} DOM){payload_marker}{growth_marker}")
                    
                else:
                    consecutive_failures += 1
                    self.record_error(critical=False)
                    logger.debug(f"Aktion fehlgeschlagen: {candidate.selector[:30]}")
                
                # Kurze Pause zwischen Aktionen
                await asyncio.sleep(random.uniform(0.3, 0.8))
                
                # Periodisch Lazy-Loading triggern (alle 10 Aktionen)
                if action_count > 0 and action_count % 10 == 0:
                    await self._trigger_lazy_loading(page)
                
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
        
        dom_growth = self.current_dom_size - self.initial_dom_size
        growth_percent = (dom_growth / self.initial_dom_size * 100) if self.initial_dom_size > 0 else 0
        
        logger.info(f"\n✅ DOM Maximizer abgeschlossen:")
        logger.info(f"   Aktionen: {self.actions_performed}")
        logger.info(f"   Inputs gefüllt: {self.inputs_filled}")
        logger.info(f"   Payloads injiziert: {self.payloads_injected}")
        logger.info(f"   DOM: {self.initial_dom_size} → {self.current_dom_size} ({growth_percent:+.1f}%)")
        logger.info(f"   Max DOM gesehen: {self.max_dom_seen}")
        logger.info(f"   DOM-wachsende Elemente: {len(self.dom_growing_candidates)}")
        logger.info(f"   Zeit: {duration:.1f}s")
        
        return self.get_result(duration)
