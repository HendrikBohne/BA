"""
DOM XSS Trigger Strategies - DOM Maximizer Strategy
Strategie 3: Maximierung der DOM-Größe und -Tiefe
"""
import random
import logging
from typing import List, Optional, Dict

from .base_strategy import BaseStrategy, ActionCandidate, ActionResult

logger = logging.getLogger(__name__)


class DOMMaximizerStrategy(BaseStrategy):
    """
    DOM Maximizer Strategie.
    
    Priorisiert Aktionen die:
    - Neue DOM-Elemente erzeugen
    - Versteckte Inhalte aufdecken
    - Lazy-Loading triggern
    """
    
    EXPANSION_PATTERNS = [
        'details', 'accordion', 'collapse', 'expand',
        'toggle', 'tab', 'modal', 'dropdown', 'menu'
    ]
    
    LOAD_MORE_KEYWORDS = [
        'more', 'load', 'show', 'expand', 'open', 'view',
        'mehr', 'laden', 'anzeigen', 'öffnen'
    ]
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.scroll_steps = self.config.get('scroll_steps', 10)
        self.max_dom_size = self.config.get('max_dom_size', 50000)
        
        # Track welche Candidates DOM vergrößert haben
        self.dom_growth_history: Dict[str, List[int]] = {}
        
    @property
    def name(self) -> str:
        return "DOM Maximizer"
    
    def _predict_dom_growth(self, candidate: ActionCandidate) -> float:
        """Schätzt erwartetes DOM-Wachstum"""
        # Historische Daten
        if candidate.id in self.dom_growth_history:
            history = self.dom_growth_history[candidate.id]
            if history:
                return sum(history) / len(history)
        
        # Heuristiken
        score = 1.0
        text_lower = candidate.text.lower()
        selector_lower = candidate.selector.lower()
        
        # Expansion-Patterns
        for pattern in self.EXPANSION_PATTERNS:
            if pattern in selector_lower or pattern in text_lower:
                score = 5.0
                break
        
        # Load-More Keywords
        for keyword in self.LOAD_MORE_KEYWORDS:
            if keyword in text_lower:
                score = max(score, 4.0)
                break
        
        # Links mit Hash (oft Tabs/Sections)
        if candidate.element_type == 'link':
            if candidate.href and '#' in candidate.href:
                score = max(score, 3.0)
            else:
                score = max(score, 2.0)
        
        # Buttons
        elif candidate.element_type == 'button':
            score = max(score, 1.5)
        
        # Forms
        elif candidate.is_form:
            score = max(score, 2.5)
        
        return score
    
    async def select_next_action(
        self, 
        candidates: List[ActionCandidate]
    ) -> Optional[ActionCandidate]:
        """Wählt Candidate mit höchstem erwarteten DOM-Wachstum"""
        if not candidates:
            return None
        
        # Score berechnen
        scored = []
        for candidate in candidates:
            growth_score = self._predict_dom_growth(candidate)
            
            # Bonus für nicht ausgeführte
            if candidate.id not in self.executed_candidates:
                growth_score *= 1.5
            
            # Bonus für XSS-relevante
            if candidate.has_input:
                growth_score *= 1.3
            
            scored.append((candidate, growth_score))
        
        # Sortieren (höchster Score zuerst)
        scored.sort(key=lambda x: x[1], reverse=True)
        
        # Top 3 mit gewichteter Zufallsauswahl
        top_n = min(3, len(scored))
        top_candidates = scored[:top_n]
        
        total_score = sum(s for _, s in top_candidates)
        if total_score == 0:
            return top_candidates[0][0]
        
        pick = random.uniform(0, total_score)
        current = 0
        
        for candidate, score in top_candidates:
            current += score
            if current >= pick:
                logger.debug(f"[DOM-Max] {candidate.text[:30]} (score={score:.1f})")
                return candidate
        
        return top_candidates[0][0]
    
    async def on_action_completed(
        self, 
        action: ActionCandidate, 
        result: ActionResult,
        new_candidates: List[ActionCandidate]
    ):
        """Update DOM-Growth-History"""
        growth = result.new_elements_count
        
        if action.id not in self.dom_growth_history:
            self.dom_growth_history[action.id] = []
        
        self.dom_growth_history[action.id].append(growth)
        
        if growth > 0:
            logger.info(f"[DOM-Max] +{growth} elements from: {action.text[:30]}")
    
    async def trigger_lazy_loading(self, page) -> int:
        """Scrollt die Seite für Lazy-Loading"""
        initial = await page.evaluate("document.getElementsByTagName('*').length")
        
        logger.info("[DOM-Max] Triggering lazy-loading...")
        
        await page.evaluate(f"""
            async () => {{
                const step = window.innerHeight;
                for (let i = 0; i < {self.scroll_steps}; i++) {{
                    window.scrollBy(0, step);
                    await new Promise(r => setTimeout(r, 300));
                }}
                window.scrollTo(0, 0);
            }}
        """)
        
        await page.wait_for_timeout(1000)
        
        final = await page.evaluate("document.getElementsByTagName('*').length")
        growth = final - initial
        
        if growth > 0:
            logger.info(f"[DOM-Max] Lazy-loading: +{growth} elements")
        
        return growth
    
    async def expand_all(self, page) -> int:
        """Öffnet alle Accordions, Details, etc."""
        initial = await page.evaluate("document.getElementsByTagName('*').length")
        
        logger.info("[DOM-Max] Expanding hidden content...")
        
        await page.evaluate("""
            () => {
                // HTML5 <details>
                document.querySelectorAll('details:not([open])').forEach(el => {
                    el.setAttribute('open', '');
                });
                
                // ARIA expanded
                document.querySelectorAll('[aria-expanded="false"]').forEach(el => {
                    try { el.click(); } catch(e) {}
                });
                
                // Bootstrap
                document.querySelectorAll('.accordion-button.collapsed, .collapsed').forEach(el => {
                    try { el.click(); } catch(e) {}
                });
            }
        """)
        
        await page.wait_for_timeout(1000)
        
        final = await page.evaluate("document.getElementsByTagName('*').length")
        return final - initial
    
    async def execute(self, page, url: str):
        """Überschreibt execute für zusätzliche DOM-Maximierung"""
        # Erst Lazy-Loading und Expansion
        await self.trigger_lazy_loading(page)
        await self.expand_all(page)
        
        # Dann normale Ausführung
        return await super().execute(page, url)
    
    def get_growth_stats(self) -> Dict:
        """DOM-Growth Statistiken"""
        if not self.dom_growth_history:
            return {'total_growth': 0, 'best_candidates': []}
        
        avg_growth = {
            cid: sum(g) / len(g)
            for cid, g in self.dom_growth_history.items()
            if g
        }
        
        sorted_candidates = sorted(avg_growth.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total_growth': sum(sum(g) for g in self.dom_growth_history.values()),
            'candidates_tracked': len(self.dom_growth_history),
            'best_candidates': sorted_candidates[:5]
        }
