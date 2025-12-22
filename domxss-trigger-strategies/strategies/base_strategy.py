"""
DOM XSS Trigger Strategies - Base Strategy
Abstrakte Basisklasse für alle Interaktionsstrategien
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ActionCandidate:
    """
    Repräsentiert ein interagierbares Element auf der Seite.
    """
    id: str                          # Eindeutiger Identifier
    selector: str                    # CSS Selector
    tag: str                         # HTML Tag
    text: str                        # Sichtbarer Text
    element_type: str                # link, button, input, form, etc.
    
    # Zusätzliche Attribute
    has_href: bool = False
    href: Optional[str] = None
    has_input: bool = False
    has_event_handler: bool = False
    is_form: bool = False
    input_type: Optional[str] = None
    
    # Tracking
    execution_count: int = 0
    last_executed: Optional[datetime] = None
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if isinstance(other, ActionCandidate):
            return self.id == other.id
        return False


@dataclass
class ActionResult:
    """Ergebnis einer ausgeführten Aktion"""
    candidate: ActionCandidate
    success: bool
    timestamp: datetime
    
    # DOM-Änderungen
    dom_changed: bool = False
    new_elements_count: int = 0
    url_changed: bool = False
    new_url: Optional[str] = None
    
    # Analyse
    taint_flows_triggered: int = 0
    error: Optional[str] = None


@dataclass 
class StrategyResult:
    """Gesamtergebnis einer Strategie-Ausführung"""
    strategy_name: str
    url: str
    started_at: datetime
    finished_at: datetime
    
    # Aktionen
    actions_performed: int
    actions_successful: int
    actions_failed: int
    action_results: List[ActionResult] = field(default_factory=list)
    
    # Candidates
    total_candidates_found: int = 0
    unique_candidates_executed: int = 0
    
    # DOM
    initial_dom_size: int = 0
    final_dom_size: int = 0
    max_dom_size_reached: int = 0
    dom_states_visited: int = 0
    
    # Wird später gefüllt
    taint_flows: List[Any] = field(default_factory=list)
    vulnerabilities: List[Any] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()
    
    @property
    def success_rate(self) -> float:
        if self.actions_performed == 0:
            return 0.0
        return self.actions_successful / self.actions_performed


class BaseStrategy(ABC):
    """
    Abstrakte Basisklasse für alle Interaktionsstrategien.
    """
    
    # XSS Test-Payloads
    XSS_PAYLOADS = [
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "javascript:alert(1)",
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_actions = self.config.get('max_actions', 50)
        self.action_delay_ms = self.config.get('action_delay_ms', 500)
        self.max_failures = self.config.get('max_failures', 5)
        
        # Tracking
        self.executed_candidates: set = set()
        self.action_history: List[ActionResult] = []
        self.current_url: Optional[str] = None
        self._payload_index = 0
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Name der Strategie"""
        pass
    
    @abstractmethod
    async def select_next_action(
        self, 
        candidates: List[ActionCandidate]
    ) -> Optional[ActionCandidate]:
        """Wählt den nächsten Candidate"""
        pass
    
    @abstractmethod
    async def on_action_completed(
        self, 
        action: ActionCandidate, 
        result: ActionResult,
        new_candidates: List[ActionCandidate]
    ):
        """Callback nach Aktion"""
        pass
    
    def _get_next_payload(self) -> str:
        """Rotiert durch XSS-Payloads"""
        payload = self.XSS_PAYLOADS[self._payload_index % len(self.XSS_PAYLOADS)]
        self._payload_index += 1
        return payload
    
    async def get_action_candidates(self, page) -> List[ActionCandidate]:
        """Findet alle interagierbaren Elemente"""
        try:
            elements = await page.evaluate("""
                () => {
                    const currentHostname = window.location.hostname;
                    const currentOrigin = window.location.origin;
                    
                    const selectors = [
                        'input:not([type="hidden"])',
                        'textarea',
                        'select',
                        'form',
                        'a[href]',
                        'button',
                        '[role="button"]',
                        '[onclick]',
                        '[contenteditable="true"]',
                        'details > summary',
                        '[role="tab"]',
                        '[role="menuitem"]',
                        '[data-action]',
                        '[data-toggle]'
                    ];
                    
                    const elements = [];
                    const seen = new Set();
                    
                    selectors.forEach(selector => {
                        document.querySelectorAll(selector).forEach((el, idx) => {
                            try {
                                const rect = el.getBoundingClientRect();
                                const style = window.getComputedStyle(el);
                                
                                if (rect.width <= 0 || rect.height <= 0 ||
                                    style.display === 'none' ||
                                    style.visibility === 'hidden' ||
                                    parseFloat(style.opacity) === 0) {
                                    return;
                                }
                                
                                let id = el.tagName.toLowerCase();
                                if (el.id) id += '#' + el.id;
                                else if (el.name) id += '[name="' + el.name + '"]';
                                else if (el.className && typeof el.className === 'string') {
                                    const cls = el.className.split(' ').filter(c => c)[0];
                                    if (cls) id += '.' + cls;
                                }
                                id += '_' + idx;
                                
                                if (seen.has(id)) return;
                                seen.add(id);
                                
                                const tag = el.tagName.toLowerCase();
                                let elementType = 'other';
                                if (tag === 'a') elementType = 'link';
                                else if (tag === 'button' || el.getAttribute('role') === 'button') elementType = 'button';
                                else if (['input', 'textarea', 'select'].includes(tag)) elementType = 'input';
                                else if (tag === 'form') elementType = 'form';
                                
                                let href = el.getAttribute('href');
                                let hasHref = false;
                                if (href) {
                                    if (href.startsWith('#') || href.startsWith('/') ||
                                        href.startsWith(currentOrigin)) {
                                        hasHref = true;
                                    } else if (href.includes('://')) {
                                        try {
                                            hasHref = new URL(href).hostname === currentHostname;
                                        } catch (e) {}
                                    } else {
                                        hasHref = true;
                                    }
                                }
                                
                                elements.push({
                                    id: id,
                                    selector: selector,
                                    tag: tag,
                                    text: (el.textContent || el.value || '').trim().substring(0, 100),
                                    elementType: elementType,
                                    hasHref: hasHref,
                                    href: hasHref ? href : null,
                                    hasInput: ['input', 'textarea'].includes(tag),
                                    hasEventHandler: !!(el.onclick || el.getAttribute('onclick')),
                                    isForm: tag === 'form',
                                    inputType: el.getAttribute('type')
                                });
                            } catch (e) {}
                        });
                    });
                    
                    return elements;
                }
            """)
            
            candidates = [
                ActionCandidate(
                    id=el['id'],
                    selector=el['selector'],
                    tag=el['tag'],
                    text=el['text'],
                    element_type=el['elementType'],
                    has_href=el['hasHref'],
                    href=el['href'],
                    has_input=el['hasInput'],
                    has_event_handler=el['hasEventHandler'],
                    is_form=el['isForm'],
                    input_type=el.get('inputType')
                )
                for el in elements
            ]
            
            logger.debug(f"Gefunden: {len(candidates)} Candidates")
            return candidates
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der Candidates: {e}")
            return []
    
    async def perform_action(self, page, candidate: ActionCandidate) -> ActionResult:
        """Führt eine Aktion aus"""
        timestamp = datetime.now()
        url_before = page.url
        
        try:
            dom_before = await page.evaluate("document.getElementsByTagName('*').length")
            
            if candidate.element_type == 'input':
                await self._fill_input(page, candidate)
            elif candidate.element_type == 'form':
                await self._submit_form(page, candidate)
            else:
                await self._click_element(page, candidate)
            
            await page.wait_for_timeout(self.action_delay_ms)
            
            dom_after = await page.evaluate("document.getElementsByTagName('*').length")
            url_after = page.url
            
            result = ActionResult(
                candidate=candidate,
                success=True,
                timestamp=timestamp,
                dom_changed=dom_after != dom_before,
                new_elements_count=max(0, dom_after - dom_before),
                url_changed=url_after != url_before,
                new_url=url_after if url_after != url_before else None
            )
            
            candidate.execution_count += 1
            candidate.last_executed = timestamp
            self.executed_candidates.add(candidate.id)
            self.action_history.append(result)
            
            logger.info(f"✅ {candidate.element_type}: '{candidate.text[:30]}' (+{result.new_elements_count} DOM)")
            
            return result
            
        except Exception as e:
            logger.debug(f"❌ Aktion fehlgeschlagen: {e}")
            return ActionResult(
                candidate=candidate,
                success=False,
                timestamp=timestamp,
                error=str(e)
            )
    
    async def _fill_input(self, page, candidate: ActionCandidate):
        """Füllt ein Input-Feld mit XSS-Payload"""
        payload = self._get_next_payload()
        
        try:
            # Versuche direktes Fill
            if '#' in candidate.id:
                selector = f"#{candidate.id.split('#')[1].split('_')[0]}"
            else:
                selector = candidate.selector
            
            await page.fill(selector, payload, timeout=3000)
        except:
            # Fallback: JavaScript
            await page.evaluate(f"""
                () => {{
                    const inputs = document.querySelectorAll('{candidate.selector}');
                    for (const el of inputs) {{
                        if (el.value !== undefined) {{
                            el.value = `{payload}`;
                            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                            break;
                        }}
                    }}
                }}
            """)
    
    async def _click_element(self, page, candidate: ActionCandidate):
        """Klickt auf ein Element"""
        try:
            await page.click(candidate.selector, timeout=3000)
        except:
            await page.evaluate(f"""
                () => {{
                    const el = document.querySelector('{candidate.selector}');
                    if (el) el.click();
                }}
            """)
    
    async def _submit_form(self, page, candidate: ActionCandidate):
        """Füllt Form aus und sendet ab"""
        payload = self._get_next_payload()
        
        await page.evaluate(f"""
            () => {{
                const form = document.querySelector('{candidate.selector}');
                if (!form) return;
                
                form.querySelectorAll('input[type="text"], input:not([type]), textarea').forEach(input => {{
                    input.value = `{payload}`;
                    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                }});
                
                form.dispatchEvent(new Event('submit', {{ bubbles: true, cancelable: true }}));
            }}
        """)
    
    async def execute(self, page, url: str) -> StrategyResult:
        """Hauptschleife: Führt die Strategie aus"""
        started_at = datetime.now()
        self.current_url = url
        
        self.executed_candidates.clear()
        self.action_history.clear()
        self._payload_index = 0
        
        actions_performed = 0
        actions_successful = 0
        consecutive_failures = 0
        max_dom_size = 0
        all_candidates_seen = set()
        
        initial_dom_size = await page.evaluate("document.getElementsByTagName('*').length")
        
        logger.info(f"🚀 Starte {self.name}")
        logger.info(f"   URL: {url}")
        logger.info(f"   Max Actions: {self.max_actions}")
        
        while actions_performed < self.max_actions:
            if consecutive_failures >= self.max_failures:
                logger.warning(f"⚠️ Abbruch: {consecutive_failures} Fehler")
                break
            
            candidates = await self.get_action_candidates(page)
            all_candidates_seen.update(c.id for c in candidates)
            
            if not candidates:
                logger.info("Keine Candidates mehr")
                break
            
            current_dom = await page.evaluate("document.getElementsByTagName('*').length")
            max_dom_size = max(max_dom_size, current_dom)
            
            selected = await self.select_next_action(candidates)
            
            if selected is None:
                logger.info("Keine Aktion ausgewählt")
                break
            
            result = await self.perform_action(page, selected)
            actions_performed += 1
            
            if result.success:
                actions_successful += 1
                consecutive_failures = 0
                new_candidates = await self.get_action_candidates(page)
                await self.on_action_completed(selected, result, new_candidates)
            else:
                consecutive_failures += 1
        
        finished_at = datetime.now()
        final_dom_size = await page.evaluate("document.getElementsByTagName('*').length")
        
        result = StrategyResult(
            strategy_name=self.name,
            url=url,
            started_at=started_at,
            finished_at=finished_at,
            actions_performed=actions_performed,
            actions_successful=actions_successful,
            actions_failed=actions_performed - actions_successful,
            action_results=self.action_history.copy(),
            total_candidates_found=len(all_candidates_seen),
            unique_candidates_executed=len(self.executed_candidates),
            initial_dom_size=initial_dom_size,
            final_dom_size=final_dom_size,
            max_dom_size_reached=max_dom_size
        )
        
        logger.info(f"\n✅ {self.name} abgeschlossen:")
        logger.info(f"   Aktionen: {actions_successful}/{actions_performed}")
        logger.info(f"   DOM: {initial_dom_size} → {final_dom_size}")
        logger.info(f"   Zeit: {result.duration_seconds:.1f}s")
        
        return result
