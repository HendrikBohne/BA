"""
DOM XSS Trigger Strategies - Base Strategy (Fixed v3)
Abstrakte Basisklasse für alle Interaktionsstrategien
Mit verbesserter Input-Feld und XSS-Payload Unterstützung
"""
import asyncio
import logging
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

logger = logging.getLogger(__name__)


# XSS Test-Payloads
XSS_PAYLOADS = [
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<img src=x onerror=console.log("XSS_DETECTED")>',
    'javascript:alert("XSS")',
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert("XSS")>',
    '<input onfocus=alert("XSS") autofocus>',
]


@dataclass
class ActionCandidate:
    """Ein möglicher Interaktions-Kandidat"""
    id: str
    element_type: str  # 'link', 'button', 'input', 'form', 'select', etc.
    selector: str
    text: str = ""
    attributes: Dict = field(default_factory=dict)
    priority: float = 1.0
    visited_count: int = 0
    
    # XSS-relevante Eigenschaften
    has_input: bool = False
    has_event_handler: bool = False
    is_form: bool = False
    input_type: str = ""


@dataclass 
class ActionResult:
    """Ergebnis einer ausgeführten Aktion"""
    candidate: ActionCandidate
    success: bool
    dom_change: int = 0
    url_changed: bool = False
    new_url: str = ""
    error: Optional[str] = None
    taint_triggered: bool = False
    payload_used: str = ""


@dataclass
class StrategyResult:
    """Gesamtergebnis einer Strategie-Ausführung"""
    strategy_name: str
    url: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    
    actions_performed: int = 0
    actions_successful: int = 0
    actions_failed: int = 0
    
    initial_dom_size: int = 0
    final_dom_size: int = 0
    max_dom_size_reached: int = 0
    dom_states_visited: int = 0
    
    total_candidates_found: int = 0
    unique_candidates_executed: int = 0
    
    inputs_filled: int = 0
    forms_submitted: int = 0
    payloads_injected: int = 0
    
    taint_flows: List = field(default_factory=list)
    vulnerabilities: List = field(default_factory=list)
    action_history: List[ActionResult] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        if self.ended_at and self.started_at:
            return (self.ended_at - self.started_at).total_seconds()
        return 0.0


class BaseStrategy(ABC):
    """
    Abstrakte Basisklasse für Interaktionsstrategien.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_actions = self.config.get('max_actions', 50)
        self.action_delay = self.config.get('action_delay', 0.5)
        
        self.visited_candidates: Set[str] = set()
        self.candidate_history: Dict[str, int] = {}
        self.dom_growth_history: Dict[str, int] = {}
        
        self.current_payload_index = 0
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @abstractmethod
    async def select_next_action(
        self, 
        candidates: List[ActionCandidate],
        page: Page
    ) -> Optional[ActionCandidate]:
        pass
    
    def get_next_payload(self) -> str:
        """Rotiert durch XSS-Payloads"""
        payload = XSS_PAYLOADS[self.current_payload_index]
        self.current_payload_index = (self.current_payload_index + 1) % len(XSS_PAYLOADS)
        return payload
    
    async def get_action_candidates(self, page: Page) -> List[ActionCandidate]:
        """
        Findet alle interagierbaren Elemente auf der Seite.
        WICHTIG: Findet auch onclick-Links ohne href!
        """
        try:
            candidates_data = await page.evaluate("""
                () => {
                    const candidates = [];
                    const seen = new Set();
                    
                    // Sammle ALLE interaktiven Elemente
                    const elements = document.querySelectorAll(
                        'input:not([type="hidden"]), ' +
                        'textarea, ' +
                        'select, ' +
                        'button, ' +
                        'a, ' +                          // ALLE Links, nicht nur a[href]
                        '[onclick], ' +                  // Alles mit onclick
                        '[role="button"], ' +
                        '[role="link"], ' +
                        '[role="tab"], ' +
                        '[role="menuitem"], ' +
                        'form, ' +
                        '[contenteditable="true"], ' +
                        'details summary'
                    );
                    
                    elements.forEach((el, idx) => {
                        try {
                            const rect = el.getBoundingClientRect();
                            const style = window.getComputedStyle(el);
                            const tag = el.tagName.toLowerCase();
                            
                            // Sichtbarkeits-Check (Inputs können auch klein sein)
                            const isInput = ['input', 'textarea', 'select'].includes(tag);
                            if (!isInput) {
                                if (rect.width <= 0 || rect.height <= 0) return;
                                if (style.display === 'none') return;
                                if (style.visibility === 'hidden') return;
                            }
                            
                            // Hidden inputs skippen
                            if (el.type === 'hidden') return;
                            
                            // ID erstellen
                            let id = tag + '_' + idx;
                            if (el.id) id = tag + '#' + el.id;
                            else if (el.name) id = tag + '[name="' + el.name + '"]';
                            
                            if (seen.has(id)) return;
                            seen.add(id);
                            
                            // Element-Typ bestimmen
                            let elementType = 'other';
                            let inputType = '';
                            let hasInput = false;
                            
                            if (tag === 'input') {
                                elementType = 'input';
                                inputType = el.type || 'text';
                                hasInput = ['text', 'search', 'email', 'url', 'tel', 'password', ''].includes(inputType);
                            } else if (tag === 'textarea') {
                                elementType = 'input';
                                inputType = 'textarea';
                                hasInput = true;
                            } else if (tag === 'select') {
                                elementType = 'select';
                            } else if (tag === 'form') {
                                elementType = 'form';
                            } else if (tag === 'a') {
                                elementType = 'link';
                            } else if (tag === 'button' || el.getAttribute('role') === 'button') {
                                elementType = 'button';
                            } else if (el.hasAttribute('onclick')) {
                                elementType = 'clickable';
                            }
                            
                            // Event-Handler Check
                            const hasEventHandler = el.hasAttribute('onclick') ||
                                                   el.hasAttribute('onsubmit') ||
                                                   el.hasAttribute('oninput') ||
                                                   el.hasAttribute('onchange');
                            
                            // Externe Links filtern (aber onclick-Links behalten!)
                            if (tag === 'a' && el.hasAttribute('href')) {
                                const href = el.getAttribute('href') || '';
                                if (href.startsWith('mailto:') || href.startsWith('tel:')) return;
                                if (href.includes('://') && !href.includes(window.location.hostname)) return;
                            }
                            
                            // Selector für späteres Finden
                            let selector = '';
                            if (el.id) {
                                selector = '#' + el.id;
                            } else if (el.name) {
                                selector = tag + '[name="' + el.name + '"]';
                            } else {
                                // Für onclick-Links ohne ID: verwende Text-Selektor
                                const text = (el.textContent || '').trim();
                                if (text && text.length < 30) {
                                    selector = tag + ':has-text("' + text + '")';
                                } else {
                                    selector = tag + ':nth-of-type(' + (idx + 1) + ')';
                                }
                            }
                            
                            candidates.push({
                                id: id,
                                element_type: elementType,
                                selector: selector,
                                text: (el.textContent || el.value || el.placeholder || '').trim().substring(0, 50),
                                has_input: hasInput,
                                has_event_handler: hasEventHandler,
                                is_form: tag === 'form',
                                input_type: inputType,
                                attributes: {
                                    href: el.getAttribute('href') || '',
                                    type: el.getAttribute('type') || '',
                                    name: el.getAttribute('name') || '',
                                    onclick: el.hasAttribute('onclick')
                                }
                            });
                        } catch (e) {}
                    });
                    
                    return candidates;
                }
            """)
            
            # Konvertiere zu ActionCandidate Objekten
            candidates = []
            for data in candidates_data:
                candidate = ActionCandidate(
                    id=data['id'],
                    element_type=data['element_type'],
                    selector=data['selector'],
                    text=data['text'],
                    attributes=data.get('attributes', {}),
                    has_input=data.get('has_input', False),
                    has_event_handler=data.get('has_event_handler', False),
                    is_form=data.get('is_form', False),
                    input_type=data.get('input_type', ''),
                    visited_count=self.candidate_history.get(data['id'], 0)
                )
                
                # Priorität setzen
                if candidate.has_input:
                    candidate.priority = 5.0  # Inputs höchste Priorität
                elif candidate.is_form:
                    candidate.priority = 4.0
                elif candidate.has_event_handler:
                    candidate.priority = 3.0  # onclick etc. wichtig
                elif candidate.element_type == 'button':
                    candidate.priority = 2.0
                elif candidate.element_type == 'link':
                    candidate.priority = 1.5
                else:
                    candidate.priority = 1.0
                
                candidates.append(candidate)
            
            # Log Übersicht
            inputs = [c for c in candidates if c.has_input]
            clickables = [c for c in candidates if c.has_event_handler]
            links = [c for c in candidates if c.element_type == 'link']
            
            logger.debug(f"Kandidaten: {len(inputs)} Inputs, {len(clickables)} Clickables, {len(links)} Links")
            
            return candidates
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der Candidates: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    async def perform_action(self, candidate: ActionCandidate, page: Page) -> ActionResult:
        """
        Führt eine Aktion auf einem Kandidaten aus.
        """
        result = ActionResult(candidate=candidate, success=False)
        
        try:
            dom_before = await page.evaluate("() => document.getElementsByTagName('*').length")
            url_before = page.url
            
            # === INPUT-FELD: XSS-Payload injizieren! ===
            if candidate.has_input:
                payload = self.get_next_payload()
                
                try:
                    # Finde Element
                    element = await page.query_selector(candidate.selector)
                    if element:
                        await element.click(timeout=1000)
                        await element.fill(payload)
                        await element.dispatch_event('input')
                        await element.dispatch_event('change')
                        
                        result.success = True
                        result.payload_used = payload
                        logger.info(f"💉 Payload in '{candidate.text or candidate.selector}': {payload[:40]}...")
                        
                        # Suche Submit-Button
                        try:
                            submit = await page.query_selector('button, input[type="submit"], [onclick*="submit"], [onclick*="search"], [onclick*="update"]')
                            if submit:
                                await submit.click(timeout=1000)
                                logger.debug("   ↳ Button geklickt")
                        except:
                            pass
                except Exception as e:
                    result.error = str(e)
                    logger.debug(f"Input-Fehler: {e}")
            
            # === LINK/BUTTON/CLICKABLE: Klicken ===
            elif candidate.element_type in ['link', 'button', 'clickable'] or candidate.has_event_handler:
                try:
                    # Methode 1: Playwright click mit Text-Selektor
                    if ':has-text(' in candidate.selector:
                        text = candidate.text
                        if text:
                            await page.click(f'text="{text}"', timeout=3000)
                            result.success = True
                    else:
                        await page.click(candidate.selector, timeout=3000)
                        result.success = True
                        
                except PlaywrightTimeout:
                    # Methode 2: JavaScript click
                    try:
                        text = candidate.text
                        await page.evaluate(f"""
                            () => {{
                                // Versuche über Text zu finden
                                const elements = document.querySelectorAll('a, button, [onclick]');
                                for (const el of elements) {{
                                    if (el.textContent.trim() === '{text}') {{
                                        el.click();
                                        return true;
                                    }}
                                }}
                                return false;
                            }}
                        """)
                        result.success = True
                    except Exception as e:
                        result.error = str(e)
                except Exception as e:
                    result.error = str(e)
            
            # === ANDERE: Versuche zu klicken ===
            else:
                try:
                    await page.click(candidate.selector, timeout=2000)
                    result.success = True
                except Exception as e:
                    result.error = str(e)
            
            await asyncio.sleep(0.3)
            
            # DOM-Änderung messen
            dom_after = await page.evaluate("() => document.getElementsByTagName('*').length")
            result.dom_change = dom_after - dom_before
            
            # URL-Änderung
            if page.url != url_before:
                result.url_changed = True
                result.new_url = page.url
            
            # Tracking aktualisieren
            self.candidate_history[candidate.id] = self.candidate_history.get(candidate.id, 0) + 1
            self.dom_growth_history[candidate.id] = result.dom_change
            
            if result.success:
                self.visited_candidates.add(candidate.id)
            
        except Exception as e:
            result.error = str(e)
            logger.debug(f"Aktion fehlgeschlagen: {e}")
        
        return result
    
    async def get_dom_size(self, page: Page) -> int:
        try:
            return await page.evaluate("() => document.getElementsByTagName('*').length")
        except:
            return 0
    
    async def execute(self, page: Page, url: str) -> StrategyResult:
        """Führt die Strategie aus."""
        result = StrategyResult(
            strategy_name=self.name,
            url=url,
            started_at=datetime.now()
        )
        
        result.initial_dom_size = await self.get_dom_size(page)
        result.max_dom_size_reached = result.initial_dom_size
        
        logger.info(f"🚀 Starte {self.name}")
        logger.info(f"   URL: {url}")
        logger.info(f"   Max Actions: {self.max_actions}")
        
        failed_attempts = 0
        max_failures = 10
        
        for i in range(self.max_actions):
            if failed_attempts >= max_failures:
                logger.warning(f"⚠️ Zu viele Fehler ({failed_attempts}), breche ab")
                break
            
            try:
                candidates = await self.get_action_candidates(page)
                
                if not candidates:
                    logger.debug("Keine Kandidaten gefunden")
                    failed_attempts += 1
                    await asyncio.sleep(0.5)
                    continue
                
                result.total_candidates_found = max(result.total_candidates_found, len(candidates))
                
                candidate = await self.select_next_action(candidates, page)
                
                if not candidate:
                    logger.debug("Kein Kandidat ausgewählt")
                    failed_attempts += 1
                    continue
                
                action_result = await self.perform_action(candidate, page)
                result.action_history.append(action_result)
                
                if action_result.success:
                    result.actions_successful += 1
                    failed_attempts = 0
                    
                    dom_info = f"+{action_result.dom_change}" if action_result.dom_change > 0 else f"{action_result.dom_change}"
                    payload_info = " 💉" if action_result.payload_used else ""
                    logger.info(f"✅ {candidate.element_type}: '{candidate.text[:20] or candidate.selector}' ({dom_info} DOM){payload_info}")
                    
                    if action_result.payload_used:
                        result.payloads_injected += 1
                    if candidate.has_input:
                        result.inputs_filled += 1
                else:
                    result.actions_failed += 1
                    failed_attempts += 1
                    logger.debug(f"❌ Fehlgeschlagen: {candidate.text} - {action_result.error}")
                
                result.actions_performed += 1
                
                current_dom = await self.get_dom_size(page)
                result.max_dom_size_reached = max(result.max_dom_size_reached, current_dom)
                
                await asyncio.sleep(self.action_delay)
                
            except Exception as e:
                logger.debug(f"Fehler in Hauptschleife: {e}")
                failed_attempts += 1
                await asyncio.sleep(0.5)
        
        result.ended_at = datetime.now()
        result.final_dom_size = await self.get_dom_size(page)
        result.unique_candidates_executed = len(self.visited_candidates)
        result.dom_states_visited = len(set(self.dom_growth_history.values()))
        
        logger.info(f"\n✅ {self.name} abgeschlossen:")
        logger.info(f"   Aktionen: {result.actions_successful}/{result.actions_performed}")
        logger.info(f"   Inputs gefüllt: {result.inputs_filled}")
        logger.info(f"   Payloads injiziert: {result.payloads_injected}")
        logger.info(f"   DOM: {result.initial_dom_size} → {result.final_dom_size}")
        logger.info(f"   Zeit: {result.duration_seconds:.1f}s")
        
        return result
