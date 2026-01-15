"""
DOM XSS Trigger Strategies - Base Strategy (v4 - Robust)

Verbesserungen v4:
- Bessere Fehlerbehandlung bei Navigation/Context-Destruction
- Retry-Logik für fehlgeschlagene Aktionen
- Element-Validierung vor Klick
- Unterscheidung zwischen kritischen und nicht-kritischen Fehlern
- Warten auf stabilen DOM-Zustand
"""
import asyncio
import logging
import random
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Any
from dataclasses import dataclass, field
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout, Error as PlaywrightError

logger = logging.getLogger(__name__)


# XSS Payloads für Input-Felder
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
    '<details open ontoggle=alert("XSS")>',
]


@dataclass
class ActionCandidate:
    """Repräsentiert ein interaktives Element auf der Seite"""
    selector: str
    type: str  # 'input', 'button', 'link', 'onclick', 'select', 'unknown'
    tag: str
    label: str = ""
    input_type: str = ""
    href: str = ""
    has_onclick: bool = False
    rect: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'selector': self.selector,
            'type': self.type,
            'tag': self.tag,
            'label': self.label,
            'inputType': self.input_type,
            'href': self.href,
            'hasOnclick': self.has_onclick,
            'rect': self.rect
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ActionCandidate':
        return cls(
            selector=data.get('selector', ''),
            type=data.get('type', 'unknown'),
            tag=data.get('tag', ''),
            label=data.get('label', ''),
            input_type=data.get('inputType', ''),
            href=data.get('href', ''),
            has_onclick=data.get('hasOnclick', False),
            rect=data.get('rect', {})
        )


@dataclass
class ActionResult:
    """Ergebnis einer ausgeführten Aktion"""
    success: bool
    candidate: ActionCandidate
    dom_change: int = 0
    payload_injected: Optional[str] = None
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class StrategyResult:
    """Gesamtergebnis einer Strategie-Ausführung"""
    strategy_name: str
    actions_performed: int
    inputs_filled: int
    payloads_injected: int
    initial_dom_size: int
    final_dom_size: int
    duration: float
    url: str = ""
    started_at: str = ""
    ended_at: str = ""
    
    # Zusätzliche Metriken für main.py Kompatibilität
    actions_successful: int = 0
    actions_failed: int = 0
    max_dom_size_reached: int = 0
    dom_states_visited: int = 0
    total_candidates_found: int = 0
    unique_candidates_executed: int = 0
    
    # Taint-Daten (werden von main.py gesetzt)
    taint_flows: List[Any] = field(default_factory=list)
    vulnerabilities: List[Any] = field(default_factory=list)
    
    visited_selectors: List[str] = field(default_factory=list)
    action_results: List[ActionResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    @property
    def dom_growth(self) -> int:
        return self.final_dom_size - self.initial_dom_size
    
    @property
    def duration_seconds(self) -> float:
        """Alias für duration - Kompatibilität mit main.py"""
        return self.duration
    
    def to_dict(self) -> Dict:
        return {
            'strategy': self.strategy_name,
            'url': self.url,
            'started_at': self.started_at,
            'ended_at': self.ended_at,
            'actions_performed': self.actions_performed,
            'actions_successful': self.actions_successful,
            'actions_failed': self.actions_failed,
            'inputs_filled': self.inputs_filled,
            'payloads_injected': self.payloads_injected,
            'initial_dom_size': self.initial_dom_size,
            'final_dom_size': self.final_dom_size,
            'max_dom_size_reached': self.max_dom_size_reached,
            'dom_growth': self.dom_growth,
            'duration': self.duration,
            'duration_seconds': self.duration_seconds,
            'visited_elements': len(self.visited_selectors),
            'total_candidates_found': self.total_candidates_found,
            'unique_candidates_executed': self.unique_candidates_executed,
            'taint_flows_count': len(self.taint_flows),
            'vulnerabilities_count': len(self.vulnerabilities),
            'errors': self.errors
        }


class BaseStrategy(ABC):
    """
    Basis-Klasse für alle Exploration-Strategien.
    Robuste Implementierung mit Fehlertoleranz.
    """
    
    def __init__(self, name: str = "base", passive: bool = False):
        self.name = name
        self.passive = passive  # Passiv-Modus: keine Payloads senden
        self.url = ""
        self.started_at = ""
        self.actions_performed = 0
        self.inputs_filled = 0
        self.payloads_injected = 0
        self.visited_selectors = set()
        self.payload_index = 0
        self.initial_dom_size = 0
        self.current_dom_size = 0
        self.max_dom_size = 0  # Track max DOM size
        self.total_candidates = 0  # Track total candidates found
        
        # Fehler-Tracking (unterschiedliche Kategorien)
        self.critical_errors = 0  # Navigation-Fehler, Context destroyed
        self.minor_errors = 0     # Element nicht gefunden, Timeout
        self.max_critical_errors = 8    # Etwas mehr Toleranz
        self.max_minor_errors = 25      # Deutlich mehr Toleranz für dynamische SPAs
        
        # Retry-Konfiguration
        self.max_retries = 2
        self.retry_delay = 0.5
        
        # Action Results
        self.action_results: List[ActionResult] = []
        self.errors: List[str] = []
    
    def get_next_payload(self) -> str:
        """Rotiert durch XSS-Payloads"""
        payload = XSS_PAYLOADS[self.payload_index % len(XSS_PAYLOADS)]
        self.payload_index += 1
        return payload
    
    async def wait_for_stable_dom(self, page: Page, timeout: float = 2.0) -> bool:
        """
        Wartet bis der DOM stabil ist (keine Änderungen mehr).
        Hilft bei dynamischen SPAs.
        """
        try:
            prev_size = await page.evaluate("document.body.innerHTML.length")
            await asyncio.sleep(0.3)
            
            for _ in range(int(timeout / 0.3)):
                current_size = await page.evaluate("document.body.innerHTML.length")
                if current_size == prev_size:
                    return True
                prev_size = current_size
                await asyncio.sleep(0.3)
            
            return True  # Timeout, aber weitermachen
        except Exception:
            return False
    
    async def is_page_valid(self, page: Page) -> bool:
        """Prüft ob die Page noch gültig ist (nicht navigiert/geschlossen)"""
        try:
            await page.evaluate("1")
            return True
        except Exception:
            return False
    
    async def wait_for_page_ready(self, page: Page, timeout: float = 5.0) -> bool:
        """
        Wartet bis die Seite bereit ist nach einer möglichen Navigation.
        """
        try:
            await page.wait_for_load_state('domcontentloaded', timeout=timeout * 1000)
            await asyncio.sleep(0.5)
            return True
        except Exception as e:
            logger.debug(f"wait_for_page_ready Fehler: {e}")
            return False
    
    async def validate_element(self, page: Page, selector: str) -> bool:
        """
        Prüft ob ein Element existiert und sichtbar ist.
        """
        try:
            element = await page.query_selector(selector)
            if not element:
                return False
            
            is_visible = await element.is_visible()
            return is_visible
        except Exception:
            return False
    
    async def safe_click(self, page: Page, selector: str, label: str = "") -> bool:
        """
        Sicherer Klick mit Retry-Logik und Fehlerbehandlung.
        """
        for attempt in range(self.max_retries + 1):
            try:
                if not await self.is_page_valid(page):
                    await self.wait_for_page_ready(page)
                
                await page.click(selector, timeout=3000)
                return True
                
            except PlaywrightTimeout:
                try:
                    escaped_label = label[:20].replace("'", "\\'").replace('"', '\\"') if label else ''
                    clicked = await page.evaluate(f"""
                        () => {{
                            let el = document.querySelector('{selector}');
                            
                            if (!el && '{escaped_label}') {{
                                const elements = document.querySelectorAll('a, button, [onclick], [role="button"]');
                                for (const e of elements) {{
                                    if (e.textContent.trim().startsWith('{escaped_label}')) {{
                                        el = e;
                                        break;
                                    }}
                                }}
                            }}
                            
                            if (el) {{
                                el.scrollIntoView({{block: 'center'}});
                                el.click();
                                return true;
                            }}
                            return false;
                        }}
                    """)
                    if clicked:
                        return True
                except Exception:
                    pass
                
            except PlaywrightError as e:
                error_msg = str(e).lower()
                
                if 'context was destroyed' in error_msg or 'navigation' in error_msg:
                    logger.debug(f"Navigation detected, waiting for page ready...")
                    await self.wait_for_page_ready(page)
                    return True
                
                if 'element is not attached' in error_msg:
                    if attempt < self.max_retries:
                        await asyncio.sleep(self.retry_delay)
                        continue
                
            except Exception as e:
                logger.debug(f"safe_click Fehler (Versuch {attempt + 1}): {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        return False
    
    async def safe_fill(self, page: Page, selector: str, value: str, label: str = "") -> bool:
        """
        Sicheres Ausfüllen von Input-Feldern mit Retry-Logik.
        """
        for attempt in range(self.max_retries + 1):
            try:
                if not await self.is_page_valid(page):
                    await self.wait_for_page_ready(page)
                
                if not await self.validate_element(page, selector):
                    if label:
                        escaped_label = label[:15].replace('"', '\\"')
                        alt_selector = f'input[placeholder*="{escaped_label}"], textarea[placeholder*="{escaped_label}"]'
                        if await self.validate_element(page, alt_selector):
                            selector = alt_selector
                        else:
                            return False
                    else:
                        return False
                
                await page.click(selector, timeout=2000)
                await page.fill(selector, value, timeout=2000)
                return True
                
            except PlaywrightError as e:
                error_msg = str(e).lower()
                
                if 'context was destroyed' in error_msg:
                    await self.wait_for_page_ready(page)
                    return False
                
            except Exception as e:
                logger.debug(f"safe_fill Fehler (Versuch {attempt + 1}): {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        return False
    
    async def get_action_candidates(self, page: Page) -> List[ActionCandidate]:
        """
        Findet alle interaktiven Elemente auf der Seite.
        Robuste Version mit Fehlerbehandlung.
        """
        for attempt in range(self.max_retries + 1):
            try:
                if not await self.is_page_valid(page):
                    await self.wait_for_page_ready(page)
                
                candidates_data = await page.evaluate("""
                    () => {
                        const candidates = [];
                        const currentHostname = window.location.hostname;
                        const currentOrigin = window.location.origin;
                        
                        const elements = document.querySelectorAll(
                            'input:not([type="hidden"]):not([disabled]), ' +
                            'textarea:not([disabled]), ' +
                            'select:not([disabled]), ' +
                            'button:not([disabled]), ' +
                            'a, ' +
                            '[onclick], ' +
                            '[role="button"], ' +
                            '[role="link"], ' +
                            '[tabindex="0"]'
                        );
                        
                        for (const el of elements) {
                            try {
                                const rect = el.getBoundingClientRect();
                                const style = window.getComputedStyle(el);
                                
                                if (rect.width <= 0 || rect.height <= 0) continue;
                                if (style.display === 'none') continue;
                                if (style.visibility === 'hidden') continue;
                                if (parseFloat(style.opacity) < 0.1) continue;
                                if (rect.bottom < 0 || rect.top > window.innerHeight * 2) continue;
                                
                                const tag = el.tagName.toLowerCase();
                                const type = el.getAttribute('type') || '';
                                const text = (el.textContent || el.value || el.placeholder || '').trim().substring(0, 50);
                                const href = el.getAttribute('href') || '';
                                const hasOnclick = el.hasAttribute('onclick');
                                
                                if (tag === 'a' && href) {
                                    if (href.startsWith('mailto:') || href.startsWith('tel:')) continue;
                                    if (href.startsWith('http') && !href.includes(currentHostname)) continue;
                                }
                                
                                let selector = tag;
                                if (el.id) {
                                    selector = '#' + CSS.escape(el.id);
                                } else if (el.name && (tag === 'input' || tag === 'textarea' || tag === 'select')) {
                                    selector = tag + '[name="' + el.name + '"]';
                                } else if (text && (tag === 'a' || tag === 'button' || hasOnclick)) {
                                    selector = tag + ':has-text("' + text.substring(0, 20).replace(/"/g, '\\\\"') + '")';
                                } else if (el.className && typeof el.className === 'string') {
                                    const firstClass = el.className.split(' ').find(c => c && c.length < 30);
                                    if (firstClass) {
                                        selector = tag + '.' + CSS.escape(firstClass);
                                    }
                                }
                                
                                if (selector === tag) {
                                    const siblings = Array.from(document.querySelectorAll(tag));
                                    const index = siblings.indexOf(el) + 1;
                                    selector = tag + ':nth-of-type(' + index + ')';
                                }
                                
                                let elementType = 'unknown';
                                if (tag === 'input' || tag === 'textarea') {
                                    elementType = 'input';
                                } else if (tag === 'select') {
                                    elementType = 'select';
                                } else if (tag === 'button' || el.getAttribute('role') === 'button') {
                                    elementType = 'button';
                                } else if (tag === 'a' || el.getAttribute('role') === 'link') {
                                    elementType = 'link';
                                } else if (hasOnclick) {
                                    elementType = 'onclick';
                                }
                                
                                candidates.push({
                                    selector: selector,
                                    type: elementType,
                                    tag: tag,
                                    label: text,
                                    inputType: type,
                                    href: href,
                                    hasOnclick: hasOnclick,
                                    rect: {
                                        top: rect.top,
                                        left: rect.left,
                                        width: rect.width,
                                        height: rect.height
                                    }
                                });
                                
                            } catch (e) {
                                continue;
                            }
                        }
                        
                        return candidates;
                    }
                """)
                
                # Konvertiere zu ActionCandidate Objekten
                candidates = [ActionCandidate.from_dict(c) for c in (candidates_data or [])]
                self.total_candidates += len(candidates)
                return candidates
                
            except PlaywrightError as e:
                error_msg = str(e).lower()
                
                if 'context was destroyed' in error_msg:
                    logger.debug("Context destroyed während get_action_candidates, warte...")
                    await self.wait_for_page_ready(page)
                    if attempt < self.max_retries:
                        continue
                    
            except Exception as e:
                logger.error(f"Fehler beim Sammeln der Candidates: {e}")
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        return []
    
    async def get_dom_size(self, page: Page) -> int:
        """Gibt die aktuelle DOM-Größe zurück und trackt Maximum"""
        try:
            if not await self.is_page_valid(page):
                return self.current_dom_size
            size = await page.evaluate("document.querySelectorAll('*').length")
            # Track maximum
            if size > self.max_dom_size:
                self.max_dom_size = size
            return size
        except Exception:
            return self.current_dom_size
    
    async def perform_action(self, page: Page, candidate: ActionCandidate) -> ActionResult:
        """
        Führt eine Aktion auf einem Element aus.
        Im Passiv-Modus werden Input-Felder übersprungen (keine Payloads).
        """
        import time
        start_time = time.time()
        
        selector = candidate.selector
        element_type = candidate.type
        label = candidate.label
        
        prev_dom_size = await self.get_dom_size(page)
        payload = None
        
        try:
            if element_type == 'input':
                # PASSIV-MODUS: Keine Payloads senden!
                if self.passive:
                    logger.debug(f"[PASSIV] Überspringe Input: {label[:20] if label else selector[:20]}")
                    # Nur klicken um Event-Handler zu triggern, aber nicht füllen
                    success = await self.safe_click(page, selector, label)
                else:
                    # AKTIV-MODUS: Payload senden
                    payload = self.get_next_payload()
                    success = await self.safe_fill(page, selector, payload, label)
                    
                    if success:
                        self.inputs_filled += 1
                        self.payloads_injected += 1
                        logger.info(f"💉 Payload in '{label[:20] or selector[:20]}': {payload[:40]}...")
                        await self._try_submit(page)
            else:
                success = await self.safe_click(page, selector, label)
            
            # DOM-Änderung messen
            await asyncio.sleep(0.3)
            new_dom_size = await self.get_dom_size(page)
            dom_change = new_dom_size - prev_dom_size
            
            duration = time.time() - start_time
            
            result = ActionResult(
                success=success,
                candidate=candidate,
                dom_change=dom_change,
                payload_injected=payload if success and element_type == 'input' else None,
                duration=duration
            )
            
            self.action_results.append(result)
            return result
                
        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            
            result = ActionResult(
                success=False,
                candidate=candidate,
                error=error_msg,
                duration=duration
            )
            
            self.action_results.append(result)
            self.errors.append(error_msg)
            return result
    
    async def _try_submit(self, page: Page):
        """Versucht einen Submit-Button zu finden und zu klicken"""
        try:
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Search")',
                'button:has-text("Submit")',
                'button:has-text("Go")',
                'button:has-text("Suchen")',
                'button:has-text("Absenden")',
            ]
            
            for selector in submit_selectors:
                if await self.validate_element(page, selector):
                    await self.safe_click(page, selector)
                    await asyncio.sleep(0.5)
                    return
                    
        except Exception:
            pass
    
    def should_continue(self) -> bool:
        """
        Prüft ob die Strategie weitermachen soll.
        Unterscheidet zwischen kritischen und nicht-kritischen Fehlern.
        """
        if self.critical_errors >= self.max_critical_errors:
            logger.warning(f"⚠️ Zu viele kritische Fehler ({self.critical_errors}), breche ab")
            return False
        
        if self.minor_errors >= self.max_minor_errors:
            logger.warning(f"⚠️ Zu viele kleine Fehler ({self.minor_errors}), breche ab")
            return False
        
        return True
    
    def record_error(self, critical: bool = False, message: str = ""):
        """Zeichnet einen Fehler auf"""
        if critical:
            self.critical_errors += 1
        else:
            self.minor_errors += 1
        
        if message:
            self.errors.append(message)
    
    def reset_error_count(self):
        """Setzt Fehler-Zähler zurück (nach erfolgreicher Aktion)"""
        self.minor_errors = max(0, self.minor_errors - 1)
    
    @abstractmethod
    async def run(self, page: Page, max_actions: int = 50) -> StrategyResult:
        """
        Führt die Strategie aus.
        Muss von Subklassen implementiert werden.
        """
        pass
    
    async def execute(self, page: Page, url: str = None, max_actions: int = 50) -> StrategyResult:
        """
        Wrapper für run() - für Kompatibilität mit main.py
        """
        from datetime import datetime
        self.url = url or page.url
        self.started_at = datetime.now().isoformat()
        return await self.run(page, max_actions)
    
    def get_result(self, duration: float) -> StrategyResult:
        """Erstellt StrategyResult aus aktuellem Zustand"""
        from datetime import datetime
        now = datetime.now().isoformat()
        
        # Zähle erfolgreiche/fehlgeschlagene Aktionen
        successful = sum(1 for r in self.action_results if r.success)
        failed = sum(1 for r in self.action_results if not r.success)
        
        return StrategyResult(
            strategy_name=self.name,
            actions_performed=self.actions_performed,
            inputs_filled=self.inputs_filled,
            payloads_injected=self.payloads_injected,
            initial_dom_size=self.initial_dom_size,
            final_dom_size=self.current_dom_size,
            duration=duration,
            url=getattr(self, 'url', ''),
            started_at=getattr(self, 'started_at', now),
            ended_at=now,
            actions_successful=successful,
            actions_failed=failed,
            max_dom_size_reached=getattr(self, 'max_dom_size', self.current_dom_size),
            dom_states_visited=len(self.visited_selectors),
            total_candidates_found=getattr(self, 'total_candidates', 0),
            unique_candidates_executed=len(self.visited_selectors),
            visited_selectors=list(self.visited_selectors),
            action_results=self.action_results,
            errors=self.errors
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Gibt Statistiken zurück"""
        return {
            'strategy': self.name,
            'actions_performed': self.actions_performed,
            'inputs_filled': self.inputs_filled,
            'payloads_injected': self.payloads_injected,
            'initial_dom_size': self.initial_dom_size,
            'final_dom_size': self.current_dom_size,
            'dom_growth': self.current_dom_size - self.initial_dom_size,
            'critical_errors': self.critical_errors,
            'minor_errors': self.minor_errors,
            'visited_elements': len(self.visited_selectors),
        }
