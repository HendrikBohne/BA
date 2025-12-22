"""
DOM XSS Trigger Strategies - Coverage Analyzer
Analysiert Code-Coverage während der Interaktionen
"""
import logging
from typing import Dict, Optional, List, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CoverageSnapshot:
    """Snapshot der Coverage zu einem Zeitpunkt"""
    timestamp: float
    functions_executed: Set[str] = field(default_factory=set)
    lines_executed: Set[str] = field(default_factory=set)
    event_handlers_triggered: Set[str] = field(default_factory=set)
    dom_elements_interacted: Set[str] = field(default_factory=set)


class CoverageAnalyzer:
    """
    Analysiert JavaScript Code-Coverage.
    
    Trackt:
    - Ausgeführte Funktionen
    - Ausgeführte Code-Zeilen
    - Getriggerte Event-Handler
    - Interagierte DOM-Elemente
    
    Hinweis: Vollständige JS-Coverage erfordert Browser-DevTools
    oder Instrumentation. Diese Implementierung bietet eine
    Approximation basierend auf DOM-Beobachtung.
    """
    
    def __init__(self):
        self.snapshots: List[CoverageSnapshot] = []
        self._initial_state: Optional[Dict] = None
        
    async def start_tracking(self, page):
        """
        Startet Coverage-Tracking.
        
        Injiziert Tracking-Hooks und speichert initialen Zustand.
        """
        logger.info("📊 Starte Coverage-Tracking...")
        
        # Speichere initialen Zustand
        self._initial_state = await self._capture_state(page)
        
        # Injiziere Coverage-Hooks
        await self._inject_coverage_hooks(page)
        
        logger.info("✅ Coverage-Tracking aktiv")
    
    async def _inject_coverage_hooks(self, page):
        """Injiziert JavaScript-Hooks für Coverage-Tracking"""
        await page.evaluate("""
            () => {
                if (window.__coverage_tracking_injected) return;
                window.__coverage_tracking_injected = true;
                
                window.__coverage = {
                    functions: new Set(),
                    eventHandlers: new Set(),
                    domInteractions: new Set(),
                    errors: []
                };
                
                // Track Event Handler Execution
                const originalAddEventListener = EventTarget.prototype.addEventListener;
                EventTarget.prototype.addEventListener = function(type, listener, options) {
                    const wrappedListener = function(event) {
                        window.__coverage.eventHandlers.add(`${type}:${event.target?.tagName || 'unknown'}`);
                        return listener.apply(this, arguments);
                    };
                    return originalAddEventListener.call(this, type, wrappedListener, options);
                };
                
                // Track DOM Interactions via click
                document.addEventListener('click', (e) => {
                    const target = e.target;
                    const id = target.id || target.className?.split(' ')[0] || target.tagName;
                    window.__coverage.domInteractions.add(`click:${target.tagName}:${id}`);
                }, true);
                
                // Track Errors
                window.addEventListener('error', (e) => {
                    window.__coverage.errors.push({
                        message: e.message,
                        filename: e.filename,
                        lineno: e.lineno
                    });
                });
                
                console.log('[Coverage] Tracking hooks injected');
            }
        """)
    
    async def _capture_state(self, page) -> Dict:
        """Erfasst aktuellen Seitenzustand"""
        return await page.evaluate("""
            () => {
                const state = {
                    // DOM Statistics
                    totalElements: document.getElementsByTagName('*').length,
                    forms: document.forms.length,
                    inputs: document.querySelectorAll('input, textarea, select').length,
                    buttons: document.querySelectorAll('button, [role="button"]').length,
                    links: document.querySelectorAll('a[href]').length,
                    
                    // Scripts
                    scripts: document.scripts.length,
                    inlineScripts: Array.from(document.scripts).filter(s => !s.src).length,
                    externalScripts: Array.from(document.scripts).filter(s => s.src).length,
                    
                    // Event Handlers (approximate)
                    elementsWithOnclick: document.querySelectorAll('[onclick]').length,
                    elementsWithOnsubmit: document.querySelectorAll('[onsubmit]').length,
                    elementsWithOninput: document.querySelectorAll('[oninput]').length,
                    
                    // Timestamp
                    timestamp: Date.now()
                };
                
                return state;
            }
        """)
    
    async def take_snapshot(self, page) -> CoverageSnapshot:
        """Nimmt einen Coverage-Snapshot"""
        import asyncio
        
        data = await page.evaluate("""
            () => {
                if (!window.__coverage) {
                    return {
                        functions: [],
                        eventHandlers: [],
                        domInteractions: [],
                        errors: []
                    };
                }
                
                return {
                    functions: Array.from(window.__coverage.functions),
                    eventHandlers: Array.from(window.__coverage.eventHandlers),
                    domInteractions: Array.from(window.__coverage.domInteractions),
                    errors: window.__coverage.errors
                };
            }
        """)
        
        snapshot = CoverageSnapshot(
            timestamp=asyncio.get_event_loop().time(),
            functions_executed=set(data.get('functions', [])),
            event_handlers_triggered=set(data.get('eventHandlers', [])),
            dom_elements_interacted=set(data.get('domInteractions', []))
        )
        
        self.snapshots.append(snapshot)
        return snapshot
    
    async def analyze(self, page) -> Dict:
        """
        Analysiert die gesammelte Coverage.
        
        Returns:
            Dictionary mit Coverage-Metriken
        """
        # Finaler Snapshot
        final_snapshot = await self.take_snapshot(page)
        final_state = await self._capture_state(page)
        
        # Berechne Metriken
        initial = self._initial_state or {}
        
        # DOM Coverage
        dom_total = initial.get('totalElements', 0)
        dom_interacted = len(final_snapshot.dom_elements_interacted)
        
        # Event Handler Coverage (Approximation)
        handlers_total = (
            initial.get('elementsWithOnclick', 0) +
            initial.get('elementsWithOnsubmit', 0) +
            initial.get('elementsWithOninput', 0)
        )
        handlers_triggered = len(final_snapshot.event_handlers_triggered)
        
        # Script Coverage (sehr grobe Approximation)
        scripts_total = initial.get('scripts', 0)
        
        metrics = {
            # DOM
            'dom_total': dom_total,
            'dom_interacted': dom_interacted,
            'dom_coverage_percent': (dom_interacted / max(1, dom_total)) * 100,
            
            # Event Handlers
            'handlers_total': handlers_total,
            'handlers_triggered': handlers_triggered,
            'handler_coverage_percent': (handlers_triggered / max(1, handlers_total)) * 100,
            
            # Functions (requires instrumentation for accurate data)
            'functions_total': scripts_total * 10,  # Rough estimate
            'functions_executed': len(final_snapshot.functions_executed),
            
            # Lines (requires instrumentation)
            'lines_total': 0,
            'lines_executed': 0,
            
            # Summary
            'snapshots_taken': len(self.snapshots),
            'unique_interactions': dom_interacted,
            'unique_handlers': handlers_triggered
        }
        
        logger.info(f"📊 Coverage: DOM {metrics['dom_coverage_percent']:.1f}%, "
                   f"Handlers {metrics['handler_coverage_percent']:.1f}%")
        
        return metrics
    
    def get_coverage_over_time(self) -> List[Dict]:
        """Gibt Coverage-Verlauf über Zeit zurück"""
        return [
            {
                'timestamp': s.timestamp,
                'functions': len(s.functions_executed),
                'handlers': len(s.event_handlers_triggered),
                'interactions': len(s.dom_elements_interacted)
            }
            for s in self.snapshots
        ]
    
    def reset(self):
        """Setzt Coverage-Tracking zurück"""
        self.snapshots = []
        self._initial_state = None
