"""
SPA Detection Tool - History API Detector (FIXED v2)
Signal 1: History-API + URL-Änderung ohne Reload

FIXES:
1. Verwendet add_init_script() für persistente Injection über Navigationen hinweg
2. Gelockerte Schwellwerte - Frame-Navigations werden anders bewertet
3. Bessere Fehlerbehandlung bei zerstörtem Context
"""
import logging
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


# JavaScript Code als Konstante (wird bei jeder Navigation injiziert)
HISTORY_MONITOR_SCRIPT = """
(() => {
    // Verhindere Mehrfach-Injection im gleichen Kontext
    if (window.__spa_detection_history_injected) return;
    window.__spa_detection_history_injected = true;
    
    window.__spa_detection = window.__spa_detection || {};
    window.__spa_detection.history = {
        pushStateCount: 0,
        replaceStateCount: 0,
        popStateCount: 0,
        urlChanges: [],
        injectionTime: Date.now(),
        currentUrl: location.href
    };
    
    // Hook pushState
    const originalPushState = history.pushState;
    history.pushState = function(...args) {
        try {
            window.__spa_detection.history.pushStateCount++;
            const newUrl = args[2] || location.href;
            window.__spa_detection.history.urlChanges.push({
                type: 'pushState',
                url: newUrl,
                fromUrl: window.__spa_detection.history.currentUrl,
                timestamp: Date.now()
            });
            window.__spa_detection.history.currentUrl = newUrl;
            console.log('[SPA-Detection] pushState:', newUrl);
        } catch (e) {
            console.error('SPA Detection pushState error:', e);
        }
        return originalPushState.apply(this, args);
    };
    
    // Hook replaceState
    const originalReplaceState = history.replaceState;
    history.replaceState = function(...args) {
        try {
            window.__spa_detection.history.replaceStateCount++;
            const newUrl = args[2] || location.href;
            window.__spa_detection.history.urlChanges.push({
                type: 'replaceState',
                url: newUrl,
                fromUrl: window.__spa_detection.history.currentUrl,
                timestamp: Date.now()
            });
            window.__spa_detection.history.currentUrl = newUrl;
            console.log('[SPA-Detection] replaceState:', newUrl);
        } catch (e) {
            console.error('SPA Detection replaceState error:', e);
        }
        return originalReplaceState.apply(this, args);
    };
    
    // Listen to popstate
    window.addEventListener('popstate', () => {
        try {
            window.__spa_detection.history.popStateCount++;
            window.__spa_detection.history.urlChanges.push({
                type: 'popstate',
                url: location.href,
                timestamp: Date.now()
            });
            window.__spa_detection.history.currentUrl = location.href;
            console.log('[SPA-Detection] popstate:', location.href);
        } catch (e) {
            console.error('SPA Detection popstate error:', e);
        }
    });
    
    console.log('[SPA-Detection] History monitor initialized at:', location.href);
})();
"""


class HistoryAPIDetector:
    """Signal 1: History-API + URL-Änderung ohne Reload"""
    
    def __init__(self):
        self.pushstate_count = 0
        self.replacestate_count = 0
        self.popstate_count = 0
        self.url_changes = []
        self.frame_navigations = 0
        self.initial_url = None
        self._init_script_added = False
        self._context = None
        
    async def inject_monitors(self, page):
        """
        Injiziert JavaScript-Hooks für History-API.
        
        WICHTIG: Verwendet add_init_script() damit die Hooks bei
        jeder Navigation (auch Redirects) automatisch neu injiziert werden.
        """
        try:
            self.initial_url = page.url
            self._context = page.context
            
            # add_init_script() wird bei JEDER Navigation ausgeführt!
            # Das ist der Schlüssel - der Script überlebt Browser-Navigationen
            if not self._init_script_added:
                await page.context.add_init_script(HISTORY_MONITOR_SCRIPT)
                self._init_script_added = True
                logger.info("History-API Monitor als InitScript registriert")
            
            # Auch für die aktuelle Seite injizieren (falls schon geladen)
            try:
                await page.evaluate(HISTORY_MONITOR_SCRIPT)
            except Exception as e:
                logger.debug(f"Initiale Injection übersprungen (bereits geladen): {e}")
            
            # Track frame navigations
            page.on("framenavigated", lambda frame: self._on_frame_navigated(frame))
            logger.info("History-API Monitor injiziert")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des History-Monitors: {e}")
    
    def _on_frame_navigated(self, frame):
        """Zählt echte Browser-Navigationen (Frame-Navigations)"""
        try:
            if frame == frame.page.main_frame:
                self.frame_navigations += 1
                logger.debug(f"Frame-Navigation #{self.frame_navigations}: {frame.url}")
        except Exception as e:
            logger.error(f"Frame-Navigation Tracking Fehler: {e}")
    
    async def collect_data(self, page):
        """Sammelt die History-API Daten mit Fehlerbehandlung"""
        try:
            data = await page.evaluate("""
                () => {
                    if (!window.__spa_detection || !window.__spa_detection.history) {
                        return {
                            pushStateCount: 0,
                            replaceStateCount: 0,
                            popStateCount: 0,
                            urlChanges: [],
                            injected: false
                        };
                    }
                    return {
                        ...window.__spa_detection.history,
                        injected: true
                    };
                }
            """)
            
            self.pushstate_count = data.get('pushStateCount', 0)
            self.replacestate_count = data.get('replaceStateCount', 0)
            self.popstate_count = data.get('popStateCount', 0)
            self.url_changes = data.get('urlChanges', [])
            
            injected = data.get('injected', False)
            logger.info(f"History-Daten: {self.pushstate_count} pushState, "
                       f"{self.replacestate_count} replaceState, "
                       f"{self.popstate_count} popstate "
                       f"(Script aktiv: {injected})")
            
        except Exception as e:
            # Bei "Execution context was destroyed" - das passiert bei Navigation
            logger.error(f"Fehler beim Sammeln der History-Daten: {e}")
            # Wir behalten die bereits gesammelten Frame-Navigations
    
    def analyze(self) -> DetectionResult:
        """
        Analysiert die gesammelten Daten mit GELOCKERTEN Schwellwerten.
        
        NEUE LOGIK:
        - History-API Calls sind ein starkes SPA-Signal
        - Frame-Navigations reduzieren die Confidence, aber invalidieren nicht
        - Auch bei vielen Frame-Navigations kann es eine SPA sein (Hybrid-Apps)
        """
        try:
            total_history_calls = (self.pushstate_count + 
                                  self.replacestate_count + 
                                  self.popstate_count)
            
            detected = False
            confidence = 0.0
            reasons = []
            
            # NEUE LOGIK: History-Calls sind das Hauptsignal
            if total_history_calls >= 1:
                detected = True
                
                # Basis-Confidence basierend auf Anzahl der History-Calls
                if total_history_calls >= 5:
                    confidence = 0.85
                    reasons.append(f"viele_history_calls={total_history_calls}")
                elif total_history_calls >= 3:
                    confidence = 0.70
                    reasons.append(f"mehrere_history_calls={total_history_calls}")
                elif total_history_calls >= 1:
                    confidence = 0.50
                    reasons.append(f"history_calls={total_history_calls}")
                
                # Abzug für Frame-Navigations (aber nicht zu stark!)
                # Verhältnis: Wenn mehr Frame-Navigations als History-Calls → reduziere
                if self.frame_navigations > 0:
                    ratio = total_history_calls / self.frame_navigations
                    if ratio >= 2:
                        # Doppelt so viele History-Calls wie Frame-Navs → Bonus
                        confidence = min(0.95, confidence + 0.1)
                        reasons.append("gutes_ratio")
                    elif ratio >= 1:
                        # Gleich viele → neutral
                        pass
                    elif ratio >= 0.5:
                        # Weniger History-Calls → leichter Abzug
                        confidence = max(0.3, confidence - 0.1)
                        reasons.append("gemischte_navigation")
                    else:
                        # Sehr wenige History-Calls vs Frame-Navs → stärkerer Abzug
                        confidence = max(0.2, confidence - 0.2)
                        reasons.append("meist_frame_navigation")
            
            # Wenn gar keine History-Calls aber viele Frame-Navigations
            elif self.frame_navigations > 2:
                detected = False
                confidence = 0.0
                reasons.append("nur_frame_navigations")
            
            evidence = {
                'pushstate_count': self.pushstate_count,
                'replacestate_count': self.replacestate_count,
                'popstate_count': self.popstate_count,
                'total_history_calls': total_history_calls,
                'frame_navigations': self.frame_navigations,
                'url_changes': len(self.url_changes),
                'sample_changes': self.url_changes[:5],
                'detection_reasons': reasons,
                'history_to_frame_ratio': (
                    total_history_calls / max(1, self.frame_navigations)
                )
            }
            
            description = (
                f"History-API Calls: {total_history_calls}, "
                f"Frame-Navigations: {self.frame_navigations}"
            )
            if reasons:
                description += f" ({', '.join(reasons)})"
            
            return DetectionResult(
                signal_name="History-API Navigation",
                detected=detected,
                confidence=round(confidence, 2),
                evidence=evidence,
                description=description
            )
            
        except Exception as e:
            logger.error(f"Fehler bei History-API Analyse: {e}")
            return DetectionResult(
                signal_name="History-API Navigation",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )
