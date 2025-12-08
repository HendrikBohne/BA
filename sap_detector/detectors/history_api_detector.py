"""
SPA Detection Tool - History API Detector
Signal 1: History-API + URL-Änderung ohne Reload
"""
import logging
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


class HistoryAPIDetector:
    """Signal 1: History-API + URL-Änderung ohne Reload"""
    
    def __init__(self):
        self.pushstate_count = 0
        self.replacestate_count = 0
        self.popstate_count = 0
        self.url_changes = []
        self.frame_navigations = 0
        self.initial_url = None
        
    async def inject_monitors(self, page):
        """Injiziert JavaScript-Hooks für History-API"""
        try:
            self.initial_url = page.url
            
            await page.evaluate("""
                () => {
                    // Verhindere Mehrfach-Injection
                    if (window.__spa_detection_history_injected) return;
                    window.__spa_detection_history_injected = true;
                    
                    window.__spa_detection = window.__spa_detection || {};
                    window.__spa_detection.history = {
                        pushStateCount: 0,
                        replaceStateCount: 0,
                        popStateCount: 0,
                        urlChanges: []
                    };
                    
                    // Hook pushState
                    const originalPushState = history.pushState;
                    history.pushState = function(...args) {
                        try {
                            window.__spa_detection.history.pushStateCount++;
                            window.__spa_detection.history.urlChanges.push({
                                type: 'pushState',
                                url: args[2] || location.href,
                                timestamp: Date.now()
                            });
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
                            window.__spa_detection.history.urlChanges.push({
                                type: 'replaceState',
                                url: args[2] || location.href,
                                timestamp: Date.now()
                            });
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
                        } catch (e) {
                            console.error('SPA Detection popstate error:', e);
                        }
                    });
                }
            """)
            
            # Track frame navigations
            page.on("framenavigated", lambda frame: self._on_frame_navigated(frame))
            logger.info("History-API Monitor injiziert")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des History-Monitors: {e}")
    
    def _on_frame_navigated(self, frame):
        try:
            if frame == frame.page.main_frame:
                self.frame_navigations += 1
                logger.debug(f"Frame-Navigation #{self.frame_navigations}")
        except Exception as e:
            logger.error(f"Frame-Navigation Tracking Fehler: {e}")
    
    async def collect_data(self, page):
        """Sammelt die History-API Daten"""
        try:
            data = await page.evaluate("""
                () => {
                    if (!window.__spa_detection || !window.__spa_detection.history) {
                        return {
                            pushStateCount: 0,
                            replaceStateCount: 0,
                            popStateCount: 0,
                            urlChanges: []
                        };
                    }
                    return window.__spa_detection.history;
                }
            """)
            
            self.pushstate_count = data.get('pushStateCount', 0)
            self.replacestate_count = data.get('replaceStateCount', 0)
            self.popstate_count = data.get('popStateCount', 0)
            self.url_changes = data.get('urlChanges', [])
            
            logger.info(f"History-Daten: {self.pushstate_count} pushState, "
                       f"{self.replacestate_count} replaceState, "
                       f"{self.popstate_count} popstate")
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der History-Daten: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert die gesammelten Daten"""
        try:
            total_history_calls = (self.pushstate_count + 
                                  self.replacestate_count + 
                                  self.popstate_count)
            
            detected = False
            confidence = 0.0
            
            # Starkes Signal: Viele History-Calls, wenige Navigations
            if total_history_calls >= 3 and self.frame_navigations <= 2:
                detected = True
                confidence = min(0.95, 0.5 + (total_history_calls / 20.0))
            # Mittleres Signal
            elif total_history_calls >= 2 and self.frame_navigations <= 2:
                detected = True
                confidence = 0.6
            # Schwaches Signal
            elif total_history_calls >= 1 and self.frame_navigations == 1:
                detected = True
                confidence = 0.4
            
            evidence = {
                'pushstate_count': self.pushstate_count,
                'replacestate_count': self.replacestate_count,
                'popstate_count': self.popstate_count,
                'total_history_calls': total_history_calls,
                'frame_navigations': self.frame_navigations,
                'url_changes': len(self.url_changes),
                'sample_changes': self.url_changes[:5]
            }
            
            return DetectionResult(
                signal_name="History-API Navigation",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"History-API Calls: {total_history_calls}, Frame-Navigations: {self.frame_navigations}"
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