"""
SPA Detection Tool - Title Change Detector
Signal 4: Soft-Navigation + Titeländerung
"""
import logging
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


class TitleChangeDetector:
    """Signal 4: Soft-Navigation + Titeländerung"""
    
    def __init__(self):
        self.title_changes = []
        self._observer_injected = False
        
    async def inject_observer(self, page):
        """Beobachtet Title-Änderungen"""
        try:
            if self._observer_injected:
                return
                
            await page.evaluate("""
                () => {
                    if (window.__spa_detection_title_injected) return;
                    window.__spa_detection_title_injected = true;
                    
                    window.__spa_detection = window.__spa_detection || {};
                    window.__spa_detection.title = {
                        changes: [{ title: document.title, timestamp: Date.now() }]
                    };
                    
                    try {
                        const observer = new MutationObserver(() => {
                            try {
                                window.__spa_detection.title.changes.push({
                                    title: document.title,
                                    timestamp: Date.now()
                                });
                            } catch (e) {
                                console.error('Title tracking error:', e);
                            }
                        });
                        
                        const titleElement = document.querySelector('title');
                        if (titleElement) {
                            observer.observe(titleElement, {
                                childList: true,
                                characterData: true,
                                subtree: true
                            });
                        }
                        
                        console.log('SPA Detection: Title observer active');
                    } catch (e) {
                        console.error('SPA Detection: Title observer failed:', e);
                    }
                }
            """)
            
            self._observer_injected = True
            logger.info("Title-Observer injiziert")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des Title-Observers: {e}")
    
    async def collect_data(self, page):
        """Sammelt Title-Changes"""
        try:
            data = await page.evaluate("""
                () => {
                    if (!window.__spa_detection || !window.__spa_detection.title) {
                        return { changes: [{ title: document.title, timestamp: Date.now() }] };
                    }
                    return window.__spa_detection.title;
                }
            """)
            
            self.title_changes = data.get('changes', [])
            logger.info(f"Title-Daten: {len(self.title_changes)} Änderungen")
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der Title-Daten: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert Title-Änderungen"""
        try:
            unique_titles = list(set([c['title'] for c in self.title_changes]))
            change_count = len(self.title_changes) - 1
            
            detected = False
            confidence = 0.0
            
            # Signal: Mehrere verschiedene Titel
            if change_count >= 3 and len(unique_titles) >= 3:
                detected = True
                confidence = min(0.90, 0.5 + (change_count / 15.0))
            elif change_count >= 2 and len(unique_titles) >= 2:
                detected = True
                confidence = 0.6
            elif change_count >= 1 and len(unique_titles) >= 2:
                detected = True
                confidence = 0.4
            
            evidence = {
                'title_change_count': change_count,
                'unique_titles': len(unique_titles),
                'titles': unique_titles[:10],
                'changes': self.title_changes
            }
            
            return DetectionResult(
                signal_name="Title Change Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"Title-Änderungen: {change_count}, Unique: {len(unique_titles)}"
            )
            
        except Exception as e:
            logger.error(f"Fehler bei Title-Analyse: {e}")
            return DetectionResult(
                signal_name="Title Change Pattern",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )