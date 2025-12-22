"""
SPA Detection Tool - Title Change Detector (FIXED v2)
Signal 4: Soft-Navigation + Titeländerung

FIXES:
1. Verwendet add_init_script() für persistente Injection über Navigationen hinweg
2. Akkumuliert Title-Changes über Navigationen hinweg
"""
import logging
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


# JavaScript Code als Konstante (wird bei jeder Navigation injiziert)
TITLE_OBSERVER_SCRIPT = """
(() => {
    // Verhindere Mehrfach-Injection im gleichen Kontext
    if (window.__spa_detection_title_injected) return;
    window.__spa_detection_title_injected = true;
    
    window.__spa_detection = window.__spa_detection || {};
    
    // Existierende Changes behalten (Akkumulation über Navigationen)
    const existingChanges = (window.__spa_detection.title && 
                            window.__spa_detection.title.changes) || [];
    
    // Aktuellen Titel hinzufügen wenn neu
    const currentTitle = document.title;
    const lastTitle = existingChanges.length > 0 ? 
                      existingChanges[existingChanges.length - 1].title : null;
    
    if (currentTitle !== lastTitle) {
        existingChanges.push({ 
            title: currentTitle, 
            timestamp: Date.now(),
            url: location.href,
            type: 'navigation'
        });
    }
    
    window.__spa_detection.title = {
        changes: existingChanges,
        observerActive: false,
        injectionCount: ((window.__spa_detection.title && 
                         window.__spa_detection.title.injectionCount) || 0) + 1,
        injectionTime: Date.now()
    };
    
    const startObserver = () => {
        try {
            const titleElement = document.querySelector('title');
            if (!titleElement) {
                console.warn('[SPA-Detection] No title element found');
                return;
            }
            
            const observer = new MutationObserver(() => {
                try {
                    const newTitle = document.title;
                    const changes = window.__spa_detection.title.changes;
                    
                    // Nur hinzufügen wenn sich der Titel wirklich geändert hat
                    if (changes.length === 0 || changes[changes.length - 1].title !== newTitle) {
                        changes.push({
                            title: newTitle,
                            timestamp: Date.now(),
                            url: location.href,
                            type: 'mutation'
                        });
                        console.log('[SPA-Detection] Title changed to:', newTitle);
                    }
                } catch (e) {
                    console.error('[SPA-Detection] Title tracking error:', e);
                }
            });
            
            observer.observe(titleElement, {
                childList: true,
                characterData: true,
                subtree: true
            });
            
            window.__spa_detection.title.observerActive = true;
            console.log('[SPA-Detection] Title observer active (injection #' + 
                       window.__spa_detection.title.injectionCount + ')');
        } catch (e) {
            console.error('[SPA-Detection] Title observer setup failed:', e);
        }
    };
    
    // Starte sofort wenn DOM bereit
    if (document.querySelector('title')) {
        startObserver();
    } else {
        document.addEventListener('DOMContentLoaded', startObserver);
        window.addEventListener('load', () => {
            if (!window.__spa_detection.title.observerActive) {
                startObserver();
            }
        });
    }
})();
"""


class TitleChangeDetector:
    """Signal 4: Soft-Navigation + Titeländerung"""
    
    def __init__(self):
        self.title_changes = []
        self._init_script_added = False
        
    async def inject_observer(self, page):
        """
        Beobachtet Title-Änderungen.
        
        WICHTIG: Verwendet add_init_script() damit der Observer bei
        jeder Navigation automatisch neu gestartet wird.
        """
        try:
            # add_init_script() wird bei JEDER Navigation ausgeführt!
            if not self._init_script_added:
                await page.context.add_init_script(TITLE_OBSERVER_SCRIPT)
                self._init_script_added = True
                logger.info("Title-Observer als InitScript registriert")
            
            # Auch für die aktuelle Seite injizieren
            try:
                await page.evaluate(TITLE_OBSERVER_SCRIPT)
            except Exception as e:
                logger.debug(f"Initiale Title-Injection übersprungen: {e}")
            
            logger.info("Title-Observer injiziert")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des Title-Observers: {e}")
    
    async def collect_data(self, page):
        """Sammelt Title-Changes"""
        try:
            data = await page.evaluate("""
                () => {
                    if (!window.__spa_detection || !window.__spa_detection.title) {
                        return { 
                            changes: [{ title: document.title, timestamp: Date.now() }],
                            observerActive: false,
                            injectionCount: 0
                        };
                    }
                    return {
                        changes: window.__spa_detection.title.changes,
                        observerActive: window.__spa_detection.title.observerActive,
                        injectionCount: window.__spa_detection.title.injectionCount
                    };
                }
            """)
            
            self.title_changes = data.get('changes', [])
            observer_active = data.get('observerActive', False)
            injection_count = data.get('injectionCount', 0)
            logger.info(f"Title-Daten: {len(self.title_changes)} Änderungen "
                       f"(Observer aktiv: {observer_active}, Injections: {injection_count})")
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der Title-Daten: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert Title-Änderungen"""
        try:
            unique_titles = list(set([c['title'] for c in self.title_changes]))
            change_count = len(self.title_changes) - 1
            
            detected = False
            confidence = 0.0
            
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
