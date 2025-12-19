"""
SPA Detection Tool - DOM Rewriting Detector (FIXED v3)
Signal 3: Signifikantes DOM-Rewriting

FIXES v3:
- Robustere Observer-Initialisierung mit Polling
- Fallback wenn DOMContentLoaded verpasst wird
- Bessere Fehlerbehandlung bei collect_data
"""
import logging
from typing import Optional, Dict
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


# JavaScript Code - robuster mit Polling-Fallback
DOM_OBSERVER_SCRIPT = """
(() => {
    // Verhindere Mehrfach-Injection im exakt gleichen Aufruf
    if (window.__spa_detection_dom_injecting) return;
    window.__spa_detection_dom_injecting = true;
    
    // Aber erlaube Re-Injection nach Navigation
    const wasInjected = window.__spa_detection_dom_injected;
    window.__spa_detection_dom_injected = true;

    window.__spa_detection = window.__spa_detection || {};
    
    // Zeitbaseline
    if (typeof window.__spa_detection.t0 !== 'number') {
        window.__spa_detection.t0 = performance.now();
    }
    
    // Initialisiere oder behalte DOM-Daten
    const existingDom = window.__spa_detection.dom || {};
    const injectionCount = (existingDom.injectionCount || 0) + 1;
    
    window.__spa_detection.dom = {
        mutationCount: existingDom.mutationCount || 0,
        nodesAdded: existingDom.nodesAdded || 0,
        nodesRemoved: existingDom.nodesRemoved || 0,
        largeMutations: existingDom.largeMutations || [],
        mediumMutations: existingDom.mediumMutations || [],
        smallMutationsCount: existingDom.smallMutationsCount || 0,
        firstMutationTime: existingDom.firstMutationTime || null,
        lastMutationTime: null,
        observerActive: false,
        injectionCount: injectionCount,
        injectionTime: Date.now(),
        startAttempts: 0,
        initial: existingDom.initial || { length: 0, tagCount: 0 }
    };

    const startObserver = () => {
        const dom = window.__spa_detection.dom;
        dom.startAttempts++;
        
        // Finde Target
        const targetNode = document.body || document.documentElement;
        
        if (!targetNode) {
            console.warn('[SPA-Detection] Kein Target für Observer (Versuch ' + dom.startAttempts + ')');
            
            // Retry nach kurzer Zeit (max 10 Versuche)
            if (dom.startAttempts < 10) {
                setTimeout(startObserver, 100);
            }
            return;
        }
        
        // Bereits aktiver Observer? Nicht nochmal starten
        if (dom.observerActive) {
            console.log('[SPA-Detection] Observer bereits aktiv');
            return;
        }
        
        // Initial-Metriken
        if (dom.initial.tagCount === 0) {
            try {
                dom.initial = {
                    length: (document.documentElement.outerHTML || '').length,
                    tagCount: document.getElementsByTagName('*').length
                };
            } catch (e) {}
        }
        
        try {
            const observer = new MutationObserver((mutations) => {
                try {
                    const t = performance.now();
                    const d = window.__spa_detection.dom;
                    
                    if (d.firstMutationTime === null) {
                        d.firstMutationTime = t;
                    }
                    d.lastMutationTime = t;
                    
                    mutations.forEach(mutation => {
                        d.mutationCount++;
                        
                        const added = mutation.addedNodes ? mutation.addedNodes.length : 0;
                        const removed = mutation.removedNodes ? mutation.removedNodes.length : 0;
                        const total = added + removed;
                        
                        d.nodesAdded += added;
                        d.nodesRemoved += removed;
                        
                        if (total >= 5 && d.largeMutations.length < 50) {
                            d.largeMutations.push({
                                added, removed,
                                timestamp_perf: t,
                                target: mutation.target?.nodeName || 'UNKNOWN'
                            });
                        } else if (total >= 2 && d.mediumMutations.length < 100) {
                            d.mediumMutations.push({ added, removed, timestamp_perf: t });
                        } else if (total >= 1) {
                            d.smallMutationsCount++;
                        }
                    });
                } catch (e) {
                    console.error('[SPA-Detection] Mutation error:', e);
                }
            });

            observer.observe(targetNode, {
                childList: true,
                subtree: true
            });
            
            dom.observerActive = true;
            dom.observerStartedAt = Date.now();
            console.log('[SPA-Detection] DOM Observer AKTIV (Injection #' + injectionCount + ', Versuch #' + dom.startAttempts + ')');
            
        } catch (e) {
            console.error('[SPA-Detection] Observer start failed:', e);
        }
    };

    // SOFORT versuchen zu starten
    startObserver();
    
    // Fallback: Nach DOMContentLoaded nochmal versuchen
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            if (!window.__spa_detection.dom.observerActive) {
                startObserver();
            }
        });
    }
    
    // Fallback: Nach load nochmal versuchen
    window.addEventListener('load', () => {
        if (!window.__spa_detection.dom.observerActive) {
            startObserver();
        }
    });
    
    // Cleanup Flag
    setTimeout(() => {
        window.__spa_detection_dom_injecting = false;
    }, 100);
})();
"""


class DOMRewritingDetector:
    """Signal 3: Signifikantes DOM-Rewriting (FIXED v3)"""
    
    def __init__(self, early_ms: int = 2000):
        self.mutation_count = 0
        self.nodes_added = 0
        self.nodes_removed = 0
        self.container_mutations = []
        self.medium_mutations = []
        self.small_mutations_count = 0
        self._init_script_added = False
        
        self.early_ms = early_ms
        self._t0 = None
        self._events = []
        self._observation_duration_ms = 0
        
        self._server_html: Optional[str] = None
        self._server_metrics: Optional[Dict[str, int]] = None
        self._initial_dom_metrics: Optional[Dict[str, int]] = None
        self._final_dom_metrics: Optional[Dict[str, int]] = None
    
    def record_server_html(self, html: str):
        self._server_html = html
        self._server_metrics = self._basic_dom_metrics(html)
    
    def _basic_dom_metrics(self, html: str) -> Dict[str, int]:
        try:
            import re
            tags = re.findall(r"<([a-zA-Z0-9-]+)(\s|>)", html or "")
            return {"length": len(html or ""), "tag_count": len(tags)}
        except Exception:
            return {"length": 0, "tag_count": 0}
    
    async def inject_observer(self, page):
        """Injiziert MutationObserver mit add_init_script UND direkter Injection"""
        try:
            # Registriere für zukünftige Navigationen
            if not self._init_script_added:
                await page.context.add_init_script(DOM_OBSERVER_SCRIPT)
                self._init_script_added = True
                logger.info("DOM-Observer als InitScript registriert")
            
            # Direkt injizieren für aktuelle Seite
            try:
                await page.evaluate(DOM_OBSERVER_SCRIPT)
            except Exception as e:
                logger.debug(f"Direkte DOM-Injection: {e}")
            
            # Warte kurz und prüfe ob Observer aktiv ist
            await page.wait_for_timeout(200)
            
            try:
                status = await page.evaluate("""
                    () => ({
                        active: !!(window.__spa_detection && window.__spa_detection.dom && window.__spa_detection.dom.observerActive),
                        attempts: (window.__spa_detection && window.__spa_detection.dom) ? window.__spa_detection.dom.startAttempts : 0
                    })
                """)
                
                if status.get('active'):
                    logger.info("DOM-Observer injiziert (auf document.body)")
                else:
                    logger.warning(f"DOM-Observer nicht aktiv nach {status.get('attempts', 0)} Versuchen")
                    
            except Exception as e:
                logger.debug(f"Status-Check fehlgeschlagen: {e}")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des DOM-Observers: {e}")
    
    async def collect_data(self, page):
        """Sammelt Mutations-Daten mit Fehlerbehandlung"""
        try:
            data = await page.evaluate("""
                () => {
                    const dom = (window.__spa_detection && window.__spa_detection.dom) || null;
                    const t0 = (window.__spa_detection && window.__spa_detection.t0) || null;
                    const currentTime = performance.now();
                    
                    if (!dom) {
                        return {
                            dom: {
                                mutationCount: 0,
                                nodesAdded: 0,
                                nodesRemoved: 0,
                                largeMutations: [],
                                mediumMutations: [],
                                smallMutationsCount: 0,
                                observerActive: false,
                                injectionCount: 0,
                                initial: { length: 0, tagCount: 0 }
                            },
                            t0: currentTime,
                            currentTime: currentTime,
                            finalMetrics: {
                                length: (document.documentElement.outerHTML || '').length,
                                tagCount: document.getElementsByTagName('*').length
                            }
                        };
                    }
                    
                    return { 
                        dom, 
                        t0, 
                        currentTime,
                        finalMetrics: {
                            length: (document.documentElement.outerHTML || '').length,
                            tagCount: document.getElementsByTagName('*').length
                        }
                    };
                }
            """)
            
            dom = data.get('dom') or {}
            
            self.mutation_count = int(dom.get('mutationCount', 0) or 0)
            self.nodes_added = int(dom.get('nodesAdded', 0) or 0)
            self.nodes_removed = int(dom.get('nodesRemoved', 0) or 0)
            
            self.container_mutations = dom.get('largeMutations', []) or []
            self.medium_mutations = dom.get('mediumMutations', []) or []
            self.small_mutations_count = int(dom.get('smallMutationsCount', 0) or 0)
            
            self._t0 = data.get('t0')
            current_time = data.get('currentTime', 0)
            
            if self._t0 and current_time:
                self._observation_duration_ms = current_time - self._t0
            
            self._initial_dom_metrics = dom.get('initial') or {"length": 0, "tagCount": 0}
            self._final_dom_metrics = data.get('finalMetrics') or {"length": 0, "tagCount": 0}
            
            observer_active = dom.get('observerActive', False)
            injection_count = dom.get('injectionCount', 0)
            
            logger.info(
                f"DOM-Daten gesammelt (Observer aktiv: {observer_active}, Injections: {injection_count}):\n"
                f"  - Mutations gesamt: {self.mutation_count}\n"
                f"  - Nodes added: {self.nodes_added}, removed: {self.nodes_removed}\n"
                f"  - Große Mutations (>=5): {len(self.container_mutations)}\n"
                f"  - Mittlere Mutations (2-4): {len(self.medium_mutations)}\n"
                f"  - Kleine Mutations (1): {self.small_mutations_count}\n"
                f"  - Beobachtungsdauer: {self._observation_duration_ms:.0f}ms"
            )
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der DOM-Daten: {e}")
            # Setze Default-Werte statt None
            self.mutation_count = 0
            self.nodes_added = 0
            self.nodes_removed = 0
            self._observation_duration_ms = 0
    
    def analyze(self) -> DetectionResult:
        """Analysiert DOM-Mutationen"""
        try:
            total_node_changes = self.nodes_added + self.nodes_removed
            large_mutations = len(self.container_mutations) if self.container_mutations else 0
            medium_mutations = len(self.medium_mutations) if self.medium_mutations else 0
            
            mutation_rate = 0.0
            if self._observation_duration_ms and self._observation_duration_ms > 0:
                mutation_rate = (self.mutation_count / self._observation_duration_ms) * 1000
            
            detected = False
            confidence = 0.0
            reasons = []
            
            # Detection-Logik
            if total_node_changes >= 50:
                detected = True
                confidence = min(0.9, 0.5 + (total_node_changes - 50) / 1000)
                reasons.append(f"total_node_changes={total_node_changes}")
            elif total_node_changes >= 20:
                detected = True
                confidence = 0.4
                reasons.append(f"moderate_node_changes={total_node_changes}")
            
            if self.mutation_count >= 100:
                if not detected:
                    detected = True
                    confidence = 0.5
                else:
                    confidence = min(0.95, confidence + 0.1)
                reasons.append(f"high_mutation_count={self.mutation_count}")
            elif self.mutation_count >= 30:
                if not detected:
                    detected = True
                    confidence = 0.35
                else:
                    confidence = min(0.95, confidence + 0.05)
                reasons.append(f"moderate_mutation_count={self.mutation_count}")
            
            if large_mutations >= 3:
                if not detected:
                    detected = True
                    confidence = 0.6
                else:
                    confidence = min(0.95, confidence + 0.1)
                reasons.append(f"large_mutations={large_mutations}")
            
            if mutation_rate >= 10:
                if not detected:
                    detected = True
                    confidence = 0.5
                else:
                    confidence = min(0.95, confidence + 0.1)
                reasons.append(f"high_mutation_rate={mutation_rate:.1f}/s")
            
            # DOM-Wachstum
            initial_tags = 0
            final_tags = 0
            dom_growth_ratio = 1.0
            
            if self._initial_dom_metrics:
                initial_tags = self._initial_dom_metrics.get('tagCount', 0) or 0
            if self._final_dom_metrics:
                final_tags = self._final_dom_metrics.get('tagCount', 0) or 0
            
            if initial_tags > 0:
                dom_growth_ratio = final_tags / initial_tags
                if dom_growth_ratio >= 1.5:
                    if not detected:
                        detected = True
                        confidence = 0.4
                    else:
                        confidence = min(0.95, confidence + 0.1)
                    reasons.append(f"dom_growth={dom_growth_ratio:.2f}x")
            
            evidence = {
                'mutation_count': self.mutation_count,
                'nodes_added': self.nodes_added,
                'nodes_removed': self.nodes_removed,
                'total_node_changes': total_node_changes,
                'large_mutations': large_mutations,
                'medium_mutations': medium_mutations,
                'small_mutations': self.small_mutations_count,
                'observation_duration_ms': self._observation_duration_ms,
                'mutation_rate_per_sec': round(mutation_rate, 2),
                'initial_tag_count': initial_tags,
                'final_tag_count': final_tags,
                'dom_growth_ratio': round(dom_growth_ratio, 2),
                'detection_reasons': reasons
            }
            
            if detected:
                description = f"DOM-Rewriting erkannt: {', '.join(reasons)}. Gesamt: {self.mutation_count} Mutations, {total_node_changes} Node-Changes"
            else:
                description = f"Kein signifikantes DOM-Rewriting. Mutations: {self.mutation_count}, Node-Changes: {total_node_changes}"
            
            return DetectionResult(
                signal_name="DOM Rewriting Pattern",
                detected=detected,
                confidence=round(confidence, 2),
                evidence=evidence,
                description=description
            )
        
        except Exception as e:
            logger.error(f"Fehler bei DOM-Analyse: {e}")
            return DetectionResult(
                signal_name="DOM Rewriting Pattern",
                detected=False,
                confidence=0.0,
                evidence={'error': str(e)},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )