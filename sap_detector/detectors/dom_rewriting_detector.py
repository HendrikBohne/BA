"""
SPA Detection Tool - DOM Rewriting Detector (v4 - mit Baseline/Post-Click)
Signal 3: Signifikantes DOM-Rewriting

ÄNDERUNGEN v4:
- Trennung von Baseline (Initial Load) und Post-Click Mutations
- Nur Post-Click Delta zählt als SPA-Signal
- Filterung von Consent/Ads/Overlay Mutations
"""
import logging
from typing import Optional, Dict, List
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


# JavaScript Code mit Baseline/Post-Click Trennung
DOM_OBSERVER_SCRIPT = """
(() => {
    if (window.__spa_detection_dom_injecting) return;
    window.__spa_detection_dom_injecting = true;
    window.__spa_detection_dom_injected = true;

    window.__spa_detection = window.__spa_detection || {};
    
    if (typeof window.__spa_detection.t0 !== 'number') {
        window.__spa_detection.t0 = performance.now();
    }
    
    // IGNORIERTE Container (Consent, Ads, Overlays, etc.)
    const IGNORED_PATTERNS = [
        'cookie', 'consent', 'banner', 'gdpr', 'privacy',
        'overlay', 'modal', 'popup', 'dialog',
        'ad-', 'ads-', 'advert', 'sponsor',
        'tracking', 'analytics', 'gtm-',
        'sticky', 'fixed-', 'toast', 'notification',
        'recaptcha', 'captcha'
    ];
    
    const shouldIgnoreMutation = (target) => {
        if (!target || !target.nodeType) return true;
        if (target.nodeType !== 1) return false; // Nur Element-Nodes prüfen
        
        const tagName = (target.tagName || '').toLowerCase();
        
        // Ignoriere script, style, iframe
        if (['script', 'style', 'iframe', 'noscript', 'link'].includes(tagName)) {
            return true;
        }
        
        // Prüfe ID und Klassen
        const id = (target.id || '').toLowerCase();
        const className = (target.className || '').toString().toLowerCase();
        
        for (const pattern of IGNORED_PATTERNS) {
            if (id.includes(pattern) || className.includes(pattern)) {
                return true;
            }
        }
        
        // Prüfe auch Parent-Elemente (bis zu 3 Level hoch)
        let parent = target.parentElement;
        for (let i = 0; i < 3 && parent; i++) {
            const parentId = (parent.id || '').toLowerCase();
            const parentClass = (parent.className || '').toString().toLowerCase();
            
            for (const pattern of IGNORED_PATTERNS) {
                if (parentId.includes(pattern) || parentClass.includes(pattern)) {
                    return true;
                }
            }
            parent = parent.parentElement;
        }
        
        return false;
    };
    
    const existingDom = window.__spa_detection.dom || {};
    const injectionCount = (existingDom.injectionCount || 0) + 1;
    
    window.__spa_detection.dom = {
        // BASELINE: Mutations während Initial Load (erste 3 Sekunden)
        baseline: {
            mutationCount: existingDom.baseline?.mutationCount || 0,
            nodesAdded: existingDom.baseline?.nodesAdded || 0,
            nodesRemoved: existingDom.baseline?.nodesRemoved || 0,
            phase: 'collecting'  // 'collecting' | 'done'
        },
        
        // POST-CLICK: Mutations nach Interaktionen
        postClick: {
            mutationCount: existingDom.postClick?.mutationCount || 0,
            nodesAdded: existingDom.postClick?.nodesAdded || 0,
            nodesRemoved: existingDom.postClick?.nodesRemoved || 0,
            windows: existingDom.postClick?.windows || []  // Jedes Click-Window separat
        },
        
        // Aktuelles Fenster
        currentWindow: null,
        windowStartTime: null,
        
        // Gesamtzahlen (für Kompatibilität)
        mutationCount: existingDom.mutationCount || 0,
        nodesAdded: existingDom.nodesAdded || 0,
        nodesRemoved: existingDom.nodesRemoved || 0,
        largeMutations: existingDom.largeMutations || [],
        
        // Meta
        observerActive: false,
        injectionCount: injectionCount,
        baselineEndTime: null,
        initial: existingDom.initial || { length: 0, tagCount: 0 }
    };

    // Baseline endet nach 3 Sekunden
    const BASELINE_DURATION_MS = 3000;
    const baselineStartTime = performance.now();
    
    setTimeout(() => {
        if (window.__spa_detection && window.__spa_detection.dom) {
            window.__spa_detection.dom.baseline.phase = 'done';
            window.__spa_detection.dom.baselineEndTime = performance.now();
            console.log('[SPA-Detection] Baseline abgeschlossen:', window.__spa_detection.dom.baseline);
        }
    }, BASELINE_DURATION_MS);

    const startObserver = () => {
        const dom = window.__spa_detection.dom;
        const targetNode = document.body || document.documentElement;
        
        if (!targetNode || dom.observerActive) return;
        
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
                    
                    let validMutations = 0;
                    let addedNodes = 0;
                    let removedNodes = 0;
                    
                    mutations.forEach(mutation => {
                        // FILTERUNG: Ignoriere Consent/Ads/etc.
                        if (shouldIgnoreMutation(mutation.target)) {
                            return;
                        }
                        
                        const added = mutation.addedNodes ? mutation.addedNodes.length : 0;
                        const removed = mutation.removedNodes ? mutation.removedNodes.length : 0;
                        
                        validMutations++;
                        addedNodes += added;
                        removedNodes += removed;
                        
                        // Große Mutations für Evidence speichern
                        const total = added + removed;
                        if (total >= 5 && d.largeMutations.length < 30) {
                            d.largeMutations.push({
                                added, removed,
                                timestamp_perf: t,
                                target: mutation.target?.nodeName || 'UNKNOWN',
                                targetId: mutation.target?.id || null,
                                phase: d.baseline.phase === 'collecting' ? 'baseline' : 'post-click'
                            });
                        }
                    });
                    
                    if (validMutations === 0) return;
                    
                    // Gesamtzahlen aktualisieren
                    d.mutationCount += validMutations;
                    d.nodesAdded += addedNodes;
                    d.nodesRemoved += removedNodes;
                    
                    // In richtige Kategorie einsortieren
                    if (d.baseline.phase === 'collecting') {
                        // BASELINE Phase
                        d.baseline.mutationCount += validMutations;
                        d.baseline.nodesAdded += addedNodes;
                        d.baseline.nodesRemoved += removedNodes;
                    } else if (d.currentWindow) {
                        // POST-CLICK Phase (aktives Fenster)
                        d.currentWindow.mutationCount += validMutations;
                        d.currentWindow.nodesAdded += addedNodes;
                        d.currentWindow.nodesRemoved += removedNodes;
                        
                        // Auch in Gesamt-PostClick
                        d.postClick.mutationCount += validMutations;
                        d.postClick.nodesAdded += addedNodes;
                        d.postClick.nodesRemoved += removedNodes;
                    }
                    
                } catch (e) {
                    console.error('[SPA-Detection] Mutation error:', e);
                }
            });

            observer.observe(targetNode, {
                childList: true,
                subtree: true
            });
            
            dom.observerActive = true;
            console.log('[SPA-Detection] DOM Observer aktiv (v4 - Baseline/PostClick)');
            
        } catch (e) {
            console.error('[SPA-Detection] Observer start failed:', e);
        }
    };

    // Methode um Click-Window zu starten (wird vom Analyzer aufgerufen)
    window.__spa_detection.startClickWindow = (label) => {
        const dom = window.__spa_detection.dom;
        const t = performance.now();
        
        // Schließe vorheriges Fenster
        if (dom.currentWindow) {
            dom.currentWindow.endTime = t;
            dom.currentWindow.duration = t - dom.currentWindow.startTime;
            dom.postClick.windows.push(dom.currentWindow);
        }
        
        // Neues Fenster öffnen
        dom.currentWindow = {
            label: label || 'click',
            startTime: t,
            mutationCount: 0,
            nodesAdded: 0,
            nodesRemoved: 0
        };
        
        console.log('[SPA-Detection] Click-Window gestartet:', label);
    };
    
    // Methode um Click-Window zu beenden
    window.__spa_detection.endClickWindow = () => {
        const dom = window.__spa_detection.dom;
        const t = performance.now();
        
        if (dom.currentWindow) {
            dom.currentWindow.endTime = t;
            dom.currentWindow.duration = t - dom.currentWindow.startTime;
            dom.postClick.windows.push(dom.currentWindow);
            
            console.log('[SPA-Detection] Click-Window beendet:', dom.currentWindow);
            dom.currentWindow = null;
        }
    };

    // Starte Observer
    if (document.body) {
        startObserver();
    } else {
        document.addEventListener('DOMContentLoaded', startObserver);
    }
    window.addEventListener('load', () => {
        if (!window.__spa_detection.dom.observerActive) startObserver();
    });
    
    setTimeout(() => { window.__spa_detection_dom_injecting = false; }, 100);
})();
"""


class DOMRewritingDetector:
    """Signal 3: Signifikantes DOM-Rewriting (v4 - Baseline/Post-Click)"""
    
    def __init__(self, early_ms: int = 2000):
        self.mutation_count = 0
        self.nodes_added = 0
        self.nodes_removed = 0
        
        # NEU: Baseline vs. Post-Click
        self.baseline_mutations = 0
        self.baseline_nodes = 0
        self.postclick_mutations = 0
        self.postclick_nodes = 0
        self.click_windows = []
        
        self.container_mutations = []
        self._init_script_added = False
        
        self.early_ms = early_ms
        self._t0 = None
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
        """Injiziert MutationObserver mit Baseline/Post-Click Tracking"""
        try:
            if not self._init_script_added:
                await page.context.add_init_script(DOM_OBSERVER_SCRIPT)
                self._init_script_added = True
                logger.info("DOM-Observer als InitScript registriert (v4)")
            
            try:
                await page.evaluate(DOM_OBSERVER_SCRIPT)
            except Exception as e:
                logger.debug(f"Direkte DOM-Injection: {e}")
            
            await page.wait_for_timeout(200)
            logger.info("DOM-Observer injiziert (Baseline/Post-Click Tracking)")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des DOM-Observers: {e}")
    
    async def start_click_window(self, page, label: str = "click"):
        """Startet ein neues Click-Measurement-Window"""
        try:
            await page.evaluate(f"window.__spa_detection?.startClickWindow('{label}')")
        except Exception as e:
            logger.debug(f"Click-Window Start fehlgeschlagen: {e}")
    
    async def end_click_window(self, page):
        """Beendet das aktuelle Click-Measurement-Window"""
        try:
            await page.evaluate("window.__spa_detection?.endClickWindow()")
        except Exception as e:
            logger.debug(f"Click-Window End fehlgeschlagen: {e}")
    
    async def collect_data(self, page):
        """Sammelt Mutations-Daten mit Baseline/Post-Click Trennung"""
        try:
            data = await page.evaluate("""
                () => {
                    const dom = (window.__spa_detection && window.__spa_detection.dom) || null;
                    const t0 = (window.__spa_detection && window.__spa_detection.t0) || null;
                    const currentTime = performance.now();
                    
                    if (!dom) {
                        return {
                            dom: {
                                mutationCount: 0, nodesAdded: 0, nodesRemoved: 0,
                                baseline: { mutationCount: 0, nodesAdded: 0, nodesRemoved: 0, phase: 'done' },
                                postClick: { mutationCount: 0, nodesAdded: 0, nodesRemoved: 0, windows: [] },
                                largeMutations: [],
                                observerActive: false,
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
                    
                    // Schließe aktuelles Window falls offen
                    if (dom.currentWindow) {
                        dom.currentWindow.endTime = currentTime;
                        dom.currentWindow.duration = currentTime - dom.currentWindow.startTime;
                        dom.postClick.windows.push(dom.currentWindow);
                        dom.currentWindow = null;
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
            baseline = dom.get('baseline') or {}
            postclick = dom.get('postClick') or {}
            
            # Gesamt
            self.mutation_count = int(dom.get('mutationCount', 0) or 0)
            self.nodes_added = int(dom.get('nodesAdded', 0) or 0)
            self.nodes_removed = int(dom.get('nodesRemoved', 0) or 0)
            
            # Baseline
            self.baseline_mutations = int(baseline.get('mutationCount', 0) or 0)
            self.baseline_nodes = int(baseline.get('nodesAdded', 0) or 0) + int(baseline.get('nodesRemoved', 0) or 0)
            
            # Post-Click
            self.postclick_mutations = int(postclick.get('mutationCount', 0) or 0)
            self.postclick_nodes = int(postclick.get('nodesAdded', 0) or 0) + int(postclick.get('nodesRemoved', 0) or 0)
            self.click_windows = postclick.get('windows') or []
            
            self.container_mutations = dom.get('largeMutations', []) or []
            
            self._t0 = data.get('t0')
            current_time = data.get('currentTime', 0)
            if self._t0 and current_time:
                self._observation_duration_ms = current_time - self._t0
            
            self._initial_dom_metrics = dom.get('initial') or {"length": 0, "tagCount": 0}
            self._final_dom_metrics = data.get('finalMetrics') or {"length": 0, "tagCount": 0}
            
            observer_active = dom.get('observerActive', False)
            
            logger.info(
                f"DOM-Daten gesammelt (Observer: {observer_active}):\n"
                f"  📊 BASELINE: {self.baseline_mutations} Mutations, {self.baseline_nodes} Node-Changes\n"
                f"  🎯 POST-CLICK: {self.postclick_mutations} Mutations, {self.postclick_nodes} Node-Changes\n"
                f"  📈 GESAMT: {self.mutation_count} Mutations, {self.nodes_added + self.nodes_removed} Node-Changes\n"
                f"  🪟 Click-Windows: {len(self.click_windows)}"
            )
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der DOM-Daten: {e}")
            self.mutation_count = 0
            self.nodes_added = 0
            self.nodes_removed = 0
            self.baseline_mutations = 0
            self.postclick_mutations = 0
    
    def analyze(self) -> DetectionResult:
        """
        Analysiert DOM-Mutationen mit Fokus auf POST-CLICK Aktivität.
        
        WICHTIG: Nur Post-Click Mutations zählen als starkes SPA-Signal!
        Baseline-Mutations (Initial Load) werden weniger gewichtet.
        """
        try:
            total_node_changes = self.nodes_added + self.nodes_removed
            
            # WICHTIG: Post-Click ist das eigentliche SPA-Signal!
            postclick_significant = self.postclick_mutations >= 10 or self.postclick_nodes >= 20
            
            detected = False
            confidence = 0.0
            reasons = []
            
            # ============================================
            # NEUE LOGIK: Post-Click ist das Haupt-Signal
            # ============================================
            
            # Starkes Signal: Viele Post-Click Mutations
            if self.postclick_mutations >= 30 or self.postclick_nodes >= 50:
                detected = True
                confidence = 0.85
                reasons.append(f"high_postclick={self.postclick_mutations}mut/{self.postclick_nodes}nodes")
            
            elif self.postclick_mutations >= 15 or self.postclick_nodes >= 30:
                detected = True
                confidence = 0.70
                reasons.append(f"moderate_postclick={self.postclick_mutations}mut/{self.postclick_nodes}nodes")
            
            elif self.postclick_mutations >= 5 or self.postclick_nodes >= 10:
                detected = True
                confidence = 0.50
                reasons.append(f"some_postclick={self.postclick_mutations}mut/{self.postclick_nodes}nodes")
            
            # Schwaches Signal: Nur Baseline-Aktivität (typisch für dynamische MPAs!)
            elif self.baseline_mutations >= 50 and self.postclick_mutations < 5:
                # Viel Baseline aber wenig Post-Click → wahrscheinlich MPA mit Ads/Consent
                detected = False
                confidence = 0.0
                reasons.append(f"only_baseline={self.baseline_mutations}mut")
            
            elif self.mutation_count >= 30 and self.postclick_mutations < 5:
                # Dynamische Seite aber keine SPA-Navigation
                detected = False
                confidence = 0.0
                reasons.append("dynamic_but_no_spa_navigation")
            
            # DOM-Wachstum als unterstützendes Signal
            initial_tags = self._initial_dom_metrics.get('tagCount', 0) if self._initial_dom_metrics else 0
            final_tags = self._final_dom_metrics.get('tagCount', 0) if self._final_dom_metrics else 0
            dom_growth_ratio = (final_tags / max(1, initial_tags)) if initial_tags > 0 else 1.0
            
            if detected and dom_growth_ratio >= 1.5:
                confidence = min(0.95, confidence + 0.1)
                reasons.append(f"dom_growth={dom_growth_ratio:.1f}x")
            
            # Click-Windows als Bonus
            if detected and len(self.click_windows) >= 3:
                confidence = min(0.95, confidence + 0.05)
                reasons.append(f"click_windows={len(self.click_windows)}")
            
            evidence = {
                # Baseline vs. Post-Click (NEU!)
                'baseline_mutations': self.baseline_mutations,
                'baseline_nodes': self.baseline_nodes,
                'postclick_mutations': self.postclick_mutations,
                'postclick_nodes': self.postclick_nodes,
                'click_windows': len(self.click_windows),
                
                # Gesamt
                'mutation_count': self.mutation_count,
                'nodes_added': self.nodes_added,
                'nodes_removed': self.nodes_removed,
                'total_node_changes': total_node_changes,
                
                # DOM-Metriken
                'initial_tag_count': initial_tags,
                'final_tag_count': final_tags,
                'dom_growth_ratio': round(dom_growth_ratio, 2),
                
                # Meta
                'observation_duration_ms': self._observation_duration_ms,
                'detection_reasons': reasons,
                'sample_mutations': self.container_mutations[:5]
            }
            
            if detected:
                description = (
                    f"DOM-Rewriting erkannt (Post-Click): {self.postclick_mutations} Mutations, "
                    f"{self.postclick_nodes} Node-Changes. Baseline: {self.baseline_mutations} Mutations."
                )
            else:
                description = (
                    f"Kein SPA-typisches DOM-Rewriting. Post-Click: {self.postclick_mutations} Mutations. "
                    f"Baseline: {self.baseline_mutations} Mutations."
                )
            
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
