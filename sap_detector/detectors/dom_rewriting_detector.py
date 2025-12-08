"""
SPA Detection Tool - DOM Rewriting Detector
Signal 3: Signifikantes DOM-Rewriting
"""
import logging
from typing import Optional, Dict
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


class DOMRewritingDetector:
    """
    Signal 3: Signifikantes DOM-Rewriting (erweitert)
    
    - Zählt Mutationen (added/removed Nodes), protokolliert signifikante Mutationen.
    - Zeitachsen-Auswertung
    - Optional: Vergleich Server-HTML vs. gerendertes DOM
    """
    
    def __init__(self, early_ms: int = 2000):
        # Mutation-Zähler
        self.mutation_count = 0
        self.nodes_added = 0
        self.nodes_removed = 0
        self.container_mutations = []
        self._observer_injected = False
        
        # Zeitachsen-Parameter
        self.early_ms = early_ms
        self._t0 = None
        self._events = []
        
        # Server-HTML (Rohzustand)
        self._server_html: Optional[str] = None
        self._server_metrics: Optional[Dict[str, int]] = None
        
        # DOM-Metriken
        self._initial_dom_metrics: Optional[Dict[str, int]] = None
        self._final_dom_metrics: Optional[Dict[str, int]] = None
    
    def record_server_html(self, html: str):
        """Optional: Server-HTML reinreichen"""
        self._server_html = html
        self._server_metrics = self._basic_dom_metrics(html)
    
    def _basic_dom_metrics(self, html: str) -> Dict[str, int]:
        """Grobe Metriken: Länge und Tag-Anzahl"""
        try:
            import re
            tags = re.findall(r"<([a-zA-Z0-9-]+)(\s|>)", html or "")
            return {"length": len(html or ""), "tag_count": len(tags)}
        except Exception:
            return {"length": 0, "tag_count": 0}
    
    async def inject_observer(self, page):
        """Injiziert MutationObserver + Zeitbaseline"""
        try:
            if self._observer_injected:
                return
            
            await page.evaluate("""
                () => {
                    if (window.__spa_detection_dom_injected) return;
                    window.__spa_detection_dom_injected = true;

                    window.__spa_detection = window.__spa_detection || {};
                    if (typeof window.__spa_detection.t0 !== 'number') {
                        window.__spa_detection.t0 = performance.now();
                    }
                    if (!Array.isArray(window.__spa_detection.events)) {
                        window.__spa_detection.events = [];
                    }

                    window.__spa_detection.dom = {
                        mutationCount: 0,
                        nodesAdded: 0,
                        nodesRemoved: 0,
                        containerMutations: [],
                        initial: {
                            length: (document.documentElement.outerHTML || '').length,
                            tagCount: document.getElementsByTagName('*').length
                        }
                    };

                    const containers = [
                        document.querySelector('#app'),
                        document.querySelector('#root'),
                        document.querySelector('[id*="app"]'),
                        document.querySelector('[id*="root"]'),
                        document.querySelector('main'),
                        document.querySelector('[role="main"]'),
                        document.querySelector('[data-reactroot]'),
                        document.querySelector('[data-react-app]'),
                        document.querySelector('.app'),
                        document.querySelector('.container'),
                        document.body
                    ].filter(Boolean);
                    const targetContainer = containers[0] || document.body;

                    const observer = new MutationObserver((mutations) => {
                        try {
                            const t = performance.now();
                            mutations.forEach(mutation => {
                                window.__spa_detection.dom.mutationCount++;
                                const added = mutation.addedNodes ? mutation.addedNodes.length : 0;
                                const removed = mutation.removedNodes ? mutation.removedNodes.length : 0;
                                window.__spa_detection.dom.nodesAdded += added;
                                window.__spa_detection.dom.nodesRemoved += removed;

                                if ((added + removed) >= 5) {
                                    window.__spa_detection.dom.containerMutations.push({
                                        added,
                                        removed,
                                        timestamp_ms: Date.now(),
                                        timestamp_perf: t,
                                        target: mutation.target && mutation.target.nodeName || 'UNKNOWN'
                                    });
                                }
                            });
                        } catch (e) {
                            console.error('Mutation tracking error:', e);
                        }
                    });

                    observer.observe(targetContainer, {
                        childList: true,
                        subtree: true
                    });

                    if (!window.__spa_detection.__markInteraction) {
                        window.__spa_detection.__markInteraction = (type, label) => {
                            try {
                                window.__spa_detection.events.push({
                                    type: type || 'interaction',
                                    label: (label || '').toString().slice(0, 80),
                                    t: performance.now()
                                });
                            } catch(e) {}
                        };
                    }
                    console.log('SPA Detection: DOM observer active on', targetContainer.nodeName);
                }
            """)
            
            self._observer_injected = True
            logger.info("DOM-Observer injiziert")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des DOM-Observers: {e}")
    
    async def collect_data(self, page):
        """Sammelt Mutations-Daten"""
        try:
            data = await page.evaluate("""
                () => {
                    const d = (window.__spa_detection && window.__spa_detection.dom) || null;
                    const t0 = (window.__spa_detection && window.__spa_detection.t0) || null;
                    const events = (window.__spa_detection && window.__spa_detection.events) || [];
                    const finalMetrics = {
                        length: (document.documentElement.outerHTML || '').length,
                        tagCount: document.getElementsByTagName('*').length
                    };
                    return { d, t0, events, finalMetrics };
                }
            """)
            
            dom = data.get('d') or {}
            self.mutation_count = int(dom.get('mutationCount', 0) or 0)
            self.nodes_added = int(dom.get('nodesAdded', 0) or 0)
            self.nodes_removed = int(dom.get('nodesRemoved', 0) or 0)
            self.container_mutations = dom.get('containerMutations', []) or []
            
            self._t0 = data.get('t0')
            self._events = data.get('events') or []
            self._initial_dom_metrics = (dom.get('initial') or {"length": 0, "tagCount": 0})
            self._final_dom_metrics = data.get('finalMetrics') or {"length": 0, "tagCount": 0}
            
            logger.info(
                f"DOM-Daten: {self.mutation_count} Mutations, "
                f"{self.nodes_added} added, {self.nodes_removed} removed"
            )
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der DOM-Daten: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert DOM-Mutationen"""
        try:
            significant_mutations = len(self.container_mutations)
            total_node_changes = self.nodes_added + self.nodes_removed
            
            # Zeitachsen-Auswertung
            early_mut = 0
            after_mut = 0
            first_event_t = None
            if self._events:
                try:
                    first_event_t = min([e.get('t', None) for e in self._events if isinstance(e.get('t', None), (int, float))] or [None])
                except Exception:
                    first_event_t = None
            
            for m in self.container_mutations:
                tperf = m.get('timestamp_perf', None)
                if not isinstance(tperf, (int, float)) or not isinstance(self._t0, (int, float)):
                    continue
                dt = tperf - self._t0
                if dt <= self.early_ms:
                    early_mut += 1
                if first_event_t is not None and tperf >= first_event_t:
                    after_mut += 1
            
            # Server-HTML vs. DOM Vergleich
            server_metrics = self._server_metrics or {"length": 0, "tag_count": 0}
            final_metrics = self._final_dom_metrics or {"length": 0, "tagCount": 0}
            
            length_ratio = 0.0
            tag_ratio = 0.0
            big_divergence = False
            minimal_shell = False
            
            if server_metrics["length"] > 0 and server_metrics["tag_count"] > 0:
                length_ratio = (final_metrics.get("length", 0) / max(1, server_metrics["length"]))
                tag_ratio = (final_metrics.get("tagCount", 0) / max(1, server_metrics["tag_count"]))
                big_divergence = (length_ratio >= 2.0) or (tag_ratio >= 2.0)
                minimal_shell = (server_metrics["tag_count"] < 150) or (server_metrics["length"] < 30_000)
            
            # Basis-Heuristik
            detected = False
            confidence = 0.0
            
            if significant_mutations >= 5 and total_node_changes >= 100:
                detected = True
                confidence = min(0.95, 0.6 + (significant_mutations / 20.0))
            elif significant_mutations >= 3 and total_node_changes >= 50:
                detected = True
                confidence = 0.7
            elif significant_mutations >= 2 and total_node_changes >= 30:
                detected = True
                confidence = 0.5
            
            # Boni
            if detected:
                if early_mut >= 2:
                    confidence = min(0.95, confidence + 0.05)
                if after_mut >= 2:
                    confidence = min(0.95, confidence + 0.05)
                if big_divergence and minimal_shell:
                    confidence = min(0.95, confidence + 0.1)
            
            evidence = {
                'mutation_count': self.mutation_count,
                'nodes_added': self.nodes_added,
                'nodes_removed': self.nodes_removed,
                'total_node_changes': total_node_changes,
                'significant_mutations': significant_mutations,
                'early_mutations': early_mut,
                'post_interaction_mutations': after_mut,
                'length_ratio': float(length_ratio),
                'tag_ratio': float(tag_ratio),
                'big_divergence': bool(big_divergence),
                'minimal_shell': bool(minimal_shell),
                'sample_mutations': self.container_mutations[:5]
            }
            
            description = (
                f"Signifikante Mutations: {significant_mutations}, "
                f"Node-Changes: {total_node_changes}, "
                f"early: {early_mut}, after_interact: {after_mut}"
            )
            
            return DetectionResult(
                signal_name="DOM Rewriting Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=description
            )
        
        except Exception as e:
            logger.error(f"Fehler bei DOM-Analyse: {e}")
            return DetectionResult(
                signal_name="DOM Rewriting Pattern",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )