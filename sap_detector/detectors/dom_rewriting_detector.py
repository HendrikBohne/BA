"""
SPA Detection Tool - DOM Rewriting Detector (v2 - Improved)
Signal 3: Signifikantes DOM-Rewriting

Änderungen gegenüber v1:
- Observer direkt auf document.body (nicht auf spezifische Container)
- Keine harte Filterung mehr bei der Erfassung
- Niedrigere Schwellwerte für Detection
- Mutation-Rate pro Sekunde als zusätzliches Signal
- Bessere Auswertung von total_node_changes
"""
import logging
from typing import Optional, Dict
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


class DOMRewritingDetector:
    """
    Signal 3: Signifikantes DOM-Rewriting (v2 - verbessert)
    
    Kernänderungen:
    - Observer auf document.body mit subtree: true
    - ALLE Mutationen werden gezählt, nicht nur "signifikante"
    - Separate Buckets für kleine/mittlere/große Mutations
    - total_node_changes allein kann schon Detection triggern
    """
    
    def __init__(self, early_ms: int = 2000):
        # Mutation-Zähler
        self.mutation_count = 0
        self.nodes_added = 0
        self.nodes_removed = 0
        self.container_mutations = []  # Große Mutations (>=5 nodes)
        self.medium_mutations = []     # Mittlere Mutations (2-4 nodes)
        self.small_mutations_count = 0 # Kleine Mutations (1 node)
        self._observer_injected = False
        
        # Zeitachsen-Parameter
        self.early_ms = early_ms
        self._t0 = None
        self._events = []
        self._observation_duration_ms = 0
        
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
        """
        Injiziert MutationObserver + Zeitbaseline
        
        WICHTIG: Observer wird direkt auf document.body gesetzt,
        nicht auf spezifische Container wie #app oder #root.
        """
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
                        // Buckets nach Größe der Mutation
                        largeMutations: [],   // >= 5 nodes
                        mediumMutations: [],  // 2-4 nodes  
                        smallMutationsCount: 0, // 1 node
                        // Timestamps für Rate-Berechnung
                        firstMutationTime: null,
                        lastMutationTime: null,
                        // Initial-Metriken
                        initial: {
                            length: (document.documentElement.outerHTML || '').length,
                            tagCount: document.getElementsByTagName('*').length
                        }
                    };

                    // WICHTIG: Observer auf document.body, nicht auf spezifische Container!
                    // Das stellt sicher, dass wir ALLE DOM-Änderungen mitbekommen.
                    const targetNode = document.body || document.documentElement;
                    
                    const observer = new MutationObserver((mutations) => {
                        try {
                            const t = performance.now();
                            const dom = window.__spa_detection.dom;
                            
                            // Timestamps tracken
                            if (dom.firstMutationTime === null) {
                                dom.firstMutationTime = t;
                            }
                            dom.lastMutationTime = t;
                            
                            mutations.forEach(mutation => {
                                dom.mutationCount++;
                                
                                const added = mutation.addedNodes ? mutation.addedNodes.length : 0;
                                const removed = mutation.removedNodes ? mutation.removedNodes.length : 0;
                                const total = added + removed;
                                
                                dom.nodesAdded += added;
                                dom.nodesRemoved += removed;
                                
                                // In Buckets einsortieren (aber ALLE zählen!)
                                if (total >= 5) {
                                    // Große Mutation - Details speichern (max 50)
                                    if (dom.largeMutations.length < 50) {
                                        dom.largeMutations.push({
                                            added,
                                            removed,
                                            timestamp_perf: t,
                                            target: mutation.target?.nodeName || 'UNKNOWN',
                                            targetId: mutation.target?.id || null,
                                            targetClass: (mutation.target?.className || '').toString().slice(0, 50)
                                        });
                                    }
                                } else if (total >= 2) {
                                    // Mittlere Mutation - nur zählen (max 100 Details)
                                    if (dom.mediumMutations.length < 100) {
                                        dom.mediumMutations.push({
                                            added,
                                            removed,
                                            timestamp_perf: t
                                        });
                                    }
                                } else if (total >= 1) {
                                    // Kleine Mutation - nur Counter
                                    dom.smallMutationsCount++;
                                }
                            });
                        } catch (e) {
                            console.error('Mutation tracking error:', e);
                        }
                    });

                    // Observer mit allen relevanten Optionen starten
                    observer.observe(targetNode, {
                        childList: true,
                        subtree: true,
                        // Optional: auch Attribute und Text beobachten
                        // attributes: true,
                        // characterData: true
                    });

                    // Interaction-Marker
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
                    
                    console.log('[SPA-Detection] DOM observer active on:', targetNode.nodeName);
                }
            """)
            
            self._observer_injected = True
            logger.info("DOM-Observer injiziert (auf document.body)")
            
        except Exception as e:
            logger.error(f"Fehler beim Injizieren des DOM-Observers: {e}")
    
    async def collect_data(self, page):
        """Sammelt Mutations-Daten aus dem Browser"""
        try:
            data = await page.evaluate("""
                () => {
                    const dom = (window.__spa_detection && window.__spa_detection.dom) || null;
                    const t0 = (window.__spa_detection && window.__spa_detection.t0) || null;
                    const events = (window.__spa_detection && window.__spa_detection.events) || [];
                    const currentTime = performance.now();
                    
                    const finalMetrics = {
                        length: (document.documentElement.outerHTML || '').length,
                        tagCount: document.getElementsByTagName('*').length
                    };
                    
                    return { 
                        dom, 
                        t0, 
                        events, 
                        finalMetrics,
                        currentTime
                    };
                }
            """)
            
            dom = data.get('dom') or {}
            
            # Basis-Zähler
            self.mutation_count = int(dom.get('mutationCount', 0) or 0)
            self.nodes_added = int(dom.get('nodesAdded', 0) or 0)
            self.nodes_removed = int(dom.get('nodesRemoved', 0) or 0)
            
            # Mutation-Buckets
            self.container_mutations = dom.get('largeMutations', []) or []
            self.medium_mutations = dom.get('mediumMutations', []) or []
            self.small_mutations_count = int(dom.get('smallMutationsCount', 0) or 0)
            
            # Zeitdaten
            self._t0 = data.get('t0')
            self._events = data.get('events') or []
            current_time = data.get('currentTime', 0)
            
            if self._t0 and current_time:
                self._observation_duration_ms = current_time - self._t0
            
            # DOM-Metriken
            self._initial_dom_metrics = dom.get('initial') or {"length": 0, "tagCount": 0}
            self._final_dom_metrics = data.get('finalMetrics') or {"length": 0, "tagCount": 0}
            
            # Detailliertes Logging
            logger.info(
                f"DOM-Daten gesammelt:\n"
                f"  - Mutations gesamt: {self.mutation_count}\n"
                f"  - Nodes added: {self.nodes_added}, removed: {self.nodes_removed}\n"
                f"  - Große Mutations (>=5): {len(self.container_mutations)}\n"
                f"  - Mittlere Mutations (2-4): {len(self.medium_mutations)}\n"
                f"  - Kleine Mutations (1): {self.small_mutations_count}\n"
                f"  - Beobachtungsdauer: {self._observation_duration_ms:.0f}ms"
            )
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der DOM-Daten: {e}")
    
    def analyze(self) -> DetectionResult:
        """
        Analysiert DOM-Mutationen mit verbesserten Schwellwerten.
        
        Änderungen:
        - total_node_changes allein kann Detection triggern
        - Niedrigere Schwellwerte
        - Mutation-Rate als zusätzliches Signal
        """
        try:
            total_node_changes = self.nodes_added + self.nodes_removed
            large_mutations = len(self.container_mutations)
            medium_mutations = len(self.medium_mutations)
            all_significant = large_mutations + medium_mutations
            
            # Mutation-Rate berechnen (pro Sekunde)
            mutation_rate = 0.0
            if self._observation_duration_ms > 0:
                mutation_rate = (self.mutation_count / self._observation_duration_ms) * 1000
            
            # Zeitachsen-Auswertung: Early vs Late Mutations
            early_mutations = 0
            late_mutations = 0
            
            for m in self.container_mutations + self.medium_mutations:
                tperf = m.get('timestamp_perf')
                if not isinstance(tperf, (int, float)) or not isinstance(self._t0, (int, float)):
                    continue
                dt = tperf - self._t0
                if dt <= self.early_ms:
                    early_mutations += 1
                else:
                    late_mutations += 1
            
            # DOM-Wachstum berechnen
            initial_tags = self._initial_dom_metrics.get('tagCount', 0) if self._initial_dom_metrics else 0
            final_tags = self._final_dom_metrics.get('tagCount', 0) if self._final_dom_metrics else 0
            dom_growth_ratio = (final_tags / max(1, initial_tags)) if initial_tags > 0 else 1.0
            
            # Server-HTML vs. DOM Vergleich
            server_metrics = self._server_metrics or {"length": 0, "tag_count": 0}
            length_ratio = 0.0
            tag_ratio = 0.0
            big_divergence = False
            
            if server_metrics.get("length", 0) > 0:
                length_ratio = self._final_dom_metrics.get("length", 0) / max(1, server_metrics["length"])
                tag_ratio = self._final_dom_metrics.get("tagCount", 0) / max(1, server_metrics.get("tag_count", 1))
                big_divergence = (length_ratio >= 1.5) or (tag_ratio >= 1.5)
            
            # ============================================
            # NEUE DETECTION-LOGIK (viel niedrigere Schwellwerte)
            # ============================================
            detected = False
            confidence = 0.0
            reasons = []
            
            # Grund 1: Viele Node-Changes (Hauptindikator!)
            # Bei TikTok mit 262 changes sollte das definitiv triggern
            if total_node_changes >= 50:
                detected = True
                # Skaliert von 0.5 (bei 50) bis 0.9 (bei 500+)
                confidence = min(0.9, 0.5 + (total_node_changes - 50) / 1000)
                reasons.append(f"total_node_changes={total_node_changes}")
            elif total_node_changes >= 20:
                detected = True
                confidence = 0.4
                reasons.append(f"moderate_node_changes={total_node_changes}")
            
            # Grund 2: Anzahl der Mutations (auch ohne große Node-Changes)
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
            
            # Grund 3: Große Mutations (alte Logik, aber niedrigere Schwelle)
            if large_mutations >= 3:
                if not detected:
                    detected = True
                    confidence = 0.6
                else:
                    confidence = min(0.95, confidence + 0.1)
                reasons.append(f"large_mutations={large_mutations}")
            elif large_mutations >= 1:
                if not detected:
                    detected = True
                    confidence = 0.4
                else:
                    confidence = min(0.95, confidence + 0.05)
                reasons.append(f"has_large_mutation")
            
            # Grund 4: Hohe Mutation-Rate
            if mutation_rate >= 10:  # 10+ Mutations pro Sekunde
                if not detected:
                    detected = True
                    confidence = 0.5
                else:
                    confidence = min(0.95, confidence + 0.1)
                reasons.append(f"high_mutation_rate={mutation_rate:.1f}/s")
            
            # Grund 5: DOM-Wachstum
            if dom_growth_ratio >= 1.5:
                if not detected:
                    detected = True
                    confidence = 0.4
                else:
                    confidence = min(0.95, confidence + 0.1)
                reasons.append(f"dom_growth={dom_growth_ratio:.2f}x")
            
            # Boni für zusätzliche Signale
            if detected:
                # Bonus für Early Mutations (SPA initialisiert sich)
                if early_mutations >= 3:
                    confidence = min(0.95, confidence + 0.05)
                    reasons.append("early_activity")
                
                # Bonus für Server/DOM Divergenz
                if big_divergence:
                    confidence = min(0.95, confidence + 0.1)
                    reasons.append("server_dom_divergence")
                
                # Bonus für viele mittlere Mutations
                if medium_mutations >= 10:
                    confidence = min(0.95, confidence + 0.05)
                    reasons.append(f"medium_mutations={medium_mutations}")
            
            # Evidence zusammenstellen
            evidence = {
                # Basis-Zahlen
                'mutation_count': self.mutation_count,
                'nodes_added': self.nodes_added,
                'nodes_removed': self.nodes_removed,
                'total_node_changes': total_node_changes,
                
                # Mutation-Buckets
                'large_mutations': large_mutations,
                'medium_mutations': medium_mutations,
                'small_mutations': self.small_mutations_count,
                
                # Zeitanalyse
                'early_mutations': early_mutations,
                'late_mutations': late_mutations,
                'observation_duration_ms': self._observation_duration_ms,
                'mutation_rate_per_sec': round(mutation_rate, 2),
                
                # DOM-Metriken
                'initial_tag_count': initial_tags,
                'final_tag_count': final_tags,
                'dom_growth_ratio': round(dom_growth_ratio, 2),
                
                # Server-Vergleich
                'length_ratio': round(length_ratio, 2),
                'tag_ratio': round(tag_ratio, 2),
                'big_divergence': big_divergence,
                
                # Detection-Gründe
                'detection_reasons': reasons,
                
                # Sample-Daten
                'sample_large_mutations': self.container_mutations[:5],
                'sample_medium_mutations': self.medium_mutations[:5]
            }
            
            # Description
            if detected:
                description = (
                    f"DOM-Rewriting erkannt: {', '.join(reasons)}. "
                    f"Gesamt: {self.mutation_count} Mutations, {total_node_changes} Node-Changes"
                )
            else:
                description = (
                    f"Kein signifikantes DOM-Rewriting. "
                    f"Mutations: {self.mutation_count}, Node-Changes: {total_node_changes}"
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