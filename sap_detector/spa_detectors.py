"""
SPA Detection Tool - Detector Module (Production Version)
Robuste Detektoren mit Fehlerbehandlung für beliebige Websites
"""
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Ergebnis eines einzelnen Detektors"""
    signal_name: str
    detected: bool
    confidence: float  # 0.0 - 1.0
    evidence: Dict[str, Any]
    description: str
    error: Optional[str] = None


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


class NetworkActivityDetector:
    """Signal 2: XHR/Fetch statt Dokument-Navigations"""
    
    def __init__(self):
        self.xhr_requests = []
        self.fetch_requests = []
        self.document_requests = []
        self.json_responses = 0
        self._listeners_setup = False
        
    async def setup_listeners(self, page):
        """Richtet Request-Listener ein"""
        try:
            if self._listeners_setup:
                return
            
            page.on("request", self._on_request)
            page.on("response", self._on_response)
            self._listeners_setup = True
            logger.info("Network-Listener eingerichtet")
            
        except Exception as e:
            logger.error(f"Fehler beim Setup der Network-Listener: {e}")
    
    def _on_request(self, request):
        try:
            resource_type = request.resource_type
            timestamp = asyncio.get_event_loop().time()
            
            request_data = {
                'url': request.url,
                'method': request.method,
                'timestamp': timestamp
            }
            
            if resource_type == "xhr":
                self.xhr_requests.append(request_data)
            elif resource_type == "fetch":
                self.fetch_requests.append(request_data)
            elif resource_type == "document":
                self.document_requests.append(request_data)
                
        except Exception as e:
            logger.error(f"Request-Tracking Fehler: {e}")
    
    def _on_response(self, response):
        try:
            # Zähle JSON-Responses
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' in content_type or 'application/ld+json' in content_type:
                self.json_responses += 1
        except Exception as e:
            logger.error(f"Response-Tracking Fehler: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert Netzwerkaktivität"""
        try:
            api_requests = len(self.xhr_requests) + len(self.fetch_requests)
            doc_requests = len(self.document_requests)
            
            detected = False
            confidence = 0.0
            
            # Starkes Signal: Viele API-Calls, wenige Documents
            if api_requests >= 5 and doc_requests <= 2:
                detected = True
                ratio = api_requests / max(1, doc_requests)
                confidence = min(0.95, 0.5 + (ratio / 20.0))
            # Mittleres Signal
            elif api_requests >= 3 and doc_requests <= 2:
                detected = True
                confidence = 0.7
            # Schwaches Signal
            elif api_requests >= 2 and doc_requests == 1:
                detected = True
                confidence = 0.5
            
            # Bonus für viele JSON-Responses
            if detected and self.json_responses >= 3:
                confidence = min(0.95, confidence + 0.1)
            
            evidence = {
                'xhr_count': len(self.xhr_requests),
                'fetch_count': len(self.fetch_requests),
                'total_api_requests': api_requests,
                'document_requests': doc_requests,
                'json_responses': self.json_responses,
                'ratio': api_requests / max(1, doc_requests),
                'sample_api_calls': (self.xhr_requests + self.fetch_requests)[:5]
            }
            
            return DetectionResult(
                signal_name="Network Activity Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"API-Requests: {api_requests}, Document-Requests: {doc_requests}, JSON: {self.json_responses}"
            )
            
        except Exception as e:
            logger.error(f"Fehler bei Network-Analyse: {e}")
            return DetectionResult(
                signal_name="Network Activity Pattern",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )


class DOMRewritingDetector:
    """Signal 3: Signifikantes DOM-Rewriting"""
    
    def __init__(self):
        self.mutation_count = 0
        self.nodes_added = 0
        self.nodes_removed = 0
        self.container_mutations = []
        self._observer_injected = False
        
    async def inject_observer(self, page):
        """Injiziert MutationObserver"""
        try:
            if self._observer_injected:
                return
            
            await page.evaluate("""
                () => {
                    if (window.__spa_detection_dom_injected) return;
                    window.__spa_detection_dom_injected = true;
                    
                    window.__spa_detection = window.__spa_detection || {};
                    window.__spa_detection.dom = {
                        mutationCount: 0,
                        nodesAdded: 0,
                        nodesRemoved: 0,
                        containerMutations: []
                    };
                    
                    try {
                        // Finde Haupt-Container (robuster)
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
                                mutations.forEach(mutation => {
                                    window.__spa_detection.dom.mutationCount++;
                                    
                                    const added = mutation.addedNodes.length;
                                    const removed = mutation.removedNodes.length;
                                    
                                    window.__spa_detection.dom.nodesAdded += added;
                                    window.__spa_detection.dom.nodesRemoved += removed;
                                    
                                    // Signifikante Mutation
                                    if (added + removed >= 5) {
                                        window.__spa_detection.dom.containerMutations.push({
                                            added: added,
                                            removed: removed,
                                            timestamp: Date.now(),
                                            target: mutation.target.nodeName
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
                        
                        console.log('SPA Detection: DOM observer active on', targetContainer.nodeName);
                    } catch (e) {
                        console.error('SPA Detection: DOM observer failed:', e);
                    }
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
                    if (!window.__spa_detection || !window.__spa_detection.dom) {
                        return {
                            mutationCount: 0,
                            nodesAdded: 0,
                            nodesRemoved: 0,
                            containerMutations: []
                        };
                    }
                    return window.__spa_detection.dom;
                }
            """)
            
            self.mutation_count = data.get('mutationCount', 0)
            self.nodes_added = data.get('nodesAdded', 0)
            self.nodes_removed = data.get('nodesRemoved', 0)
            self.container_mutations = data.get('containerMutations', [])
            
            logger.info(f"DOM-Daten: {self.mutation_count} Mutations, "
                       f"{self.nodes_added} added, {self.nodes_removed} removed")
            
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der DOM-Daten: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert DOM-Mutations"""
        try:
            significant_mutations = len(self.container_mutations)
            total_node_changes = self.nodes_added + self.nodes_removed
            
            detected = False
            confidence = 0.0
            
            # Starkes Signal: Viele signifikante Mutations
            if significant_mutations >= 5 and total_node_changes >= 100:
                detected = True
                confidence = min(0.95, 0.6 + (significant_mutations / 20.0))
            # Mittleres Signal
            elif significant_mutations >= 3 and total_node_changes >= 50:
                detected = True
                confidence = 0.7
            # Schwaches Signal
            elif significant_mutations >= 2 and total_node_changes >= 30:
                detected = True
                confidence = 0.5
            
            evidence = {
                'mutation_count': self.mutation_count,
                'nodes_added': self.nodes_added,
                'nodes_removed': self.nodes_removed,
                'total_node_changes': total_node_changes,
                'significant_mutations': significant_mutations,
                'sample_mutations': self.container_mutations[:5]
            }
            
            return DetectionResult(
                signal_name="DOM Rewriting Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"Signifikante Mutations: {significant_mutations}, Node-Changes: {total_node_changes}"
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


class ClickableElementDetector:
    """Signal 5: Klickbare Elemente ohne echtes href"""
    
    async def scan_dom(self, page) -> DetectionResult:
        """Scannt das DOM nach Clickable-Patterns"""
        try:
            data = await page.evaluate("""
                () => {
                    try {
                        // Echte Links (aber nicht Anker-Links)
                        const realLinks = document.querySelectorAll(
                            'a[href]:not([href^="#"]):not([href^="javascript:"]):not([href=""])'
                        );
                        const realLinkCount = realLinks.length;
                        
                        // Fake Clickables
                        const clickables = document.querySelectorAll(
                            'div[onclick], span[onclick], button:not([type="submit"]), ' +
                            '[role="button"], [role="link"]'
                        );
                        const fakeClickableCount = clickables.length;
                        
                        // Cursor Pointer Elemente
                        const withCursor = document.querySelectorAll(
                            '[style*="cursor: pointer"], [style*="cursor:pointer"], ' +
                            '.clickable, .pointer, .click'
                        );
                        const cursorPointerCount = withCursor.length;
                        
                        // Router-Links (Framework-spezifisch)
                        const routerLinks = document.querySelectorAll(
                            '[routerlink], [to], [data-route], [href^="/"], ' +
                            '.router-link, .nav-link, [class*="link"]'
                        );
                        const routerLinkCount = routerLinks.length;
                        
                        // Framework-Hinweise
                        const hasReact = !!document.querySelector('[data-reactroot], [data-react-app]');
                        const hasVue = !!document.querySelector('[data-v-], #app.__vue__');
                        const hasAngular = !!document.querySelector('[ng-version], [ng-app]');
                        
                        return {
                            realLinks: realLinkCount,
                            fakeClickables: fakeClickableCount,
                            cursorPointers: cursorPointerCount,
                            routerLinks: routerLinkCount,
                            total: document.querySelectorAll('*').length,
                            hasReact,
                            hasVue,
                            hasAngular
                        };
                    } catch (e) {
                        console.error('DOM scan error:', e);
                        return {
                            realLinks: 0,
                            fakeClickables: 0,
                            cursorPointers: 0,
                            routerLinks: 0,
                            total: 0,
                            hasReact: false,
                            hasVue: false,
                            hasAngular: false
                        };
                    }
                }
            """)
            
            fake_total = data['fakeClickables'] + data['routerLinks']
            real_total = data['realLinks']
            
            detected = False
            confidence = 0.0
            
            # Framework erkannt = starker Hinweis
            framework_detected = data['hasReact'] or data['hasVue'] or data['hasAngular']
            
            # Starkes Signal: Viele Router-Links
            if data['routerLinks'] >= 5:
                detected = True
                confidence = 0.8
            # Mittleres Signal: Viele Fake-Clickables
            elif fake_total >= 10 and real_total > 0:
                ratio = fake_total / real_total
                if ratio >= 0.5:
                    detected = True
                    confidence = min(0.85, 0.5 + (ratio / 4.0))
            # Schwaches Signal
            elif fake_total >= 5:
                detected = True
                confidence = 0.4
            
            # Bonus für Framework-Detection
            if detected and framework_detected:
                confidence = min(0.95, confidence + 0.1)
            
            evidence = {
                'real_links': real_total,
                'fake_clickables': data['fakeClickables'],
                'router_links': data['routerLinks'],
                'cursor_pointers': data['cursorPointers'],
                'fake_to_real_ratio': fake_total / max(1, real_total),
                'total_elements': data['total'],
                'framework': 'React' if data['hasReact'] else 'Vue' if data['hasVue'] else 'Angular' if data['hasAngular'] else 'None'
            }
            
            return DetectionResult(
                signal_name="Clickable Element Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"Fake-Clickables: {fake_total}, Real-Links: {real_total}, Framework: {evidence['framework']}"
            )
            
        except Exception as e:
            logger.error(f"Fehler bei Clickable-Analyse: {e}")
            return DetectionResult(
                signal_name="Clickable Element Pattern",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )