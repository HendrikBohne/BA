"""
SPA Detection Tool - Main Analyzer (FIXED v3)
Haupt-Analyzer der alle Detektoren koordiniert

FIXES v3:
- Kontinuierliche Datensammlung während der Interaktionen
- Re-Injection nach jeder Navigation
- Robustere Fehlerbehandlung
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import List, Dict
from playwright.async_api import Page

from detectors import (
    DetectionResult,
    HistoryAPIDetector,
    NetworkActivityDetector,
    DOMRewritingDetector,
    TitleChangeDetector,
    ClickableElementDetector
)
from .cookie_handler import CookieHandler
from .interaction_strategy import InteractionStrategy
from .weights import SIGNAL_WEIGHTS

logger = logging.getLogger(__name__)


@dataclass
class SPAAnalysisResult:
    """Gesamtergebnis der SPA-Analyse"""
    is_spa: bool
    confidence: float
    overall_score: float
    signal_results: List[DetectionResult]
    detected_signals: int
    total_signals: int
    verdict: str
    recommendations: List[str]
    url: str
    errors: List[str]


class SPAAnalyzer:
    """Haupt-Analyzer mit robustem Error-Handling"""
    
    SIGNAL_WEIGHTS = SIGNAL_WEIGHTS
    
    def __init__(self, page: Page):
        self.page = page
        self.url = page.url if page else None
        self.errors = []
        self._last_url = None
        self._navigation_count = 0
        
        # Detektoren
        self.history_detector = HistoryAPIDetector()
        self.network_detector = NetworkActivityDetector()
        self.dom_detector = DOMRewritingDetector()
        self.title_detector = TitleChangeDetector()
        self.clickable_detector = ClickableElementDetector()
        
        self.interaction_strategy = InteractionStrategy()
        self.cookie_handler = CookieHandler()
    
    async def setup(self):
        """Initialisiert alle Detektoren"""
        logger.info("🔧 Initialisiere Detektoren...")
        
        try:
            # Handle Cookies zuerst
            await self.cookie_handler.handle_cookies(self.page)
            await self.cookie_handler.close_popups(self.page)
            
            # Speichere initiale URL
            self._last_url = self.page.url
            
            # Injiziere Monitoring-Code
            await self.history_detector.inject_monitors(self.page)
            await self.dom_detector.inject_observer(self.page)
            await self.title_detector.inject_observer(self.page)
            
            # Setup Network-Listener
            await self.network_detector.setup_listeners(self.page)
            
            # Navigation-Listener für Re-Injection
            self.page.on("framenavigated", self._on_navigation)
            
            logger.info("✅ Alle Detektoren bereit")
            
        except Exception as e:
            error_msg = f"Setup-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
    
    def _on_navigation(self, frame):
        """Wird bei jeder Navigation aufgerufen"""
        try:
            if frame == self.page.main_frame:
                self._navigation_count += 1
                new_url = frame.url
                logger.debug(f"Navigation #{self._navigation_count}: {self._last_url} → {new_url}")
                self._last_url = new_url
        except Exception as e:
            logger.debug(f"Navigation-Tracking Fehler: {e}")
    
    async def _ensure_scripts_active(self):
        """Stellt sicher dass die Scripts aktiv sind"""
        try:
            # Prüfe ob Scripts noch aktiv sind
            status = await self.page.evaluate("""
                () => ({
                    history: !!(window.__spa_detection && window.__spa_detection.history),
                    dom: !!(window.__spa_detection && window.__spa_detection.dom),
                    domActive: !!(window.__spa_detection && window.__spa_detection.dom && window.__spa_detection.dom.observerActive)
                })
            """)
            
            if not status.get('history') or not status.get('dom'):
                logger.warning("⚠️  Scripts nicht aktiv, re-injiziere...")
                # Re-inject manually
                await self.history_detector.inject_monitors(self.page)
                await self.dom_detector.inject_observer(self.page)
                await self.title_detector.inject_observer(self.page)
                
            return status
            
        except Exception as e:
            logger.debug(f"Script-Check fehlgeschlagen: {e}")
            return {'history': False, 'dom': False, 'domActive': False}
    
    async def _safe_collect_data(self):
        """Sammelt Daten mit Fehlerbehandlung"""
        try:
            # Warte kurz auf Stabilität
            await asyncio.sleep(0.5)
            
            # Prüfe Scripts
            await self._ensure_scripts_active()
            
            # Sammle Daten
            await self.history_detector.collect_data(self.page)
            await self.dom_detector.collect_data(self.page)
            await self.title_detector.collect_data(self.page)
            
            return True
            
        except Exception as e:
            logger.warning(f"Datensammlung fehlgeschlagen: {e}")
            return False
    
    async def perform_interactions(self, strategy: str = "smart", max_actions: int = 10):
        """Führt robuste Interaktionen aus mit kontinuierlicher Datensammlung"""
        logger.info(f"🎮 Starte Interaktionen (Strategie: {strategy})...")
        
        total_actions = 0
        
        try:
            # Scrolle Seite zuerst
            await self.interaction_strategy.scroll_page(self.page)
            
            # Sammle initiale Daten
            await self._safe_collect_data()
            
            # Führe Interaktionen einzeln aus mit Zwischensammlung
            if strategy == "smart" or strategy == "random_walk":
                total_actions = await self._interactive_random_walk(max_actions)
            elif strategy == "navigation":
                total_actions = await self._interactive_navigation(max_actions)
            elif strategy == "model_guided":
                total_actions = await self._interactive_model_guided(max_actions)
            else:
                logger.warning(f"Unbekannte Strategie: {strategy}, verwende 'smart'")
                total_actions = await self._interactive_random_walk(max_actions)
            
            logger.info(f"✅ {total_actions} Interaktionen durchgeführt")
            
        except Exception as e:
            error_msg = f"Interaktions-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
        
        return total_actions
    
    async def _interactive_random_walk(self, max_actions: int) -> int:
        """Random Walk mit kontinuierlicher Datensammlung"""
        actions = 0
        failed = 0
        
        logger.info(f"🎮 Starte Smart Random-Walk (max {max_actions} Aktionen)...")
        
        for i in range(max_actions):
            if failed >= 3:
                break
                
            try:
                # Finde nur sichere Elemente
                clickables = await self._get_safe_clickables()
                
                if not clickables:
                    failed += 1
                    await asyncio.sleep(0.5)
                    continue
                
                # Wähle Element
                import random
                target = random.choice(clickables)
                
                # Klicke
                success = await self._safe_click(target)
                
                if success:
                    actions += 1
                    failed = 0
                    logger.info(f"✅ Aktion {actions}: {target['text'][:30]}")
                    
                    # Warte und sammle Daten nach jeder Aktion
                    await asyncio.sleep(1)
                    await self._safe_collect_data()
                else:
                    failed += 1
                    
            except Exception as e:
                logger.debug(f"Interaktion fehlgeschlagen: {e}")
                failed += 1
        
        logger.info(f"✅ Random-Walk abgeschlossen: {actions} erfolgreiche Aktionen")
        return actions
    
    async def _interactive_navigation(self, max_actions: int) -> int:
        """Navigation Test mit kontinuierlicher Datensammlung"""
        actions = await self.interaction_strategy.test_navigation(self.page, max_actions)
        await self._safe_collect_data()
        return actions
    
    async def _interactive_model_guided(self, max_actions: int) -> int:
        """Model-Guided mit kontinuierlicher Datensammlung"""
        from .model_guided_strategy import ModelGuidedStrategy
        from .state_independent_model import StateIndependentModel
        
        model = StateIndependentModel(w_model=25.0)
        actions = 0
        failed = 0
        
        logger.info(f"🧠 Starte Model-Guided Random-Walk (max {max_actions} Aktionen)...")
        
        for i in range(max_actions):
            if failed >= 3:
                break
                
            try:
                clickables = await self._get_safe_clickables()
                
                if not clickables:
                    failed += 1
                    await asyncio.sleep(0.5)
                    continue
                
                # Candidate IDs erstellen
                candidate_ids = [ModelGuidedStrategy.create_candidate_id(c) for c in clickables]
                model.observe_candidates(candidate_ids)
                
                # Gewichte berechnen
                import random
                weights = []
                for idx, c_id in enumerate(candidate_ids):
                    base = 2.5 if clickables[idx].get('isSpaElement') else 1.0
                    if c_id in model.executed_candidates:
                        w = model.calculate_weight(c_id, base)
                    else:
                        w = base * 2.0
                    weights.append(w)
                
                # Weighted choice
                total = sum(weights)
                if total > 0:
                    r = random.uniform(0, total)
                    cumsum = 0
                    target_idx = 0
                    for idx, w in enumerate(weights):
                        cumsum += w
                        if r <= cumsum:
                            target_idx = idx
                            break
                else:
                    target_idx = random.randint(0, len(clickables) - 1)
                
                target = clickables[target_idx]
                success = await self._safe_click(target)
                
                if success:
                    actions += 1
                    failed = 0
                    logger.info(f"✅ Aktion {actions}: {target['text'][:30]}")
                    
                    # Sammle Nachfolger
                    await asyncio.sleep(0.5)
                    successors = await self._get_safe_clickables()
                    successor_ids = [ModelGuidedStrategy.create_candidate_id(s) for s in successors]
                    model.execute_candidate(candidate_ids[target_idx], successor_ids)
                    
                    # Daten sammeln
                    await asyncio.sleep(0.5)
                    await self._safe_collect_data()
                else:
                    failed += 1
                    
            except Exception as e:
                logger.debug(f"Model-guided Interaktion fehlgeschlagen: {e}")
                failed += 1
        
        stats = model.get_stats()
        logger.info(f"✅ Model-Guided Random-Walk abgeschlossen: {actions} erfolgreiche Aktionen")
        logger.info(f"📊 Model-Stats: {stats['total_candidates']} Candidates, {stats['executed_candidates']} ausgeführt ({stats['execution_rate']:.1%})")
        return actions
    
    async def _get_safe_clickables(self) -> list:
        """Findet nur SICHERE klickbare Elemente (keine echten Navigationen)"""
        try:
            return await self.page.evaluate("""
                () => {
                    const currentHostname = window.location.hostname;
                    
                    // BLACKLIST: Diese Texte/Klassen triggern oft echte Navigationen
                    const blacklist = [
                        'live', 'app holen', 'download', 'herunterladen', 'install',
                        'creator', 'tool', 'studio', 'business', 'ads', 'werbung',
                        'impressum', 'datenschutz', 'privacy', 'terms', 'agb',
                        'hilfe', 'help', 'support', 'kontakt', 'contact',
                        'karriere', 'jobs', 'über uns', 'about', 'presse',
                        'cookie', 'einstellungen', 'settings', 'language', 'sprache'
                    ];
                    
                    // Nur diese Elemente sind sicher
                    const safeElements = [
                        ...document.querySelectorAll('[role="button"]:not([href])'),
                        ...document.querySelectorAll('[role="tab"]'),
                        ...document.querySelectorAll('[role="menuitem"]:not([href])'),
                        ...document.querySelectorAll('button:not([type="submit"]):not([formaction])'),
                        ...document.querySelectorAll('[onclick]:not(a)'),
                        ...document.querySelectorAll('div[tabindex="0"]'),
                        ...document.querySelectorAll('span[tabindex="0"]'),
                    ];
                    
                    // Auch Hash-Links sind sicher
                    const hashLinks = document.querySelectorAll('a[href^="#"]:not([href="#"])');
                    
                    const allElements = [...safeElements, ...hashLinks];
                    
                    return allElements
                        .filter(el => {
                            try {
                                const rect = el.getBoundingClientRect();
                                const style = window.getComputedStyle(el);
                                
                                // Sichtbarkeits-Check
                                if (rect.width < 10 || rect.height < 10 || 
                                    rect.top < 0 || rect.left < 0 ||
                                    rect.top >= window.innerHeight ||
                                    rect.bottom <= 0 ||
                                    style.display === 'none' ||
                                    style.visibility === 'hidden' ||
                                    parseFloat(style.opacity) < 0.1) {
                                    return false;
                                }
                                
                                // Blacklist-Check
                                const text = (el.textContent || '').toLowerCase().trim();
                                const className = (el.className || '').toString().toLowerCase();
                                const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                                
                                for (const blocked of blacklist) {
                                    if (text.includes(blocked) || 
                                        className.includes(blocked) ||
                                        ariaLabel.includes(blocked)) {
                                        return false;
                                    }
                                }
                                
                                // Keine Links mit echten hrefs
                                if (el.tagName.toLowerCase() === 'a') {
                                    const href = el.getAttribute('href') || '';
                                    if (!href.startsWith('#') || href === '#') {
                                        return false;
                                    }
                                }
                                
                                return true;
                            } catch (e) {
                                return false;
                            }
                        })
                        .map((el, idx) => {
                            let selector = el.tagName.toLowerCase();
                            if (el.id) selector += '#' + el.id;
                            else if (el.className && typeof el.className === 'string') {
                                const cls = el.className.split(' ').filter(c => c && c.length < 30)[0];
                                if (cls) selector += '.' + cls;
                            }
                            
                            return {
                                index: idx,
                                selector: selector,
                                text: (el.textContent || '').trim().substring(0, 50),
                                tag: el.tagName.toLowerCase(),
                                isSpaElement: true
                            };
                        })
                        .slice(0, 30);
                }
            """)
        except Exception as e:
            logger.debug(f"Fehler beim Finden klickbarer Elemente: {e}")
            return []
    
    async def _safe_click(self, target: dict) -> bool:
        """Führt einen sicheren Klick aus"""
        try:
            # Versuche direkten Klick
            try:
                await self.page.click(target['selector'], timeout=2000)
                return True
            except:
                pass
            
            # Fallback: JS Klick
            try:
                clicked = await self.page.evaluate(f"""
                    () => {{
                        const els = document.querySelectorAll('{target["selector"]}');
                        const el = els[{target.get("index", 0)}];
                        if (el) {{
                            el.click();
                            return true;
                        }}
                        return false;
                    }}
                """)
                return clicked
            except:
                return False
                
        except Exception as e:
            logger.debug(f"Klick fehlgeschlagen: {e}")
            return False

    async def collect_all_data(self):
        """Sammelt Daten von allen Detektoren"""
        logger.info("📊 Sammle Daten von allen Detektoren...")
        
        try:
            await self._safe_collect_data()
            logger.info("✅ Datensammlung abgeschlossen")
            
        except Exception as e:
            error_msg = f"Datensammlung-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
    
    async def analyze(self, interact: bool = True, 
                     interaction_strategy: str = "smart",
                     max_interactions: int = 10) -> SPAAnalysisResult:
        """Führt komplette SPA-Analyse durch"""
        logger.info("=" * 60)
        logger.info("🔍 SPA-ANALYSE GESTARTET")
        logger.info("=" * 60)
        logger.info(f"URL: {self.url}")
        
        try:
            # Setup
            await self.setup()
            
            # Initiales Warten
            logger.info("⏳ Warte auf initiales Rendering...")
            await asyncio.sleep(2)
            
            # Interaktionen
            if interact:
                await self.perform_interactions(interaction_strategy, max_interactions)
                await asyncio.sleep(2)
            else:
                logger.info("ℹ️  Interaktionen übersprungen (--no-interact)")
            
            # Finale Datensammlung
            await self.collect_all_data()
            
            # Analysen durchführen
            logger.info("\n🔬 Analysiere Signale...")
            results = []
            
            # Signal 1: History-API
            result1 = self.history_detector.analyze()
            results.append(result1)
            self._print_signal_result(result1)
            
            # Signal 2: Network
            result2 = self.network_detector.analyze()
            results.append(result2)
            self._print_signal_result(result2)
            
            # Signal 3: DOM
            result3 = self.dom_detector.analyze()
            results.append(result3)
            self._print_signal_result(result3)
            
            # Signal 4: Title
            result4 = self.title_detector.analyze()
            results.append(result4)
            self._print_signal_result(result4)
            
            # Signal 5: Clickables
            result5 = await self.clickable_detector.scan_dom(self.page)
            results.append(result5)
            self._print_signal_result(result5)
            
            # Finale Auswertung
            return self._compute_final_result(results)
            
        except Exception as e:
            error_msg = f"Kritischer Analyse-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            
            return SPAAnalysisResult(
                is_spa=False,
                confidence=0.0,
                overall_score=0.0,
                signal_results=[],
                detected_signals=0,
                total_signals=5,
                verdict="❌ ANALYSE FEHLGESCHLAGEN",
                recommendations=["Prüfe Logs für Details"],
                url=self.url,
                errors=self.errors
            )
    
    def _print_signal_result(self, result: DetectionResult):
        """Formatierte Ausgabe eines Signal-Ergebnisses"""
        status = "✅" if result.detected else "❌"
        confidence_bar = "█" * int(result.confidence * 10) + "░" * (10 - int(result.confidence * 10))
        
        print(f"\n{status} {result.signal_name}")
        print(f"   Confidence: [{confidence_bar}] {result.confidence:.2%}")
        print(f"   {result.description}")
        
        if result.error:
            print(f"   ⚠️  Error: {result.error}")
    
    def _compute_final_result(self, results: List[DetectionResult]) -> SPAAnalysisResult:
        """Berechnet finales SPA-Urteil"""
        logger.info("\n" + "=" * 60)
        logger.info("📊 FINALE AUSWERTUNG")
        logger.info("=" * 60)
        
        detected_count = sum(1 for r in results if r.detected)
        total_count = len(results)
        
        weighted_score = 0.0
        for result in results:
            weight = self.SIGNAL_WEIGHTS.get(result.signal_name, 0.1)
            if result.detected:
                weighted_score += weight * result.confidence
        
        is_spa = False
        confidence = 0.0
        verdict = ""
        
        if detected_count >= 4:
            is_spa = True
            confidence = min(0.98, weighted_score + 0.1)
            verdict = "🎯 DEFINITIV SPA"
        elif detected_count >= 3 and weighted_score >= 0.5:
            is_spa = True
            confidence = min(0.95, weighted_score)
            verdict = "✅ SEHR WAHRSCHEINLICH SPA"
        elif detected_count >= 2 and weighted_score >= 0.4:
            is_spa = True
            confidence = min(0.85, weighted_score)
            verdict = "✅ WAHRSCHEINLICH SPA"
        elif detected_count >= 1 and weighted_score >= 0.3:
            is_spa = True
            confidence = min(0.70, weighted_score)
            verdict = "⚠️  MÖGLICHERWEISE SPA"
        else:
            is_spa = False
            confidence = weighted_score
            verdict = "❌ KEINE SPA"
        
        recommendations = self._generate_recommendations(results, detected_count, is_spa)
        
        print(f"\n{'='*60}")
        print(f"🎯 ERGEBNIS: {verdict}")
        print(f"{'='*60}")
        print(f"URL: {self.url}")
        print(f"Detektierte Signale: {detected_count}/{total_count}")
        print(f"Gewichteter Score: {weighted_score:.3f}")
        print(f"Finale Confidence: {confidence:.2%}")
        print(f"{'='*60}")
        
        if recommendations:
            print("\n💡 EMPFEHLUNGEN:")
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        
        if self.errors:
            print("\n⚠️  AUFGETRETENE FEHLER:")
            for err in self.errors:
                print(f"   - {err}")
        
        return SPAAnalysisResult(
            is_spa=is_spa,
            confidence=confidence,
            overall_score=weighted_score,
            signal_results=results,
            detected_signals=detected_count,
            total_signals=total_count,
            verdict=verdict,
            recommendations=recommendations,
            url=self.url,
            errors=self.errors
        )
    
    def _generate_recommendations(self, results: List[DetectionResult], 
                                 detected_count: int, is_spa: bool) -> List[str]:
        """Generiert intelligente Empfehlungen"""
        recommendations = []
        
        if detected_count < 2:
            recommendations.append(
                "Mehr Interaktionen durchführen (erhöhe --max-actions auf 15-20)"
            )
            recommendations.append(
                "Versuche verschiedene Strategien (--strategy navigation)"
            )
        
        if not is_spa:
            recommendations.append(
                "Diese Seite scheint eine traditionelle Multi-Page Application zu sein"
            )
        
        for result in results:
            if not result.detected and not result.error:
                if result.signal_name == "History-API Navigation":
                    recommendations.append(
                        "Teste Navigation-Links intensiver um History-API Calls zu triggern"
                    )
                elif result.signal_name == "DOM Rewriting Pattern":
                    recommendations.append(
                        "Klicke auf mehr verschiedene Elemente um DOM-Änderungen zu provozieren"
                    )
        
        return recommendations[:5]
    
    @staticmethod
    def export_report(result: SPAAnalysisResult) -> Dict:
        """Exportiert detaillierten JSON-Report"""
        return {
            "url": result.url,
            "verdict": result.verdict,
            "is_spa": result.is_spa,
            "confidence": result.confidence,
            "overall_score": result.overall_score,
            "detected_signals": result.detected_signals,
            "total_signals": result.total_signals,
            "signals": [
                {
                    "name": r.signal_name,
                    "detected": r.detected,
                    "confidence": r.confidence,
                    "description": r.description,
                    "evidence": r.evidence,
                    "error": r.error
                }
                for r in result.signal_results
            ],
            "recommendations": result.recommendations,
            "errors": result.errors
        }