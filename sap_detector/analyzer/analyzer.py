"""
SPA Detection Tool - Main Analyzer (v4 - mit Hard Signal Gating)
Haupt-Analyzer der alle Detektoren koordiniert

ÄNDERUNGEN v4:
1. HARD SIGNAL GATING: Ohne History-API zählen DOM/Network weniger
2. POST-CLICK MESSUNG: Click-Windows für DOM und Network
3. ANTI-SIGNAL: Full Document Navigation reduziert Score
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
    """
    Haupt-Analyzer mit:
    - Hard Signal Gating
    - Post-Click Messung
    - Anti-Signal für Full Navigation
    """
    
    # Basis-Gewichte (werden durch Gating modifiziert)
    SIGNAL_WEIGHTS = {
        "History-API Navigation": 0.40,      # HARD SIGNAL - höchstes Gewicht
        "Network Activity Pattern": 0.20,    # Reduziert von 0.30
        "DOM Rewriting Pattern": 0.20,       # Reduziert von 0.25
        "Title Change Pattern": 0.10,
        "Clickable Element Pattern": 0.10,
    }
    
    def __init__(self, page: Page):
        self.page = page
        self.url = page.url if page else None
        self.errors = []
        self._navigation_count = 0
        self._last_url = None
        
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
            await self.cookie_handler.handle_cookies(self.page)
            await self.cookie_handler.close_popups(self.page)
            
            self._last_url = self.page.url
            
            # Navigation-Tracking für Anti-Signal
            self.page.on("framenavigated", self._on_navigation)
            
            await self.history_detector.inject_monitors(self.page)
            await self.dom_detector.inject_observer(self.page)
            await self.title_detector.inject_observer(self.page)
            await self.network_detector.setup_listeners(self.page)
            
            logger.info("✅ Alle Detektoren bereit (v4 - mit Hard Signal Gating)")
            
        except Exception as e:
            error_msg = f"Setup-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
    
    def _on_navigation(self, frame):
        """Zählt Full Document Navigations (Anti-Signal)"""
        try:
            if frame == self.page.main_frame:
                self._navigation_count += 1
                new_url = frame.url
                logger.debug(f"📄 Document Navigation #{self._navigation_count}: {new_url}")
                self._last_url = new_url
        except Exception as e:
            logger.debug(f"Navigation-Tracking Fehler: {e}")
    
    async def perform_interactions(self, strategy: str = "smart", max_actions: int = 10):
        """Führt Interaktionen mit Click-Window Tracking durch"""
        logger.info(f"🎮 Starte Interaktionen (Strategie: {strategy})...")
        
        total_actions = 0
        
        try:
            # Baseline-Phase: Warte 3 Sekunden für Initial-Load
            logger.info("⏳ Baseline-Phase (3s Initial Load)...")
            await asyncio.sleep(3)
            
            # Scrolle Seite
            await self.interaction_strategy.scroll_page(self.page)
            
            # Interaktionen mit Click-Windows
            if strategy in ["smart", "random_walk"]:
                total_actions = await self._interactive_with_windows(max_actions)
            elif strategy == "navigation":
                total_actions = await self._navigation_with_windows(max_actions)
            elif strategy == "model_guided":
                total_actions = await self._model_guided_with_windows(max_actions)
            else:
                total_actions = await self._interactive_with_windows(max_actions)
            
            logger.info(f"✅ {total_actions} Interaktionen durchgeführt")
            
        except Exception as e:
            error_msg = f"Interaktions-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
        
        return total_actions
    
    async def _interactive_with_windows(self, max_actions: int) -> int:
        """Random Walk mit Click-Window Tracking für DOM und Network"""
        actions = 0
        failed = 0
        
        logger.info(f"🎮 Starte Smart Random-Walk mit Click-Windows (max {max_actions})...")
        
        for i in range(max_actions):
            if failed >= 3:
                break
            
            try:
                clickables = await self._get_safe_clickables()
                
                if not clickables:
                    failed += 1
                    await asyncio.sleep(0.5)
                    continue
                
                import random
                target = random.choice(clickables)
                
                # ======= CLICK-WINDOW STARTEN =======
                label = target['text'][:20] or f"click_{i}"
                await self.dom_detector.start_click_window(self.page, label)
                self.network_detector.start_click_window(label)
                
                # Klick ausführen
                success = await self._safe_click(target)
                
                if success:
                    actions += 1
                    failed = 0
                    logger.info(f"✅ Aktion {actions}: {target['text'][:30]}")
                    
                    # Warte auf Reaktion
                    await asyncio.sleep(1.5)
                else:
                    failed += 1
                
                # ======= CLICK-WINDOW BEENDEN =======
                await self.dom_detector.end_click_window(self.page)
                self.network_detector.end_click_window()
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Interaktion fehlgeschlagen: {e}")
                failed += 1
        
        logger.info(f"✅ Random-Walk abgeschlossen: {actions} Aktionen")
        return actions
    
    async def _navigation_with_windows(self, max_actions: int) -> int:
        """Navigation Test mit Click-Windows"""
        return await self.interaction_strategy.test_navigation(self.page, max_actions)
    
    async def _model_guided_with_windows(self, max_actions: int) -> int:
        """Model-Guided mit Click-Windows"""
        from .model_guided_strategy import ModelGuidedStrategy
        from .state_independent_model import StateIndependentModel
        
        model = StateIndependentModel(w_model=25.0)
        actions = 0
        failed = 0
        
        logger.info(f"🧠 Starte Model-Guided mit Click-Windows (max {max_actions})...")
        
        for i in range(max_actions):
            if failed >= 3:
                break
            
            try:
                clickables = await self._get_safe_clickables()
                
                if not clickables:
                    failed += 1
                    await asyncio.sleep(0.5)
                    continue
                
                # Model-basierte Auswahl
                candidate_ids = [ModelGuidedStrategy.create_candidate_id(c) for c in clickables]
                model.observe_candidates(candidate_ids)
                
                import random
                weights = []
                for idx, c_id in enumerate(candidate_ids):
                    base = 2.5 if clickables[idx].get('isSpaElement') else 1.0
                    if c_id in model.executed_candidates:
                        w = model.calculate_weight(c_id, base)
                    else:
                        w = base * 2.0
                    weights.append(w)
                
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
                
                # Click-Window
                label = target['text'][:20] or f"click_{i}"
                await self.dom_detector.start_click_window(self.page, label)
                self.network_detector.start_click_window(label)
                
                success = await self._safe_click(target)
                
                if success:
                    actions += 1
                    failed = 0
                    logger.info(f"✅ Aktion {actions}: {target['text'][:30]}")
                    
                    await asyncio.sleep(1.5)
                    
                    # Model Update
                    successors = await self._get_safe_clickables()
                    successor_ids = [ModelGuidedStrategy.create_candidate_id(s) for s in successors]
                    model.execute_candidate(candidate_ids[target_idx], successor_ids)
                else:
                    failed += 1
                
                await self.dom_detector.end_click_window(self.page)
                self.network_detector.end_click_window()
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Model-guided fehlgeschlagen: {e}")
                failed += 1
        
        stats = model.get_stats()
        logger.info(f"✅ Model-Guided abgeschlossen: {actions} Aktionen")
        logger.info(f"📊 Model-Stats: {stats['total_candidates']} Candidates, {stats['executed_candidates']} ausgeführt")
        return actions
    
    async def _get_safe_clickables(self) -> list:
        """Findet sichere klickbare Elemente"""
        try:
            return await self.page.evaluate("""
                () => {
                    const blacklist = [
                        'live', 'app holen', 'download', 'herunterladen', 'install',
                        'creator', 'tool', 'studio', 'business', 'ads', 'werbung',
                        'impressum', 'datenschutz', 'privacy', 'terms', 'agb',
                        'hilfe', 'help', 'support', 'kontakt', 'contact',
                        'karriere', 'jobs', 'über uns', 'about', 'presse',
                        'cookie', 'einstellungen', 'settings', 'language', 'sprache'
                    ];
                    
                    const safeElements = [
                        ...document.querySelectorAll('[role="button"]:not([href])'),
                        ...document.querySelectorAll('[role="tab"]'),
                        ...document.querySelectorAll('button:not([type="submit"]):not([formaction])'),
                        ...document.querySelectorAll('[onclick]:not(a)'),
                        ...document.querySelectorAll('div[tabindex="0"]'),
                        ...document.querySelectorAll('a[href^="#"]:not([href="#"])'),
                    ];
                    
                    return safeElements
                        .filter(el => {
                            try {
                                const rect = el.getBoundingClientRect();
                                const style = window.getComputedStyle(el);
                                
                                if (rect.width < 10 || rect.height < 10 || 
                                    rect.top < 0 || rect.top >= window.innerHeight ||
                                    style.display === 'none' || style.visibility === 'hidden') {
                                    return false;
                                }
                                
                                const text = (el.textContent || '').toLowerCase().trim();
                                const className = (el.className || '').toString().toLowerCase();
                                
                                for (const blocked of blacklist) {
                                    if (text.includes(blocked) || className.includes(blocked)) {
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
            try:
                await self.page.click(target['selector'], timeout=2000)
                return True
            except:
                pass
            
            try:
                clicked = await self.page.evaluate(f"""
                    () => {{
                        const els = document.querySelectorAll('{target["selector"]}');
                        const el = els[{target.get("index", 0)}];
                        if (el) {{ el.click(); return true; }}
                        return false;
                    }}
                """)
                return clicked
            except:
                return False
        except:
            return False

    async def collect_all_data(self):
        """Sammelt Daten von allen Detektoren"""
        logger.info("📊 Sammle Daten von allen Detektoren...")
        
        try:
            await self.history_detector.collect_data(self.page)
            await self.dom_detector.collect_data(self.page)
            await self.title_detector.collect_data(self.page)
            logger.info("✅ Datensammlung abgeschlossen")
        except Exception as e:
            error_msg = f"Datensammlung-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
    
    async def analyze(self, interact: bool = True, 
                     interaction_strategy: str = "smart",
                     max_interactions: int = 10) -> SPAAnalysisResult:
        """Führt komplette SPA-Analyse mit Hard Signal Gating durch"""
        logger.info("=" * 60)
        logger.info("🔍 SPA-ANALYSE GESTARTET (v4 - Hard Signal Gating)")
        logger.info("=" * 60)
        logger.info(f"URL: {self.url}")
        
        try:
            await self.setup()
            
            if interact:
                await self.perform_interactions(interaction_strategy, max_interactions)
                await asyncio.sleep(2)
            else:
                logger.info("ℹ️  Interaktionen übersprungen (--no-interact)")
                await asyncio.sleep(3)  # Baseline abwarten
            
            await self.collect_all_data()
            
            logger.info("\n🔬 Analysiere Signale...")
            results = []
            
            # Alle Signale analysieren
            result1 = self.history_detector.analyze()
            results.append(result1)
            self._print_signal_result(result1)
            
            result2 = self.network_detector.analyze()
            results.append(result2)
            self._print_signal_result(result2)
            
            result3 = self.dom_detector.analyze()
            results.append(result3)
            self._print_signal_result(result3)
            
            result4 = self.title_detector.analyze()
            results.append(result4)
            self._print_signal_result(result4)
            
            result5 = await self.clickable_detector.scan_dom(self.page)
            results.append(result5)
            self._print_signal_result(result5)
            
            # Finale Auswertung MIT HARD SIGNAL GATING
            return self._compute_final_result_with_gating(results)
            
        except Exception as e:
            error_msg = f"Kritischer Analyse-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            
            return SPAAnalysisResult(
                is_spa=False, confidence=0.0, overall_score=0.0,
                signal_results=[], detected_signals=0, total_signals=5,
                verdict="❌ ANALYSE FEHLGESCHLAGEN",
                recommendations=["Prüfe Logs für Details"],
                url=self.url, errors=self.errors
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
    
    def _compute_final_result_with_gating(self, results: List[DetectionResult]) -> SPAAnalysisResult:
        """
        Berechnet finales SPA-Urteil MIT HARD SIGNAL GATING.
        
        REGEL: Ohne History-API (Hard Signal) zählen DOM/Network nur 35%!
        ANTI-SIGNAL: Viele Frame-Navigations reduzieren den Score.
        """
        logger.info("\n" + "=" * 60)
        logger.info("📊 FINALE AUSWERTUNG (mit Hard Signal Gating)")
        logger.info("=" * 60)
        
        # ============================================
        # 1. PRÜFE HARD SIGNAL (History-API)
        # ============================================
        history_result = next((r for r in results if r.signal_name == "History-API Navigation"), None)
        hard_signal_present = history_result and history_result.detected
        
        if hard_signal_present:
            logger.info("🎯 HARD SIGNAL VORHANDEN: History-API Navigation erkannt")
        else:
            logger.info("⚠️  KEIN HARD SIGNAL: History-API nicht erkannt")
        
        # ============================================
        # 2. BERECHNE SCORE MIT GATING
        # ============================================
        detected_count = sum(1 for r in results if r.detected)
        
        weighted_score = 0.0
        gating_applied = False
        
        for result in results:
            weight = self.SIGNAL_WEIGHTS.get(result.signal_name, 0.1)
            
            if result.detected:
                contribution = weight * result.confidence
                
                # GATING: Ohne Hard Signal zählen DOM/Network nur 35%
                if not hard_signal_present:
                    if result.signal_name in ["DOM Rewriting Pattern", "Network Activity Pattern"]:
                        contribution *= 0.35
                        gating_applied = True
                
                weighted_score += contribution
        
        if gating_applied:
            logger.info("📉 GATING ANGEWENDET: DOM/Network auf 35% reduziert")
        
        # ============================================
        # 3. ANTI-SIGNAL: Full Document Navigation
        # ============================================
        history_calls = 0
        if history_result and history_result.evidence:
            history_calls = history_result.evidence.get('total_history_calls', 0)
        
        frame_navs = self._navigation_count
        
        # Anti-Signal: Viele Frame-Navigations ohne entsprechende History-Calls
        if frame_navs >= 3 and history_calls < frame_navs:
            anti_signal_penalty = min(0.25, (frame_navs - history_calls) * 0.05)
            weighted_score = max(0.0, weighted_score - anti_signal_penalty)
            logger.info(f"📉 ANTI-SIGNAL: {frame_navs} Frame-Navigations → Score -{anti_signal_penalty:.2f}")
        
        # ============================================
        # 4. FINALE ENTSCHEIDUNG
        # ============================================
        is_spa = False
        confidence = 0.0
        verdict = ""
        
        # MIT Hard Signal: Normale Schwellwerte
        if hard_signal_present:
            if detected_count >= 4 or weighted_score >= 0.6:
                is_spa = True
                confidence = min(0.98, weighted_score + 0.1)
                verdict = "🎯 DEFINITIV SPA"
            elif detected_count >= 3 and weighted_score >= 0.45:
                is_spa = True
                confidence = min(0.90, weighted_score)
                verdict = "✅ SEHR WAHRSCHEINLICH SPA"
            elif detected_count >= 2 and weighted_score >= 0.35:
                is_spa = True
                confidence = min(0.80, weighted_score)
                verdict = "✅ WAHRSCHEINLICH SPA"
            else:
                is_spa = True
                confidence = min(0.65, weighted_score)
                verdict = "⚠️  MÖGLICHERWEISE SPA"
        
        # OHNE Hard Signal: Sehr strenge Schwellwerte
        else:
            if weighted_score >= 0.5 and detected_count >= 4:
                # Alle anderen Signale müssen sehr stark sein
                is_spa = True
                confidence = min(0.60, weighted_score)
                verdict = "⚠️  MÖGLICHERWEISE SPA (ohne History-API)"
            elif weighted_score >= 0.3 and detected_count >= 3:
                is_spa = False
                confidence = weighted_score
                verdict = "❓ DYNAMISCHE SEITE (kein klares SPA-Signal)"
            else:
                is_spa = False
                confidence = weighted_score
                verdict = "❌ KEINE SPA"
        
        recommendations = self._generate_recommendations(results, detected_count, is_spa, hard_signal_present)
        
        # ============================================
        # 5. AUSGABE
        # ============================================
        print(f"\n{'='*60}")
        print(f"🎯 ERGEBNIS: {verdict}")
        print(f"{'='*60}")
        print(f"URL: {self.url}")
        print(f"Hard Signal (History-API): {'✅ JA' if hard_signal_present else '❌ NEIN'}")
        print(f"Detektierte Signale: {detected_count}/5")
        print(f"Frame-Navigations: {frame_navs}")
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
            total_signals=5,
            verdict=verdict,
            recommendations=recommendations,
            url=self.url,
            errors=self.errors
        )
    
    def _generate_recommendations(self, results: List[DetectionResult], 
                                 detected_count: int, is_spa: bool,
                                 hard_signal: bool) -> List[str]:
        """Generiert intelligente Empfehlungen"""
        recommendations = []
        
        if not hard_signal:
            recommendations.append(
                "Kein History-API Signal erkannt - prüfe ob die Seite tatsächlich SPA-Navigation nutzt"
            )
        
        if detected_count < 2:
            recommendations.append(
                "Wenige Signale erkannt - erhöhe --max-actions auf 15-20"
            )
        
        if not is_spa and detected_count >= 2:
            recommendations.append(
                "Dynamische Seite, aber keine eindeutige SPA - könnte Hybrid-App sein"
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
