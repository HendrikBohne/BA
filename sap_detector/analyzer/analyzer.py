"""
SPA Detection Tool - Main Analyzer
Haupt-Analyzer der alle Detektoren koordiniert
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
    
    # Verwende importierte Weights
    SIGNAL_WEIGHTS = SIGNAL_WEIGHTS
    
    def __init__(self, page: Page):
        self.page = page
        self.url = page.url if page else None  # Fix für None-Page
        self.errors = []
        
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
            
            # Injiziere Monitoring-Code
            await self.history_detector.inject_monitors(self.page)
            await self.dom_detector.inject_observer(self.page)
            await self.title_detector.inject_observer(self.page)
            
            # Setup Network-Listener
            await self.network_detector.setup_listeners(self.page)
            
            logger.info("✅ Alle Detektoren bereit")
            
        except Exception as e:
            error_msg = f"Setup-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
    
    async def perform_interactions(self, strategy: str = "smart", max_actions: int = 10):
        """Führt robuste Interaktionen aus"""
        logger.info(f"🎮 Starte Interaktionen (Strategie: {strategy})...")
        
        total_actions = 0
        
        try:
            # Scrolle Seite zuerst (für Lazy-Loading)
            await self.interaction_strategy.scroll_page(self.page)
            
            # Führe Hauptstrategie aus
            if strategy == "smart" or strategy == "random_walk":
                actions = await self.interaction_strategy.smart_random_walk(self.page, max_actions)
                total_actions += actions
            elif strategy == "navigation":
                actions = await self.interaction_strategy.test_navigation(self.page, max_actions)
                total_actions += actions
            elif strategy == "model_guided":  # ← NEU!
                actions = await self.interaction_strategy.model_guided_random_walk(self.page, max_actions)
                total_actions += actions
            else:
                logger.warning(f"Unbekannte Strategie: {strategy}, verwende 'smart'")
                actions = await self.interaction_strategy.smart_random_walk(self.page, max_actions)
                total_actions += actions
            
            logger.info(f"✅ {total_actions} Interaktionen durchgeführt")
            
        except Exception as e:
            error_msg = f"Interaktions-Fehler: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
        
        return total_actions

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
        """
        Führt komplette SPA-Analyse durch
        
        Args:
            interact: Interaktionen durchführen
            interaction_strategy: "smart", "random_walk" oder "navigation"
            max_interactions: Max. Anzahl Interaktionen
        """
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
            
            # Daten sammeln
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
            
            # Rückgabe mit Fehler
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
        
        # Zähle detektierte Signale
        detected_count = sum(1 for r in results if r.detected)
        total_count = len(results)
        
        # Gewichteter Score
        weighted_score = 0.0
        for result in results:
            weight = self.SIGNAL_WEIGHTS.get(result.signal_name, 0.1)
            if result.detected:
                weighted_score += weight * result.confidence
        
        # SPA-Entscheidung
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
        
        # Empfehlungen
        recommendations = self._generate_recommendations(results, detected_count, is_spa)
        
        # Ausgabe
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
        
        # Signal-spezifische Empfehlungen
        for result in results:
            if not result.detected and not result.error:
                if result.signal_name == "History-API Navigation":
                    recommendations.append(
                        "Teste Navigation-Links intensiver um History-API Calls zu triggern"
                    )
                elif result.signal_name == "Network Activity Pattern":
                    recommendations.append(
                        "Suche nach dynamischen Inhalten (Filter, Suche, Pagination)"
                    )
                elif result.signal_name == "DOM Rewriting Pattern":
                    recommendations.append(
                        "Klicke auf mehr verschiedene Elemente um DOM-Änderungen zu provozieren"
                    )
        
        return recommendations[:5]  # Maximal 5 Empfehlungen
    
    @staticmethod
    def export_report(result: SPAAnalysisResult) -> Dict:
        """Exportiert detaillierten JSON-Report (statische Methode)"""
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