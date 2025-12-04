"""
SPA Detection Tool - Main Analyzer (Production Version)
Robuster Analyzer mit Cookie-Handling und fehlertoleranten Interaktionen
"""
import asyncio
import random
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

from spa_detectors import (
    DetectionResult,
    HistoryAPIDetector,
    NetworkActivityDetector,
    DOMRewritingDetector,
    TitleChangeDetector,
    ClickableElementDetector
)

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


class CookieHandler:
    """Automatisches Cookie-Banner Handling"""
    
    # Bekannte Cookie-Banner Selektoren (erweiterte Liste)
    COOKIE_SELECTORS = [
        # Allgemeine Begriffe
        'button:has-text("Accept")',
        'button:has-text("Akzeptieren")',
        'button:has-text("Accept all")',
        'button:has-text("Alle akzeptieren")',
        'button:has-text("Agree")',
        'button:has-text("Zustimmen")',
        'button:has-text("OK")',
        'button:has-text("Got it")',
        'button:has-text("Verstanden")',
        'button:has-text("Allow")',
        'button:has-text("Erlauben")',
        'button:has-text("Continue")',
        'button:has-text("Weiter")',
        
        # ID-basierte Selektoren
        '#onetrust-accept-btn-handler',
        '#accept-cookies',
        '#acceptCookies',
        '#cookie-accept',
        '#cookieAccept',
        '.accept-cookies',
        '.cookie-accept',
        
        # Klassen-basierte Selektoren
        '[class*="accept"][class*="cookie"]',
        '[class*="cookie"][class*="accept"]',
        '[class*="consent"][class*="accept"]',
        '[class*="accept"][class*="all"]',
        
        # Data-Attribute
        '[data-testid*="accept"]',
        '[data-testid*="cookie"]',
        '[data-test*="accept"]',
        '[data-test*="cookie"]',
        
        # ARIA-Labels
        '[aria-label*="Accept"]',
        '[aria-label*="Akzeptieren"]',
        '[aria-label*="cookie"]',
        
        # OneTrust (häufiges Cookie-Tool)
        '.onetrust-close-btn-handler',
        '#onetrust-button-group button',
        
        # Cookie-Bot
        '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
        
        # Quantcast
        '.qc-cmp2-summary-buttons button',
        
        # TrustArc
        '#truste-consent-button',
        
        # Generische Fallbacks
        'button[id*="cookie"]',
        'button[class*="cookie"]',
        'a[id*="cookie"]',
        'a[class*="cookie"]',
    ]
    
    @staticmethod
    async def handle_cookies(page: Page, timeout: int = 5000) -> bool:
        """
        Versucht Cookie-Banner automatisch zu akzeptieren
        Returns: True wenn Banner gefunden und geklickt wurde
        """
        try:
            logger.info("🍪 Suche nach Cookie-Banner...")
            
            # Warte kurz, damit Banner erscheinen kann
            await asyncio.sleep(1)
            
            for selector in CookieHandler.COOKIE_SELECTORS:
                try:
                    # Versuche Element zu finden (kurzes Timeout)
                    element = await page.wait_for_selector(selector, timeout=1000, state='visible')
                    
                    if element:
                        # Klicke auf das Element
                        await element.click(timeout=2000)
                        logger.info(f"✅ Cookie-Banner akzeptiert (Selector: {selector})")
                        await asyncio.sleep(1)  # Warte kurz nach Klick
                        return True
                        
                except PlaywrightTimeout:
                    continue
                except Exception as e:
                    logger.debug(f"Cookie-Klick fehlgeschlagen für {selector}: {e}")
                    continue
            
            logger.info("ℹ️  Kein Cookie-Banner gefunden (oder bereits akzeptiert)")
            return False
            
        except Exception as e:
            logger.warning(f"Cookie-Handling Fehler: {e}")
            return False
    
    @staticmethod
    async def close_popups(page: Page):
        """Schließt zusätzliche Popups (Newsletter, etc.)"""
        try:
            # Suche nach häufigen Close-Buttons
            close_selectors = [
                'button[aria-label*="Close"]',
                'button[aria-label*="Schließen"]',
                '.close',
                '.modal-close',
                '[class*="close"][class*="button"]',
                '[data-dismiss="modal"]',
            ]
            
            for selector in close_selectors:
                try:
                    element = await page.wait_for_selector(selector, timeout=1000, state='visible')
                    if element:
                        await element.click(timeout=2000)
                        logger.info(f"✅ Popup geschlossen: {selector}")
                        await asyncio.sleep(0.5)
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Popup-Close Fehler: {e}")


class InteractionStrategy:
    """Robuste Interaktionsstrategien für beliebige Websites"""
    
    @staticmethod
    async def smart_random_walk(page: Page, max_actions: int = 10) -> int:
        """
        Intelligenter Random-Walk mit Fehlerbehandlung
        Returns: Anzahl erfolgreicher Aktionen
        """
        actions_performed = 0
        failed_attempts = 0
        max_failures = 5
        
        logger.info(f"🎮 Starte Smart Random-Walk (max {max_actions} Aktionen)...")
        
        for i in range(max_actions):
            if failed_attempts >= max_failures:
                logger.warning(f"⚠️  Zu viele fehlgeschlagene Versuche ({failed_attempts}), breche ab")
                break
            
            try:
                # Finde klickbare Elemente (robuster)
                clickables = await page.evaluate("""
                    () => {
                        const elements = [
                            ...document.querySelectorAll('a, button, [role="button"], [onclick], nav a, .nav-link'),
                            ...document.querySelectorAll('[class*="menu"], [class*="nav"], [class*="link"]')
                        ];
                        
                        return elements
                            .filter(el => {
                                try {
                                    const rect = el.getBoundingClientRect();
                                    const style = window.getComputedStyle(el);
                                    
                                    // Element muss sichtbar und klickbar sein
                                    return rect.width > 0 && 
                                           rect.height > 0 && 
                                           rect.top >= 0 && 
                                           rect.left >= 0 &&
                                           rect.top < window.innerHeight &&
                                           style.display !== 'none' &&
                                           style.visibility !== 'hidden' &&
                                           style.opacity !== '0';
                                } catch (e) {
                                    return false;
                                }
                            })
                            .map((el, idx) => {
                                let selector = el.tagName.toLowerCase();
                                if (el.id) selector += '#' + el.id;
                                else if (el.className && typeof el.className === 'string') {
                                    const classes = el.className.split(' ').filter(c => c && c.length < 30);
                                    if (classes[0]) selector += '.' + classes[0];
                                }
                                
                                return {
                                    index: idx,
                                    selector: selector,
                                    text: (el.textContent || '').trim().substring(0, 50),
                                    tag: el.tagName.toLowerCase(),
                                    hasHref: el.hasAttribute('href')
                                };
                            })
                            .slice(0, 50);  // Limitiere auf 50 Elemente
                    }
                """)
                
                if not clickables or len(clickables) == 0:
                    logger.debug(f"Keine klickbaren Elemente gefunden (Versuch {i+1})")
                    failed_attempts += 1
                    await asyncio.sleep(0.5)
                    continue
                
                # Wähle zufälliges Element (bevorzuge Links)
                links = [c for c in clickables if c['hasHref']]
                target = random.choice(links if links else clickables)
                
                logger.debug(f"Klicke auf: {target['text'][:30]} ({target['tag']})")
                
                # Versuche verschiedene Klick-Methoden
                try:
                    # Methode 1: Direkter Klick
                    await page.click(target['selector'], timeout=3000)
                    actions_performed += 1
                    failed_attempts = 0  # Reset bei Erfolg
                    logger.info(f"✅ Aktion {actions_performed}: {target['text'][:30]}")
                    
                except PlaywrightTimeout:
                    # Methode 2: JavaScript Klick
                    try:
                        await page.evaluate(f"""
                            () => {{
                                const elements = document.querySelectorAll('{target['selector']}');
                                if (elements[{target['index']}]) {{
                                    elements[{target['index']}].click();
                                }}
                            }}
                        """)
                        actions_performed += 1
                        logger.info(f"✅ Aktion {actions_performed} (JS): {target['text'][:30]}")
                    except:
                        failed_attempts += 1
                        logger.debug(f"❌ Klick fehlgeschlagen: {target['text'][:30]}")
                
                # Warte zwischen Aktionen (variabel)
                await asyncio.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                logger.debug(f"Interaktion {i+1} fehlgeschlagen: {e}")
                failed_attempts += 1
                await asyncio.sleep(0.5)
                continue
        
        logger.info(f"✅ Random-Walk abgeschlossen: {actions_performed} erfolgreiche Aktionen")
        return actions_performed
    
    @staticmethod
    async def test_navigation(page: Page, max_links: int = 5) -> int:
        """
        Testet Navigation-Links systematisch
        Returns: Anzahl erfolgreicher Aktionen
        """
        actions = 0
        
        try:
            logger.info("🧭 Teste Navigation-Links...")
            
            # Finde Navigation-Links
            nav_links = await page.evaluate("""
                () => {
                    const navElements = [
                        ...document.querySelectorAll('nav a, [role="navigation"] a'),
                        ...document.querySelectorAll('.nav a, .navigation a, .menu a'),
                        ...document.querySelectorAll('header a, [class*="header"] a')
                    ];
                    
                    return [...new Set(navElements)]  // Deduplizieren
                        .filter(el => {
                            const rect = el.getBoundingClientRect();
                            return rect.width > 0 && rect.height > 0;
                        })
                        .slice(0, 10)
                        .map(el => ({
                            text: el.textContent.trim().substring(0, 30),
                            href: el.getAttribute('href')
                        }));
                }
            """)
            
            logger.info(f"Gefunden: {len(nav_links)} Navigation-Links")
            
            for link in nav_links[:max_links]:
                try:
                    # Klicke auf Link
                    await page.click(f'a:has-text("{link["text"]}")', timeout=2000)
                    actions += 1
                    logger.info(f"✅ Navigation-Klick: {link['text']}")
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.debug(f"Navigation-Klick fehlgeschlagen: {link['text']}: {e}")
                    continue
            
            logger.info(f"✅ Navigation-Test: {actions} erfolgreiche Klicks")
            
        except Exception as e:
            logger.error(f"Navigation-Test Fehler: {e}")
        
        return actions
    
    @staticmethod
    async def scroll_page(page: Page):
        """Scrollt die Seite für Lazy-Loading"""
        try:
            logger.info("📜 Scrolle Seite...")
            
            await page.evaluate("""
                async () => {
                    const scrollStep = window.innerHeight / 2;
                    const scrollDelay = 200;
                    
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, scrollStep);
                        await new Promise(resolve => setTimeout(resolve, scrollDelay));
                    }
                    
                    // Zurück nach oben
                    window.scrollTo(0, 0);
                }
            """)
            
            await asyncio.sleep(1)
            logger.info("✅ Scrolling abgeschlossen")
            
        except Exception as e:
            logger.debug(f"Scroll-Fehler: {e}")


class SPAAnalyzer:
    """Haupt-Analyzer mit robustem Error-Handling"""
    
    SIGNAL_WEIGHTS = {
        "History-API Navigation": 0.30,
        "Network Activity Pattern": 0.25,
        "DOM Rewriting Pattern": 0.25,
        "Title Change Pattern": 0.10,
        "Clickable Element Pattern": 0.10
    }
    
    def __init__(self, page: Page):
        self.page = page
        self.url = page.url
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
    
    def export_report(self, result: SPAAnalysisResult) -> Dict:
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