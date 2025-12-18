"""
SPA Detection Tool - Main Entry Point (Production Version)
Robustes CLI mit vollständigem Error-Handling und Logging
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.absolute()))


import asyncio
import argparse
import json
import logging
from datetime import datetime
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

from analyzer import SPAAnalyzer, SPAAnalysisResult


# Logging Setup
def setup_logging(verbose: bool = False):
    """Konfiguriert Logging"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Root Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # File Handler (optional)
    try:
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_handler = logging.FileHandler(
            log_dir / f'spa_detection_{timestamp}.log',
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
    except Exception as e:
        print(f"⚠️  Konnte Log-Datei nicht erstellen: {e}")


class SPADetectionTool:
    """Haupt-CLI Tool mit robustem Error-Handling"""
    
    def __init__(self, headless: bool = False, timeout: int = 30000):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.headless = headless
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
    
    async def setup_browser(self):
        """Initialisiert Firefox mit optimalen Einstellungen"""
        try:
            self.logger.info("🦊 Starte Firefox...")
            
            self.playwright = await async_playwright().start()
            
            self.browser = await self.playwright.firefox.launch(
                headless=self.headless,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                ],
            )
            
            # Context mit realistischen Einstellungen
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
                locale='de-DE',
                timezone_id='Europe/Berlin',
                accept_downloads=False,
                ignore_https_errors=True,
            )
            
            # Setze längere Timeouts
            self.context.set_default_timeout(self.timeout)
            self.context.set_default_navigation_timeout(self.timeout)
            
            # Erstelle Page
            self.page = await self.context.new_page()
            
            # Blockiere unnötige Ressourcen für Speed
            await self.page.route("**/*", lambda route: (
                route.abort() if route.request.resource_type in ["image", "media", "font"] 
                else route.continue_()
            ))
            
            self.logger.info("✅ Browser bereit\n")
            
        except Exception as e:
            self.logger.error(f"❌ Browser-Setup fehlgeschlagen: {e}")
            raise
    
    async def cleanup(self):
        """Räumt Browser-Ressourcen auf"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            self.logger.info("✅ Browser bereinigt")
        except Exception as e:
            self.logger.error(f"Cleanup-Fehler: {e}")
    
    async def navigate_to_url(self, url: str, retries: int = 2) -> bool:
        """
        Navigiert zur URL mit Retry-Logik
        Returns: True bei Erfolg
        """
        for attempt in range(retries + 1):
            try:
                self.logger.info(f"🌐 Lade URL: {url} (Versuch {attempt + 1}/{retries + 1})")
                
                response = await self.page.goto(
                    url,
                    wait_until='networkidle',
                    timeout=self.timeout
                )
                
                if response and response.status >= 400:
                    self.logger.warning(f"⚠️  HTTP Status {response.status}")
                
                self.logger.info("✅ Seite geladen\n")
                return True
                
            except PlaywrightTimeout:
                self.logger.warning(f"⏱️  Timeout bei Versuch {attempt + 1}")
                if attempt < retries:
                    self.logger.info("🔄 Versuche erneut...")
                    await asyncio.sleep(2)
                else:
                    self.logger.error("❌ Alle Versuche fehlgeschlagen (Timeout)")
                    return False
                    
            except Exception as e:
                self.logger.error(f"❌ Navigation fehlgeschlagen: {e}")
                if attempt < retries:
                    await asyncio.sleep(2)
                else:
                    return False
        
        return False
    
    async def analyze_url(self, url: str, 
                         interact: bool = True,
                         interaction_strategy: str = "smart",
                         max_interactions: int = 10,
                         wait_time: int = 3) -> SPAAnalysisResult:
        """
        Analysiert eine URL auf SPA-Eigenschaften
        
        Args:
            url: Zu analysierende URL
            interact: Interaktionen durchführen
            interaction_strategy: "smart", "random_walk" oder "navigation"
            max_interactions: Anzahl Interaktionen
            wait_time: Wartezeit nach Load
        """
        try:
            # Navigiere zur URL
            success = await self.navigate_to_url(url)
            if not success:
                self.logger.error(f"❌ Konnte {url} nicht laden")
                return None
            
            # Server-HTML abrufen (für DOM-Detector)
            server_html = await self.page.content()
            
            # Warte auf initiales Rendering
            await asyncio.sleep(wait_time)
            
            # Erstelle Analyzer
            analyzer = SPAAnalyzer(self.page)
            
            # Server-HTML an DOM-Detector übergeben
            analyzer.dom_detector.record_server_html(server_html)
            
            # Führe Analyse durch
            result = await analyzer.analyze(
                interact=interact,
                interaction_strategy=interaction_strategy,
                max_interactions=max_interactions
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Analyse-Fehler für {url}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    async def analyze_multiple_urls(self, urls: list, **kwargs) -> dict:
        """Analysiert mehrere URLs nacheinander"""
        results = {}
        
        for i, url in enumerate(urls, 1):
            print(f"\n{'='*80}")
            print(f"📊 Analyse {i}/{len(urls)}: {url}")
            print(f"{'='*80}\n")
            
            try:
                result = await self.analyze_url(url, **kwargs)
                results[url] = result
                
                if result:
                    print(f"\n✅ Analyse abgeschlossen: {result.verdict}")
                else:
                    print(f"\n❌ Analyse fehlgeschlagen")
                
            except Exception as e:
                self.logger.error(f"❌ Fehler bei {url}: {e}")
                results[url] = None
            
            # Neue Seite für nächste URL
            if i < len(urls):
                try:
                    await self.page.close()
                    self.page = await self.context.new_page()
                except Exception as e:
                    self.logger.error(f"Fehler beim Erstellen neuer Page: {e}")
        
        return results
    
    @staticmethod
    def save_report(result: SPAAnalysisResult, output_path: str):
        """Speichert Analyse-Report als JSON"""
        try:
            report = SPAAnalyzer.export_report(result)
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"\n💾 Report gespeichert: {output_file}")
            
        except Exception as e:
            logging.error(f"❌ Report-Speicherung fehlgeschlagen: {e}")
    
    @staticmethod
    def print_summary(results: dict):
        """Gibt Zusammenfassung mehrerer Analysen aus"""
        print(f"\n{'='*80}")
        print("📊 ZUSAMMENFASSUNG")
        print(f"{'='*80}\n")
        
        total = len(results)
        spa_count = sum(1 for r in results.values() if r and r.is_spa)
        failed = sum(1 for r in results.values() if r is None)
        
        print(f"Gesamt analysiert: {total}")
        print(f"SPAs erkannt: {spa_count}")
        print(f"Keine SPA: {total - spa_count - failed}")
        print(f"Fehlgeschlagen: {failed}")
        
        print("\n📋 Details:\n")
        for url, result in results.items():
            if result:
                status = "✅ SPA" if result.is_spa else "❌ NO SPA"
                confidence = f"{result.confidence:.0%}"
                print(f"  {status:12} | {confidence:5} | {url}")
            else:
                print(f"  ❌ ERROR      | N/A   | {url}")
        
        print(f"\n{'='*80}")


async def main():
    """Haupt-Funktion mit CLI"""
    parser = argparse.ArgumentParser(
        description='🔍 SPA Detection Tool - Erkennt Single-Page Applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s https://react.dev
  %(prog)s https://example.com --no-interact
  %(prog)s https://vuejs.org --strategy navigation --max-actions 15
  %(prog)s https://angular.io --output report.json --verbose
  %(prog)s urls.txt --headless --output batch_report.json
  %(prog)s https://example.com --timeout 60000 --wait-time 5
        """
    )
    
    # Positional Arguments
    parser.add_argument(
        'url',
        help='URL oder Datei mit URLs (eine pro Zeile)'
    )
    
    # Interaction Options
    interaction_group = parser.add_argument_group('Interaktions-Optionen')
    interaction_group.add_argument(
        '--no-interact',
        action='store_true',
        help='Keine Interaktionen durchführen (nur initialer Load)'
    )
    interaction_group.add_argument(
        '--strategy',
        choices=['smart', 'random_walk', 'navigation','model_guided'],
        default='smart',
        help='Interaktionsstrategie (default: smart)'
    )
    interaction_group.add_argument(
        '--max-actions',
        type=int,
        default=10,
        help='Maximale Anzahl Interaktionen (default: 10)'
    )
    
    # Browser Options
    browser_group = parser.add_argument_group('Browser-Optionen')
    browser_group.add_argument(
        '--headless',
        action='store_true',
        help='Browser im Headless-Modus starten'
    )
    browser_group.add_argument(
        '--timeout',
        type=int,
        default=30000,
        help='Timeout in Millisekunden (default: 30000)'
    )
    browser_group.add_argument(
        '--wait-time',
        type=int,
        default=3,
        help='Wartezeit nach Load in Sekunden (default: 3)'
    )
    
    # Output Options
    output_group = parser.add_argument_group('Ausgabe-Optionen')
    output_group.add_argument(
        '--output', '-o',
        help='Ausgabe-Datei für JSON-Report'
    )
    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Ausführliche Logs ausgeben'
    )
    output_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Nur finale Ergebnisse ausgeben'
    )
    
    args = parser.parse_args()
    
    # Setup Logging
    if not args.quiet:
        setup_logging(args.verbose)
    
    logger = logging.getLogger(__name__)
    
    # Banner
    if not args.quiet:
        print("\n" + "="*80)
        print("🔍 SPA DETECTION TOOL v2.0")
        print("="*80 + "\n")
    
    # Parse URLs
    urls = []
    url_path = Path(args.url)
    
    if url_path.is_file():
        try:
            with open(url_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"📄 {len(urls)} URLs aus Datei geladen: {url_path}\n")
        except Exception as e:
            logger.error(f"❌ Fehler beim Lesen der URL-Datei: {e}")
            sys.exit(1)
    else:
        urls = [args.url]
    
    if not urls:
        logger.error("❌ Keine URLs zum Analysieren gefunden")
        sys.exit(1)
    
    # Führe Analyse durch
    try:
        async with SPADetectionTool(headless=args.headless, timeout=args.timeout) as tool:
            await tool.setup_browser()
            
            if len(urls) == 1:
                # Einzelne URL
                result = await tool.analyze_url(
                    urls[0],
                    interact=not args.no_interact,
                    interaction_strategy=args.strategy,
                    max_interactions=args.max_actions,
                    wait_time=args.wait_time
                )
                
                if result:
                    # Speichere Report
                    if args.output:
                        tool.save_report(result, args.output)
                    
                    # Exit-Code basierend auf Ergebnis
                    sys.exit(0 if result.is_spa else 1)
                else:
                    logger.error("❌ Analyse fehlgeschlagen")
                    sys.exit(2)
            
            else:
                # Mehrere URLs
                results = await tool.analyze_multiple_urls(
                    urls,
                    interact=not args.no_interact,
                    interaction_strategy=args.strategy,
                    max_interactions=args.max_actions,
                    wait_time=args.wait_time
                )
                
                # Zusammenfassung
                if not args.quiet:
                    tool.print_summary(results)
                
                # Speichere Combined Report
                if args.output:
                    try:
                        combined = {
                            "analyzed_at": datetime.now().isoformat(),
                            "total_urls": len(urls),
                            "spa_detected": sum(1 for r in results.values() if r and r.is_spa),
                            "results": {
                                url: SPAAnalyzer.export_report(r) if r else {"error": "Analysis failed"}
                                for url, r in results.items()
                            }
                        }
                        
                        output_file = Path(args.output)
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(output_file, 'w', encoding='utf-8') as f:
                            json.dump(combined, f, indent=2, ensure_ascii=False)
                        
                        print(f"\n💾 Combined Report gespeichert: {output_file}")
                        
                    except Exception as e:
                        logger.error(f"❌ Report-Speicherung fehlgeschlagen: {e}")
                
                # Exit-Code: 0 wenn mindestens eine SPA
                spa_found = any(r and r.is_spa for r in results.values())
                sys.exit(0 if spa_found else 1)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Abbruch durch Benutzer")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"\n❌ KRITISCHER FEHLER: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())