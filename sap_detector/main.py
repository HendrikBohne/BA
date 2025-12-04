"""
SPA Detection Tool - Main Entry Point
Command-Line Interface für SPA-Erkennung
"""
import asyncio
import argparse
import json
import sys
from pathlib import Path
from playwright.async_api import async_playwright

from spa_analyzer import SPAAnalyzer, SPAAnalysisResult


class SPADetectionTool:
    """Haupt-CLI Tool"""
    
    def __init__(self):
        self.browser = None
        self.context = None
        self.page = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()
    
    async def setup_browser(self, headless: bool = False):
        """Initialisiert Firefox Browser"""
        print("🦊 Starte Firefox...")
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.firefox.launch(
            headless=headless,
            args=['--disable-blink-features=AutomationControlled']
        )
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
        )
        self.page = await self.context.new_page()
        print("✅ Browser bereit\n")
    
    async def cleanup(self):
        """Räumt Browser-Ressourcen auf"""
        if self.page:
            await self.page.close()
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()
    
    async def analyze_url(self, url: str, 
                         interact: bool = True,
                         interaction_strategy: str = "random_walk",
                         max_interactions: int = 10,
                         wait_time: int = 3) -> SPAAnalysisResult:
        """
        Analysiert eine URL auf SPA-Eigenschaften
        
        Args:
            url: Zu analysierende URL
            interact: Interaktionen durchführen
            interaction_strategy: "random_walk" oder "navigation"
            max_interactions: Anzahl Interaktionen
            wait_time: Wartezeit nach Load in Sekunden
        """
        print(f"🌐 Lade URL: {url}")
        
        try:
            # Navigiere zur URL
            await self.page.goto(url, wait_until='networkidle', timeout=30000)
            print(f"✅ Seite geladen\n")
            
            # Warte auf initiales Rendering
            await asyncio.sleep(wait_time)
            
            # Erstelle Analyzer
            analyzer = SPAAnalyzer(self.page)
            
            # Führe Analyse durch
            result = await analyzer.analyze(
                interact=interact,
                interaction_strategy=interaction_strategy,
                max_interactions=max_interactions
            )
            
            return result
            
        except Exception as e:
            print(f"\n❌ FEHLER: {e}")
            raise
    
    async def analyze_multiple_urls(self, urls: list, **kwargs) -> dict:
        """Analysiert mehrere URLs"""
        results = {}
        
        for i, url in enumerate(urls, 1):
            print(f"\n{'='*80}")
            print(f"📊 Analyse {i}/{len(urls)}: {url}")
            print(f"{'='*80}\n")
            
            try:
                result = await self.analyze_url(url, **kwargs)
                results[url] = result
            except Exception as e:
                print(f"❌ Fehler bei {url}: {e}")
                results[url] = None
            
            # Neue Seite für nächste URL
            if i < len(urls):
                await self.page.close()
                self.page = await self.context.new_page()
        
        return results
    
    @staticmethod
    def save_report(result: SPAAnalysisResult, url: str, output_path: str):
        """Speichert Analyse-Report als JSON"""
        analyzer = SPAAnalyzer(None)  # Dummy für export_report
        report = analyzer.export_report(result)
        report['url'] = url
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Report gespeichert: {output_file}")


async def main():
    """Haupt-Funktion mit CLI-Argument-Parsing"""
    parser = argparse.ArgumentParser(
        description='🔍 SPA Detection Tool - Erkennt Single-Page Applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s https://example.com
  %(prog)s https://example.com --no-interact
  %(prog)s https://example.com --strategy navigation --max-actions 15
  %(prog)s https://example.com --output report.json
  %(prog)s urls.txt --headless
        """
    )
    
    parser.add_argument(
        'url',
        help='URL oder Datei mit URLs (eine pro Zeile)'
    )
    
    parser.add_argument(
        '--no-interact',
        action='store_true',
        help='Keine Interaktionen durchführen (nur initialer Load)'
    )
    
    parser.add_argument(
        '--strategy',
        choices=['random_walk', 'navigation'],
        default='random_walk',
        help='Interaktionsstrategie (default: random_walk)'
    )
    
    parser.add_argument(
        '--max-actions',
        type=int,
        default=10,
        help='Maximale Anzahl Interaktionen (default: 10)'
    )
    
    parser.add_argument(
        '--wait-time',
        type=int,
        default=3,
        help='Wartezeit nach Load in Sekunden (default: 3)'
    )
    
    parser.add_argument(
        '--headless',
        action='store_true',
        help='Browser im Headless-Modus starten'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Ausgabe-Datei für JSON-Report'
    )
    
    args = parser.parse_args()
    
    # Prüfe ob URL oder Datei
    urls = []
    if Path(args.url).is_file():
        with open(args.url, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"📄 {len(urls)} URLs aus Datei geladen\n")
    else:
        urls = [args.url]
    
    # Führe Analyse durch
    async with SPADetectionTool() as tool:
        await tool.setup_browser(headless=args.headless)
        
        if len(urls) == 1:
            # Einzelne URL
            result = await tool.analyze_url(
                urls[0],
                interact=not args.no_interact,
                interaction_strategy=args.strategy,
                max_interactions=args.max_actions,
                wait_time=args.wait_time
            )
            
            # Speichere Report wenn gewünscht
            if args.output:
                tool.save_report(result, urls[0], args.output)
            
            # Exit-Code basierend auf Ergebnis
            sys.exit(0 if result.is_spa else 1)
        
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
            print(f"\n{'='*80}")
            print("📊 ZUSAMMENFASSUNG")
            print(f"{'='*80}\n")
            
            spa_count = sum(1 for r in results.values() if r and r.is_spa)
            total = len(results)
            
            print(f"SPAs erkannt: {spa_count}/{total}")
            print("\nDetails:")
            for url, result in results.items():
                if result:
                    status = "✅ SPA" if result.is_spa else "❌ NO SPA"
                    print(f"  {status} - {url} ({result.confidence:.0%})")
                else:
                    print(f"  ❌ ERROR - {url}")
            
            # Speichere Combined Report
            if args.output:
                combined = {
                    url: SPAAnalyzer(None).export_report(r) if r else None
                    for url, r in results.items()
                }
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(combined, f, indent=2, ensure_ascii=False)
                print(f"\n💾 Combined Report gespeichert: {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Abbruch durch Benutzer")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ KRITISCHER FEHLER: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)