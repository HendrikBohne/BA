#!/usr/bin/env python3
"""
Dual-Browser Evaluation Script

Führt zwei separate Läufe durch:
1. Foxhound → Taint-Tracking (Security Impact)
2. Chromium → JS Byte Coverage (DevTools Coverage API)

Kombiniert die Ergebnisse in einem einheitlichen Evaluation-Report.
"""
import sys
import asyncio
import argparse
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict

from playwright.async_api import async_playwright

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class CoverageResult:
    """JavaScript Coverage Result from Chromium"""
    url: str
    total_bytes: int = 0
    used_bytes: int = 0
    coverage_percent: float = 0.0
    scripts_total: int = 0
    scripts_covered: int = 0
    duration_seconds: float = 0.0
    script_details: List[Dict] = field(default_factory=list)


@dataclass
class CombinedResult:
    """Combined result from both browsers"""
    url: str
    strategy: str
    timestamp: str
    
    # From Chromium
    coverage: CoverageResult = None
    
    # From Foxhound (loaded from findings file)
    taint_flows: int = 0
    confirmed_bugs: int = 0
    foxhound_duration: float = 0.0
    
    # Combined metrics
    total_duration: float = 0.0


class ChromiumCoverageCollector:
    """
    Collects JavaScript coverage using Chromium DevTools Protocol.
    """
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self._client = None
    
    async def start(self):
        """Start Chromium browser"""
        logger.info("🌐 Starte Chromium für Coverage-Messung...")
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=['--disable-web-security']  # Für Cross-Origin Scripts
        )
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
        )
        
        self.page = await self.context.new_page()
        logger.info("✅ Chromium bereit")
    
    async def stop(self):
        """Stop browser"""
        if self.page:
            await self.page.close()
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("✅ Chromium gestoppt")
    
    async def start_coverage(self):
        """Start collecting JS coverage via CDP"""
        try:
            self._client = await self.context.new_cdp_session(self.page)
            
            await self._client.send("Profiler.enable")
            await self._client.send("Profiler.startPreciseCoverage", {
                "callCount": True,
                "detailed": True
            })
            
            logger.info("📊 Coverage-Sammlung gestartet")
            return True
            
        except Exception as e:
            logger.error(f"❌ Coverage-Start fehlgeschlagen: {e}")
            return False
    
    async def stop_coverage(self) -> Dict:
        """Stop collecting and return coverage data"""
        try:
            result = await self._client.send("Profiler.takePreciseCoverage")
            await self._client.send("Profiler.stopPreciseCoverage")
            await self._client.send("Profiler.disable")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Coverage-Stop fehlgeschlagen: {e}")
            return {}
    
    def parse_coverage(self, result: Dict, url: str) -> CoverageResult:
        """Parse CDP coverage result"""
        total_bytes = 0
        used_bytes = 0
        script_details = []
        
        for script in result.get('result', []):
            script_url = script.get('url', '')
            
            # Skip internal/empty scripts
            if not script_url or script_url.startswith('chrome://'):
                continue
            
            functions = script.get('functions', [])
            
            script_total = 0
            script_used = 0
            
            for func in functions:
                for range_info in func.get('ranges', []):
                    start = range_info.get('startOffset', 0)
                    end = range_info.get('endOffset', 0)
                    count = range_info.get('count', 0)
                    
                    range_bytes = end - start
                    script_total += range_bytes
                    
                    if count > 0:
                        script_used += range_bytes
            
            if script_total > 0:
                total_bytes += script_total
                used_bytes += script_used
                
                script_details.append({
                    'url': script_url[:100],
                    'total_bytes': script_total,
                    'used_bytes': script_used,
                    'coverage_percent': round(script_used / script_total * 100, 1)
                })
        
        coverage_percent = (used_bytes / total_bytes * 100) if total_bytes > 0 else 0
        
        return CoverageResult(
            url=url,
            total_bytes=total_bytes,
            used_bytes=used_bytes,
            coverage_percent=round(coverage_percent, 2),
            scripts_total=len(script_details),
            scripts_covered=sum(1 for s in script_details if s['coverage_percent'] > 0),
            script_details=script_details
        )
    
    async def measure_coverage(
        self, 
        url: str, 
        interaction_time: int = 30,
        scroll: bool = True,
        click_elements: bool = True
    ) -> CoverageResult:
        """
        Navigate to URL, interact, and measure JS coverage.
        
        Args:
            url: Target URL
            interaction_time: Seconds to interact with page
            scroll: Whether to scroll the page
            click_elements: Whether to click interactive elements
        """
        import time
        start_time = time.time()
        
        logger.info(f"📊 Messe Coverage: {url}")
        
        try:
            # Start coverage BEFORE navigation
            await self.start_coverage()
            
            # Navigate
            await self.page.goto(url, wait_until='networkidle', timeout=60000)
            logger.info("✅ Seite geladen")
            
            # Wait for initial JS execution
            await asyncio.sleep(3)
            
            # Interact to trigger more code
            if scroll:
                await self._scroll_page()
            
            if click_elements:
                await self._click_interactive_elements(max_clicks=20)
            
            # Wait for remaining interaction time
            elapsed = time.time() - start_time
            remaining = max(0, interaction_time - elapsed)
            if remaining > 0:
                logger.info(f"⏳ Warte {remaining:.0f}s für weitere JS-Ausführung...")
                await asyncio.sleep(remaining)
            
            # Stop and collect coverage
            result = await self.stop_coverage()
            coverage = self.parse_coverage(result, url)
            coverage.duration_seconds = time.time() - start_time
            
            logger.info(f"📊 Coverage: {coverage.coverage_percent:.1f}% "
                       f"({coverage.used_bytes:,}/{coverage.total_bytes:,} bytes)")
            
            return coverage
            
        except Exception as e:
            logger.error(f"❌ Coverage-Messung fehlgeschlagen: {e}")
            return CoverageResult(
                url=url,
                duration_seconds=time.time() - start_time
            )
    
    async def _scroll_page(self):
        """Scroll page to trigger lazy-loading"""
        try:
            await self.page.evaluate("""
                async () => {
                    const step = window.innerHeight / 2;
                    for (let i = 0; i < 10; i++) {
                        window.scrollBy(0, step);
                        await new Promise(r => setTimeout(r, 300));
                    }
                    window.scrollTo(0, 0);
                }
            """)
            logger.debug("Scrolling abgeschlossen")
        except Exception as e:
            logger.debug(f"Scroll error: {e}")
    
    async def _click_interactive_elements(self, max_clicks: int = 20):
        """Click on interactive elements to trigger code"""
        try:
            # Find clickable elements
            clickables = await self.page.evaluate("""
                () => {
                    const elements = document.querySelectorAll(
                        'button, [role="button"], a[href^="#"], ' +
                        '[onclick], .tab, .accordion, [data-toggle]'
                    );
                    
                    return Array.from(elements)
                        .filter(el => {
                            const rect = el.getBoundingClientRect();
                            return rect.width > 0 && rect.height > 0 &&
                                   rect.top >= 0 && rect.top < window.innerHeight;
                        })
                        .slice(0, 50)
                        .map((el, i) => ({
                            index: i,
                            tag: el.tagName.toLowerCase(),
                            text: (el.textContent || '').slice(0, 30)
                        }));
                }
            """)
            
            clicks = 0
            for el in clickables[:max_clicks]:
                try:
                    selector = f"{el['tag']}:has-text(\"{el['text'][:20]}\")" if el['text'] else el['tag']
                    await self.page.click(selector, timeout=2000)
                    clicks += 1
                    await asyncio.sleep(0.3)
                except:
                    continue
            
            logger.debug(f"{clicks} Elemente geklickt")
            
        except Exception as e:
            logger.debug(f"Click error: {e}")


class DualBrowserEvaluator:
    """
    Orchestrates dual-browser evaluation:
    1. Run Foxhound for taint-tracking
    2. Run Chromium for coverage
    3. Combine results
    """
    
    def __init__(self, output_dir: Path, foxhound_path: str = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.foxhound_path = foxhound_path
        self.results: List[CombinedResult] = []
    
    async def run_foxhound(self, url: str, strategy: str, max_actions: int, passive: bool):
        """Run Foxhound for taint-tracking (calls main.py)"""
        import subprocess
        import os
        
        logger.info(f"🦊 Starte Foxhound für: {url}")
        
        env = os.environ.copy()
        if self.foxhound_path:
            env['FOXHOUND_PATH'] = self.foxhound_path
        
        cmd = [
            'xvfb-run', '-a', 'python', 'main.py',
            url,
            '--strategy', strategy,
            '--max-actions', str(max_actions),
            '--headless',
            '--output', str(self.output_dir)
        ]
        
        if passive:
            cmd.append('--passive')
        
        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=300  # 5 min timeout
            )
            
            if result.returncode == 0:
                logger.info("✅ Foxhound-Lauf abgeschlossen")
            else:
                logger.warning(f"⚠️ Foxhound beendet mit Code {result.returncode}")
                if result.stderr:
                    logger.debug(f"Stderr: {result.stderr[:500]}")
            
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("❌ Foxhound-Timeout (5min)")
            return False
        except Exception as e:
            logger.error(f"❌ Foxhound-Fehler: {e}")
            return False
    
    def load_foxhound_results(self, url: str, strategy: str) -> Dict:
        """Load results from Foxhound findings file"""
        import re
        
        # Generate filename like main.py does
        name = re.sub(r'^https?://', '', url)
        name = re.sub(r'[^\w\-.]', '_', name)[:50]
        
        findings_file = self.output_dir / f"findings_{strategy}_{name}.json"
        
        if not findings_file.exists():
            logger.warning(f"⚠️ Keine Findings-Datei gefunden: {findings_file}")
            return {}
        
        try:
            with open(findings_file) as f:
                data = json.load(f)
            
            # Count confirmed bugs (critical sinks with high confidence)
            critical_sinks = ['innerhtml', 'outerhtml', 'eval', 'document.write', 
                            'script.src', 'function', 'setinterval', 'settimeout']
            
            confirmed = 0
            for finding in data.get('findings', []):
                sink = finding.get('sink', '').lower()
                conf = finding.get('confidence', 0)
                
                if any(s in sink for s in critical_sinks) and conf >= 0.7:
                    confirmed += 1
            
            return {
                'total_flows': data.get('total_findings', 0),
                'confirmed_bugs': confirmed,
                'findings': data.get('findings', [])
            }
            
        except Exception as e:
            logger.error(f"❌ Fehler beim Laden der Findings: {e}")
            return {}
    
    async def evaluate_url(
        self,
        url: str,
        strategy: str = "random_walk",
        max_actions: int = 50,
        passive: bool = True,
        interaction_time: int = 30
    ) -> CombinedResult:
        """
        Run complete dual-browser evaluation for one URL.
        """
        import time
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🔬 DUAL-BROWSER EVALUATION")
        logger.info(f"   URL: {url}")
        logger.info(f"   Strategie: {strategy}")
        logger.info(f"   Passiv: {'Ja' if passive else 'Nein'}")
        logger.info(f"{'='*60}\n")
        
        result = CombinedResult(
            url=url,
            strategy=strategy,
            timestamp=datetime.now().isoformat()
        )
        
        total_start = time.time()
        
        # 1. Run Foxhound
        foxhound_start = time.time()
        await self.run_foxhound(url, strategy, max_actions, passive)
        result.foxhound_duration = time.time() - foxhound_start
        
        # Load Foxhound results
        foxhound_data = self.load_foxhound_results(url, strategy)
        result.taint_flows = foxhound_data.get('total_flows', 0)
        result.confirmed_bugs = foxhound_data.get('confirmed_bugs', 0)
        
        # 2. Run Chromium for coverage
        collector = ChromiumCoverageCollector(headless=True)
        try:
            await collector.start()
            coverage = await collector.measure_coverage(
                url, 
                interaction_time=interaction_time
            )
            result.coverage = coverage
        finally:
            await collector.stop()
        
        result.total_duration = time.time() - total_start
        
        # Log summary
        logger.info(f"\n📊 ERGEBNIS für {url}")
        logger.info(f"   JS Coverage: {result.coverage.coverage_percent:.1f}%")
        logger.info(f"   Taint-Flows: {result.taint_flows}")
        logger.info(f"   Bestätigte Bugs: {result.confirmed_bugs}")
        logger.info(f"   Gesamtzeit: {result.total_duration:.1f}s")
        
        self.results.append(result)
        return result
    
    async def evaluate_urls(
        self,
        urls: List[str],
        strategy: str = "random_walk",
        max_actions: int = 50,
        passive: bool = True
    ):
        """Evaluate multiple URLs"""
        for i, url in enumerate(urls, 1):
            logger.info(f"\n[{i}/{len(urls)}] Evaluiere: {url}")
            await self.evaluate_url(url, strategy, max_actions, passive)
    
    def print_summary(self):
        """Print evaluation summary"""
        if not self.results:
            print("Keine Ergebnisse vorhanden")
            return
        
        from statistics import mean, median
        
        print(f"\n{'='*70}")
        print("📊 EVALUATION SUMMARY (DUAL-BROWSER)")
        print(f"{'='*70}")
        
        # Group by strategy
        strategies = sorted(set(r.strategy for r in self.results))
        urls = sorted(set(r.url for r in self.results))
        
        print(f"\n📈 ÜBERSICHT")
        print(f"   URLs analysiert: {len(urls)}")
        print(f"   Strategien: {', '.join(strategies)}")
        print(f"   Gesamtzeit: {sum(r.total_duration for r in self.results):.1f}s")
        
        # Coverage stats
        coverages = [r.coverage.coverage_percent for r in self.results if r.coverage]
        if coverages:
            print(f"\n📊 JS BYTE COVERAGE (Chromium)")
            print(f"   Mean: {mean(coverages):.1f}%")
            print(f"   Median: {median(coverages):.1f}%")
            print(f"   Min: {min(coverages):.1f}%")
            print(f"   Max: {max(coverages):.1f}%")
        
        # Security stats
        total_flows = sum(r.taint_flows for r in self.results)
        total_bugs = sum(r.confirmed_bugs for r in self.results)
        urls_with_bugs = len(set(r.url for r in self.results if r.confirmed_bugs > 0))
        
        print(f"\n🔒 SECURITY IMPACT (Foxhound)")
        print(f"   Taint-Flows gesamt: {total_flows}")
        print(f"   Bestätigte DOM-XSS: {total_bugs}")
        print(f"   URLs mit Bugs: {urls_with_bugs}")
        
        # Efficiency
        total_time_hours = sum(r.total_duration for r in self.results) / 3600
        if total_time_hours > 0:
            print(f"\n⚡ EFFIZIENZ")
            print(f"   Bugs/Stunde: {total_bugs / total_time_hours:.2f}")
            print(f"   Flows/Stunde: {total_flows / total_time_hours:.2f}")
        
        # Per-strategy breakdown (if multiple strategies)
        if len(strategies) > 1:
            print(f"\n{'='*70}")
            print("🏁 STRATEGIE-VERGLEICH")
            print(f"{'='*70}")
            print(f"{'Strategie':<20} {'Coverage':>10} {'Flows':>8} {'Bugs':>6} {'Zeit':>10}")
            print(f"{'-'*54}")
            
            for strat in strategies:
                strat_results = [r for r in self.results if r.strategy == strat]
                strat_cov = mean([r.coverage.coverage_percent for r in strat_results if r.coverage] or [0])
                strat_flows = sum(r.taint_flows for r in strat_results)
                strat_bugs = sum(r.confirmed_bugs for r in strat_results)
                strat_time = sum(r.total_duration for r in strat_results)
                
                print(f"{strat:<20} {strat_cov:>9.1f}% {strat_flows:>8} {strat_bugs:>6} {strat_time:>9.1f}s")
            
            print(f"{'-'*54}")
            
            # Winner
            best_bugs = max(strategies, key=lambda s: sum(r.confirmed_bugs for r in self.results if r.strategy == s))
            best_flows = max(strategies, key=lambda s: sum(r.taint_flows for r in self.results if r.strategy == s))
            
            print(f"\n🏆 Beste Strategie (Bugs): {best_bugs}")
            print(f"🏆 Beste Strategie (Flows): {best_flows}")
        
        # Per-URL table
        print(f"\n{'='*70}")
        print("📋 DETAIL-ERGEBNISSE")
        print(f"{'='*70}")
        print(f"{'URL':<30} {'Strategie':<15} {'Cov':>6} {'Flows':>6} {'Bugs':>5} {'Zeit':>7}")
        print(f"{'-'*70}")
        
        for r in self.results:
            url_short = r.url[:28] + '..' if len(r.url) > 30 else r.url
            cov = f"{r.coverage.coverage_percent:.0f}%" if r.coverage else "N/A"
            print(f"{url_short:<30} {r.strategy:<15} {cov:>6} {r.taint_flows:>6} {r.confirmed_bugs:>5} {r.total_duration:>6.1f}s")
        
        print(f"{'='*70}\n")
    
    def export_results(self, filename: str = "dual_browser_evaluation.json"):
        """Export results to JSON"""
        filepath = self.output_dir / filename
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'total_urls': len(self.results),
            'results': []
        }
        
        for r in self.results:
            export_data['results'].append({
                'url': r.url,
                'strategy': r.strategy,
                'timestamp': r.timestamp,
                'coverage': {
                    'percent': r.coverage.coverage_percent if r.coverage else 0,
                    'total_bytes': r.coverage.total_bytes if r.coverage else 0,
                    'used_bytes': r.coverage.used_bytes if r.coverage else 0,
                    'scripts_total': r.coverage.scripts_total if r.coverage else 0,
                } if r.coverage else None,
                'security': {
                    'taint_flows': r.taint_flows,
                    'confirmed_bugs': r.confirmed_bugs,
                },
                'duration': {
                    'foxhound_seconds': r.foxhound_duration,
                    'total_seconds': r.total_duration,
                }
            })
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"📄 Ergebnisse exportiert: {filepath}")
    
    def export_csv(self, filename: str = "dual_browser_evaluation.csv"):
        """Export results to CSV"""
        import csv
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'url', 'strategy', 
                'coverage_percent', 'js_bytes_total', 'js_bytes_used',
                'taint_flows', 'confirmed_bugs',
                'foxhound_duration_s', 'total_duration_s'
            ])
            
            for r in self.results:
                writer.writerow([
                    r.url,
                    r.strategy,
                    f"{r.coverage.coverage_percent:.1f}" if r.coverage else 0,
                    r.coverage.total_bytes if r.coverage else 0,
                    r.coverage.used_bytes if r.coverage else 0,
                    r.taint_flows,
                    r.confirmed_bugs,
                    f"{r.foxhound_duration:.1f}",
                    f"{r.total_duration:.1f}"
                ])
        
        logger.info(f"📄 CSV exportiert: {filepath}")


async def main():
    parser = argparse.ArgumentParser(
        description='🔬 Dual-Browser Evaluation: Foxhound (Taint) + Chromium (Coverage)'
    )
    
    parser.add_argument('target', help='URL oder Datei mit URLs')
    parser.add_argument('--strategy', '-s', default='random_walk',
                       choices=['random_walk', 'model_guided', 'dom_maximizer'])
    parser.add_argument('--compare-all', '-c', action='store_true',
                       help='Vergleiche alle Strategien')
    parser.add_argument('--max-actions', '-m', type=int, default=50)
    parser.add_argument('--passive', action='store_true', 
                       help='Passiv-Modus (keine Payloads)')
    parser.add_argument('--foxhound-path', help='Pfad zu Foxhound')
    parser.add_argument('--output', '-o', default='results')
    parser.add_argument('--interaction-time', type=int, default=30,
                       help='Interaktionszeit für Coverage (Sekunden)')
    
    args = parser.parse_args()
    
    # Parse URLs
    target = Path(args.target)
    if target.is_file():
        with open(target) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        urls = [args.target]
    
    if not urls:
        logger.error("❌ Keine URLs angegeben")
        sys.exit(1)
    
    # Run evaluation
    evaluator = DualBrowserEvaluator(
        output_dir=Path(args.output),
        foxhound_path=args.foxhound_path or '/opt/foxhound-3/foxhound'
    )
    
    try:
        # Determine strategies to run
        if args.compare_all:
            strategies = ['random_walk', 'model_guided', 'dom_maximizer']
            logger.info(f"🏁 COMPARE-ALL: Vergleiche {len(strategies)} Strategien")
        else:
            strategies = [args.strategy]
        
        # Run evaluation for each URL and strategy combination
        for url in urls:
            for strategy in strategies:
                logger.info(f"\n[{urls.index(url)+1}/{len(urls)}] URL: {url}, Strategie: {strategy}")
                await evaluator.evaluate_url(
                    url,
                    strategy=strategy,
                    max_actions=args.max_actions,
                    passive=args.passive
                )
        
        evaluator.print_summary()
        evaluator.export_results()
        evaluator.export_csv()
        
    except KeyboardInterrupt:
        print("\n⚠️ Abbruch durch Benutzer")
    except Exception as e:
        logger.error(f"❌ Fehler: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())