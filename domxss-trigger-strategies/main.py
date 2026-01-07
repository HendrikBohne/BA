#!/usr/bin/env python3
"""
DOM XSS Trigger Strategies - Main CLI Entry Point
Automatisierte Erkennung von DOM-basierten XSS in Single-Page Applications
"""
import sys
import asyncio
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Lokale Imports
from utils.logging_config import setup_logging, get_logger
from strategies import STRATEGIES, StrategyResult
from foxhound.controller import FoxhoundController
from foxhound.taint_parser import TaintLogParser
from analysis.vulnerability import VulnerabilityDetector
from analysis.coverage import CoverageAnalyzer
from analysis.metrics import StrategyMetrics, ComparisonResult
from reporting.json_reporter import JSONReporter
from reporting.html_reporter import HTMLReporter
from reporting.comparison import ComparisonReporter

logger = get_logger(__name__)


class DOMXSSAnalyzer:
    """
    Hauptklasse für DOM XSS Analyse.
    Koordiniert Strategien, Foxhound und Analyse.
    """
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.foxhound = None
        self.taint_parser = TaintLogParser()
        self.vuln_detector = VulnerabilityDetector()
        self.coverage_analyzer = CoverageAnalyzer()
        
    async def setup(self, foxhound_path: str = None, headless: bool = False):
        """Initialisiert Foxhound Browser"""
        logger.info("🦊 Initialisiere Foxhound Browser...")
        
        self.foxhound = FoxhoundController(
            foxhound_path=foxhound_path,
            headless=headless,
            config=self.config.get('foxhound', {})
        )
        
        await self.foxhound.start()
        logger.info("✅ Foxhound bereit")
    
    async def cleanup(self):
        """Räumt Ressourcen auf"""
        if self.foxhound:
            await self.foxhound.stop()
            logger.info("✅ Foxhound gestoppt")
    
    async def analyze_url(
        self,
        url: str,
        strategy_name: str = "model_guided",
        max_actions: int = 50
    ) -> StrategyMetrics:
        """
        Analysiert eine URL mit der gewählten Strategie.
        
        Args:
            url: Zu analysierende URL
            strategy_name: Name der Strategie
            max_actions: Maximale Anzahl Interaktionen
            
        Returns:
            StrategyMetrics mit allen Ergebnissen
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"🔍 Analysiere: {url}")
        logger.info(f"📋 Strategie: {strategy_name}")
        logger.info(f"{'='*60}\n")
        
        # Strategie instantiieren
        if strategy_name not in STRATEGIES:
            raise ValueError(f"Unbekannte Strategie: {strategy_name}. "
                           f"Verfügbar: {list(STRATEGIES.keys())}")
        
        strategy_class = STRATEGIES[strategy_name]
        strategy = strategy_class(config={
            'max_actions': max_actions,
            **self.config.get('strategies', {}).get(strategy_name, {})
        })
        
        # Navigiere zur URL
        success = await self.foxhound.navigate(url)
        page = self.foxhound.page
        
        if not page:
            logger.error(f"❌ Konnte {url} nicht laden")
            return None
        
        # Starte Taint-Tracking
        await self.foxhound.start_taint_tracking()
        
        # Führe Strategie aus
        result: StrategyResult = await strategy.execute(page, url)
        
        # Sammle Taint-Logs
        taint_logs = await self.foxhound.get_taint_logs()
        
        # Parse Taint-Flows
        taint_flows = self.taint_parser.parse(taint_logs)
        result.taint_flows = taint_flows
        
        logger.info(f"\n📊 Gefundene Taint-Flows: {len(taint_flows)}")
        
        # Analysiere Vulnerabilities
        vulnerabilities = self.vuln_detector.analyze(taint_flows)
        result.vulnerabilities = vulnerabilities
        
        exploitable = [v for v in vulnerabilities if v.confidence >= 0.7]
        logger.info(f"🚨 Potentielle Vulnerabilities: {len(vulnerabilities)}")
        logger.info(f"⚠️  Exploitable (confidence >= 0.7): {len(exploitable)}")
        
        # Coverage analysieren (falls verfügbar)
        coverage = await self.coverage_analyzer.analyze(page)
        
        # Erstelle Metriken
        metrics = self._create_metrics(result, coverage)
        
        return metrics
    
    async def compare_strategies(
        self,
        url: str,
        strategies: list = None,
        max_actions: int = 50
    ) -> ComparisonResult:
        """
        Vergleicht alle Strategien auf einer URL.
        
        Args:
            url: Zu analysierende URL
            strategies: Liste der Strategien (default: alle)
            max_actions: Maximale Aktionen pro Strategie
            
        Returns:
            ComparisonResult mit Vergleichsdaten
        """
        strategies = strategies or list(STRATEGIES.keys())
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🏁 STRATEGIE-VERGLEICH")
        logger.info(f"🌐 URL: {url}")
        logger.info(f"📋 Strategien: {', '.join(strategies)}")
        logger.info(f"{'='*60}\n")
        
        results = []
        
        for strategy_name in strategies:
            logger.info(f"\n--- {strategy_name.upper()} ---\n")
            
            # Neue Browser-Session für faire Vergleiche
            await self.foxhound.new_context()
            
            metrics = await self.analyze_url(url, strategy_name, max_actions)
            
            if metrics:
                results.append(metrics)
        
        # Erstelle Vergleich
        comparison = ComparisonResult(
            url=url,
            timestamp=datetime.now(),
            strategies=results
        )
        
        # Zeige Zusammenfassung
        self._print_comparison_summary(comparison)
        
        return comparison
    
    def _create_metrics(self, result: StrategyResult, coverage: dict) -> StrategyMetrics:
        """Erstellt StrategyMetrics aus StrategyResult"""
        from analysis.metrics import (
            StrategyMetrics, CoverageMetrics, TaintMetrics, EfficiencyMetrics
        )
        from foxhound.taint_flow import SourceType, SinkType, Severity
        
        metrics = StrategyMetrics(
            strategy_name=result.strategy_name,
            url=result.url,
            run_id=f"{result.strategy_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=result.started_at
        )
        
        # Efficiency
        metrics.efficiency = EfficiencyMetrics(
            total_duration_seconds=result.duration_seconds,
            actions_performed=result.actions_performed,
            actions_successful=result.actions_successful,
            actions_failed=result.actions_failed
        )
        
        # DOM Metriken
        metrics.initial_dom_size = result.initial_dom_size
        metrics.final_dom_size = result.final_dom_size
        metrics.max_dom_size = result.max_dom_size_reached
        metrics.dom_states_visited = result.dom_states_visited
        
        # Candidates
        metrics.total_candidates_found = result.total_candidates_found
        metrics.unique_candidates_executed = result.unique_candidates_executed
        
        # Taint Metriken
        flows = result.taint_flows or []
        vulns = result.vulnerabilities or []
        
        metrics.taint = TaintMetrics(
            total_flows=len(flows),
            unique_flows=len(set(flows)),
            exploitable_flows=len([v for v in vulns if v.confidence >= 0.7]),
            unique_source_sink_pairs=len(set((f.source.name, f.sink.name) for f in flows)) if flows else 0,
            # Nach Source
            flows_from_url=len([f for f in flows if f.source.type == SourceType.URL]),
            flows_from_storage=len([f for f in flows if f.source.type == SourceType.STORAGE]),
            flows_from_dom=len([f for f in flows if f.source.type == SourceType.DOM]),
            flows_from_user_input=len([f for f in flows if f.source.type == SourceType.USER_INPUT]),
            # Nach Sink
            flows_to_html_injection=len([f for f in flows if f.sink.type == SinkType.HTML_INJECTION]),
            flows_to_js_execution=len([f for f in flows if f.sink.type == SinkType.JS_EXECUTION]),
            flows_to_url_redirect=len([f for f in flows if f.sink.type == SinkType.URL_REDIRECT]),
            # Nach Severity
            critical_count=len([v for v in vulns if v.severity == Severity.CRITICAL]),
            high_count=len([v for v in vulns if v.severity == Severity.HIGH]),
            medium_count=len([v for v in vulns if v.severity == Severity.MEDIUM]),
            low_count=len([v for v in vulns if v.severity == Severity.LOW])
        )
        
        # Coverage (falls vorhanden)
        if coverage:
            metrics.coverage = CoverageMetrics(
                js_functions_total=coverage.get('functions_total', 0),
                js_functions_executed=coverage.get('functions_executed', 0),
                js_lines_total=coverage.get('lines_total', 0),
                js_lines_executed=coverage.get('lines_executed', 0),
                event_handlers_total=coverage.get('handlers_total', 0),
                event_handlers_triggered=coverage.get('handlers_triggered', 0),
                dom_elements_total=coverage.get('dom_total', 0),
                dom_elements_interacted=coverage.get('dom_interacted', 0)
            )
        
        return metrics
    
    def _print_comparison_summary(self, comparison: ComparisonResult):
        """Gibt Vergleichs-Zusammenfassung aus"""
        print(f"\n{'='*70}")
        print("📊 VERGLEICHS-ERGEBNIS")
        print(f"{'='*70}")
        
        table = comparison.to_summary_table()
        
        if not table:
            print("Keine Ergebnisse verfügbar")
            return
        
        # Header
        print(f"\n{'Strategie':<25} {'Flows':>8} {'Vulns':>8} {'Coverage':>10} {'Eff.':>8} {'Zeit':>10}")
        print("-" * 70)
        
        for row in table:
            print(f"{row['strategy']:<25} {row['flows']:>8} {row['vulnerabilities']:>8} "
                  f"{row['coverage']:>10} {row['efficiency']:>8} {row['duration']:>10}")
        
        # Winner
        winner = comparison.get_winner('vulnerabilities')
        if winner:
            print(f"\n🏆 Beste Strategie (nach Vulnerabilities): {winner}")
        
        print(f"{'='*70}\n")


async def main():
    """CLI Entry Point"""
    parser = argparse.ArgumentParser(
        description='🔍 DOM XSS Trigger Strategies - Automatisierte XSS-Erkennung für SPAs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s https://target-spa.com
  %(prog)s https://target-spa.com --strategy random_walk
  %(prog)s https://target-spa.com --compare-all
  %(prog)s urls.txt --output results/ --strategy model_guided
  %(prog)s https://target-spa.com --max-actions 100 --verbose
        """
    )
    
    # Positional
    parser.add_argument(
        'target',
        help='Ziel-URL oder Datei mit URLs (eine pro Zeile)'
    )
    
    # Strategie-Optionen
    strategy_group = parser.add_argument_group('Strategie-Optionen')
    strategy_group.add_argument(
        '--strategy', '-s',
        choices=list(STRATEGIES.keys()),
        default='model_guided',
        help='Interaktionsstrategie (default: model_guided)'
    )
    strategy_group.add_argument(
        '--compare-all', '-c',
        action='store_true',
        help='Führe alle Strategien aus und vergleiche'
    )
    strategy_group.add_argument(
        '--max-actions', '-m',
        type=int,
        default=50,
        help='Maximale Aktionen pro URL (default: 50)'
    )
    
    # Foxhound-Optionen
    foxhound_group = parser.add_argument_group('Foxhound-Optionen')
    foxhound_group.add_argument(
        '--foxhound-path',
        help='Pfad zur Foxhound-Installation'
    )
    foxhound_group.add_argument(
        '--headless',
        action='store_true',
        help='Browser im Headless-Modus'
    )
    
    # Output-Optionen
    output_group = parser.add_argument_group('Ausgabe-Optionen')
    output_group.add_argument(
        '--output', '-o',
        help='Ausgabeverzeichnis für Reports'
    )
    output_group.add_argument(
        '--format', '-f',
        choices=['json', 'html', 'both'],
        default='both',
        help='Report-Format (default: both)'
    )
    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Ausführliche Ausgabe'
    )
    output_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Nur Ergebnisse ausgeben'
    )
    
    args = parser.parse_args()
    
    # Logging Setup
    log_level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    setup_logging(level=log_level)
    
    # Banner
    if not args.quiet:
        print("\n" + "="*60)
        print("🔍 DOM XSS TRIGGER STRATEGIES")
        print("   Automatisierte XSS-Erkennung für SPAs")
        print("="*60 + "\n")
    
    # Parse URLs
    target_path = Path(args.target)
    urls = []
    
    if target_path.is_file():
        with open(target_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"📄 {len(urls)} URLs aus Datei geladen")
    else:
        urls = [args.target]
    
    if not urls:
        logger.error("❌ Keine URLs angegeben")
        sys.exit(1)
    
    # Output-Verzeichnis
    output_dir = Path(args.output) if args.output else Path('results')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Analyzer initialisieren
    analyzer = DOMXSSAnalyzer()
    
    try:
        await analyzer.setup(
            foxhound_path=args.foxhound_path,
            headless=args.headless
        )
        
        all_results = []
        
        for url in urls:
            if args.compare_all:
                # Vergleiche alle Strategien
                comparison = await analyzer.compare_strategies(
                    url=url,
                    max_actions=args.max_actions
                )
                all_results.append(comparison)
                
                # Reports generieren
                if args.format in ['json', 'both']:
                    JSONReporter.save_comparison(comparison, output_dir / f"comparison_{url_to_filename(url)}.json")
                if args.format in ['html', 'both']:
                    HTMLReporter.save_comparison(comparison, output_dir / f"comparison_{url_to_filename(url)}.html")
            else:
                # Einzelne Strategie
                metrics = await analyzer.analyze_url(
                    url=url,
                    strategy_name=args.strategy,
                    max_actions=args.max_actions
                )
                
                if metrics:
                    all_results.append(metrics)
                    
                    # Reports generieren
                    if args.format in ['json', 'both']:
                        JSONReporter.save_metrics(metrics, output_dir / f"{args.strategy}_{url_to_filename(url)}.json")
                    if args.format in ['html', 'both']:
                        HTMLReporter.save_metrics(metrics, output_dir / f"{args.strategy}_{url_to_filename(url)}.html")
        
        # Zusammenfassung
        if not args.quiet:
            print(f"\n✅ Analyse abgeschlossen")
            print(f"📁 Reports gespeichert in: {output_dir.absolute()}")
        
        # Exit-Code basierend auf Vulnerabilities
        total_vulns = sum(
            r.taint.exploitable_flows if hasattr(r, 'taint') else 0
            for r in all_results
        )
        sys.exit(0 if total_vulns == 0 else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Abbruch durch Benutzer")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Fehler: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)
    finally:
        await analyzer.cleanup()


def url_to_filename(url: str) -> str:
    """Konvertiert URL zu sicherem Dateinamen"""
    import re
    # Entferne Protokoll
    name = re.sub(r'^https?://', '', url)
    # Ersetze unsichere Zeichen
    name = re.sub(r'[^\w\-.]', '_', name)
    # Kürze
    return name[:50]


if __name__ == "__main__":
    asyncio.run(main())
