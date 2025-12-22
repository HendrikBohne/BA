"""
DOM XSS Trigger Strategies - Comparison Reporter
Erstellt detaillierte Vergleiche zwischen Strategien
"""
import logging
from typing import List, Dict, Optional
from datetime import datetime

from analysis.metrics import StrategyMetrics, ComparisonResult

logger = logging.getLogger(__name__)


class ComparisonReporter:
    """
    Erstellt detaillierte Strategie-Vergleiche.
    
    Funktionen:
    - Statistische Analyse
    - Ranking-Erstellung
    - Trend-Analyse über mehrere Runs
    """
    
    @staticmethod
    def create_comparison(
        metrics_list: List[StrategyMetrics],
        url: str = None
    ) -> ComparisonResult:
        """
        Erstellt ComparisonResult aus Liste von Metriken.
        
        Args:
            metrics_list: Liste von StrategyMetrics
            url: Gemeinsame URL (falls nicht in Metriken)
            
        Returns:
            ComparisonResult
        """
        url = url or (metrics_list[0].url if metrics_list else "unknown")
        
        return ComparisonResult(
            url=url,
            timestamp=datetime.now(),
            strategies=metrics_list
        )
    
    @staticmethod
    def calculate_improvements(
        baseline: StrategyMetrics,
        comparison: StrategyMetrics
    ) -> Dict:
        """
        Berechnet prozentuale Verbesserungen gegenüber Baseline.
        
        Args:
            baseline: Baseline-Metriken (z.B. Random Walk)
            comparison: Zu vergleichende Metriken
            
        Returns:
            Dictionary mit prozentualen Änderungen
        """
        def pct_change(old, new):
            if old == 0:
                return float('inf') if new > 0 else 0
            return ((new - old) / old) * 100
        
        return {
            'flows_change': pct_change(
                baseline.taint.total_flows,
                comparison.taint.total_flows
            ),
            'vulnerabilities_change': pct_change(
                baseline.taint.exploitable_flows,
                comparison.taint.exploitable_flows
            ),
            'efficiency_change': pct_change(
                baseline.flows_per_action,
                comparison.flows_per_action
            ),
            'coverage_change': pct_change(
                baseline.coverage.js_function_coverage,
                comparison.coverage.js_function_coverage
            ),
            'duration_change': pct_change(
                baseline.efficiency.total_duration_seconds,
                comparison.efficiency.total_duration_seconds
            )
        }
    
    @staticmethod
    def generate_summary_text(comparison: ComparisonResult) -> str:
        """
        Generiert Text-Zusammenfassung des Vergleichs.
        
        Args:
            comparison: ComparisonResult
            
        Returns:
            Formatierte Text-Zusammenfassung
        """
        lines = [
            "=" * 60,
            "STRATEGIE-VERGLEICH ZUSAMMENFASSUNG",
            "=" * 60,
            f"URL: {comparison.url}",
            f"Zeitpunkt: {comparison.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Strategien verglichen: {len(comparison.strategies)}",
            "",
            "-" * 60,
            "ERGEBNISSE:",
            "-" * 60,
        ]
        
        for strategy in comparison.strategies:
            lines.extend([
                f"\n{strategy.strategy_name}:",
                f"  Taint-Flows: {strategy.taint.total_flows}",
                f"  Vulnerabilities: {strategy.taint.exploitable_flows}",
                f"  Effizienz: {strategy.flows_per_action:.2f} Flows/Aktion",
                f"  Dauer: {strategy.efficiency.total_duration_seconds:.1f}s",
            ])
        
        # Rankings
        rankings = comparison.get_rankings()
        
        lines.extend([
            "",
            "-" * 60,
            "RANKINGS:",
            "-" * 60,
        ])
        
        for metric, strategy_ranks in rankings.items():
            lines.append(f"\n{metric}:")
            for strategy, rank in sorted(strategy_ranks.items(), key=lambda x: x[1]):
                lines.append(f"  {rank}. {strategy}")
        
        # Winner
        lines.extend([
            "",
            "-" * 60,
            "GEWINNER:",
            "-" * 60,
        ])
        
        for metric in ['flows_found', 'vulnerabilities', 'efficiency', 'coverage']:
            winner = comparison.get_winner(metric)
            lines.append(f"  {metric}: {winner or 'N/A'}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    @staticmethod
    def aggregate_runs(
        runs: List[ComparisonResult]
    ) -> Dict:
        """
        Aggregiert Ergebnisse über mehrere Runs.
        Berechnet Durchschnitte und Standardabweichungen.
        
        Args:
            runs: Liste von ComparisonResults
            
        Returns:
            Aggregierte Statistiken
        """
        if not runs:
            return {}
        
        # Sammle Metriken pro Strategie
        strategy_metrics = {}
        
        for run in runs:
            for strategy in run.strategies:
                name = strategy.strategy_name
                if name not in strategy_metrics:
                    strategy_metrics[name] = {
                        'flows': [],
                        'vulnerabilities': [],
                        'efficiency': [],
                        'duration': []
                    }
                
                strategy_metrics[name]['flows'].append(strategy.taint.total_flows)
                strategy_metrics[name]['vulnerabilities'].append(strategy.taint.exploitable_flows)
                strategy_metrics[name]['efficiency'].append(strategy.flows_per_action)
                strategy_metrics[name]['duration'].append(strategy.efficiency.total_duration_seconds)
        
        # Berechne Statistiken
        def calc_stats(values):
            if not values:
                return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
            
            import statistics
            return {
                'mean': statistics.mean(values),
                'std': statistics.stdev(values) if len(values) > 1 else 0,
                'min': min(values),
                'max': max(values)
            }
        
        aggregated = {}
        for name, metrics in strategy_metrics.items():
            aggregated[name] = {
                metric: calc_stats(values)
                for metric, values in metrics.items()
            }
        
        return {
            'run_count': len(runs),
            'strategies': aggregated
        }
