"""
DOM XSS Trigger Strategies - Strategy Comparator
Statistische Vergleiche zwischen Strategien
"""
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum
import statistics

logger = logging.getLogger(__name__)


class StatisticalTest(Enum):
    """Verfügbare statistische Tests"""
    WILCOXON = "wilcoxon"
    MANN_WHITNEY = "mann_whitney"
    T_TEST = "t_test"
    PAIRED_T_TEST = "paired_t_test"


@dataclass
class ComparisonMetric:
    """Einzelner Vergleich zwischen zwei Strategien"""
    metric_name: str
    strategy_a: str
    strategy_b: str
    mean_a: float
    mean_b: float
    std_a: float
    std_b: float
    p_value: Optional[float] = None
    effect_size: Optional[float] = None
    is_significant: bool = False
    winner: Optional[str] = None


class StrategyComparator:
    """
    Führt statistische Vergleiche zwischen Strategien durch.
    
    Features:
    - Paarweise Vergleiche
    - Mehrere statistische Tests
    - Effect Size Berechnung
    - Signifikanz-Prüfung
    """
    
    def __init__(self, significance_level: float = 0.05):
        """
        Args:
            significance_level: Alpha für Signifikanz-Test (default: 0.05)
        """
        self.significance_level = significance_level
    
    def compare_all(
        self,
        results: Dict[str, List[float]],
        metric_name: str = "flows",
        test: StatisticalTest = StatisticalTest.MANN_WHITNEY
    ) -> List[ComparisonMetric]:
        """
        Vergleicht alle Strategie-Paare.
        
        Args:
            results: Dict mit {strategy_name: [values]}
            metric_name: Name der Metrik
            test: Statistischer Test
            
        Returns:
            Liste von ComparisonMetric
        """
        comparisons = []
        strategies = list(results.keys())
        
        for i, strategy_a in enumerate(strategies):
            for strategy_b in strategies[i+1:]:
                comparison = self.compare_pair(
                    results[strategy_a],
                    results[strategy_b],
                    strategy_a,
                    strategy_b,
                    metric_name,
                    test
                )
                comparisons.append(comparison)
        
        return comparisons
    
    def compare_pair(
        self,
        values_a: List[float],
        values_b: List[float],
        name_a: str,
        name_b: str,
        metric_name: str,
        test: StatisticalTest = StatisticalTest.MANN_WHITNEY
    ) -> ComparisonMetric:
        """
        Vergleicht zwei Strategien.
        
        Args:
            values_a: Werte von Strategie A
            values_b: Werte von Strategie B
            name_a: Name Strategie A
            name_b: Name Strategie B
            metric_name: Name der Metrik
            test: Statistischer Test
            
        Returns:
            ComparisonMetric
        """
        # Grundlegende Statistiken
        mean_a = statistics.mean(values_a) if values_a else 0
        mean_b = statistics.mean(values_b) if values_b else 0
        std_a = statistics.stdev(values_a) if len(values_a) > 1 else 0
        std_b = statistics.stdev(values_b) if len(values_b) > 1 else 0
        
        # Statistischer Test
        p_value = self._run_test(values_a, values_b, test)
        
        # Effect Size (Cohen's d)
        effect_size = self._calculate_effect_size(values_a, values_b)
        
        # Signifikanz und Winner bestimmen
        is_significant = p_value is not None and p_value < self.significance_level
        
        winner = None
        if is_significant:
            winner = name_a if mean_a > mean_b else name_b
        
        return ComparisonMetric(
            metric_name=metric_name,
            strategy_a=name_a,
            strategy_b=name_b,
            mean_a=mean_a,
            mean_b=mean_b,
            std_a=std_a,
            std_b=std_b,
            p_value=p_value,
            effect_size=effect_size,
            is_significant=is_significant,
            winner=winner
        )
    
    def _run_test(
        self,
        values_a: List[float],
        values_b: List[float],
        test: StatisticalTest
    ) -> Optional[float]:
        """Führt statistischen Test durch"""
        if len(values_a) < 2 or len(values_b) < 2:
            return None
        
        try:
            # Versuche scipy zu importieren
            from scipy import stats
            
            if test == StatisticalTest.MANN_WHITNEY:
                _, p_value = stats.mannwhitneyu(values_a, values_b, alternative='two-sided')
            elif test == StatisticalTest.WILCOXON:
                if len(values_a) == len(values_b):
                    _, p_value = stats.wilcoxon(values_a, values_b)
                else:
                    return None
            elif test == StatisticalTest.T_TEST:
                _, p_value = stats.ttest_ind(values_a, values_b)
            elif test == StatisticalTest.PAIRED_T_TEST:
                if len(values_a) == len(values_b):
                    _, p_value = stats.ttest_rel(values_a, values_b)
                else:
                    return None
            else:
                return None
            
            return float(p_value)
            
        except ImportError:
            logger.warning("scipy nicht installiert - keine statistischen Tests möglich")
            return None
        except Exception as e:
            logger.error(f"Test fehlgeschlagen: {e}")
            return None
    
    def _calculate_effect_size(
        self,
        values_a: List[float],
        values_b: List[float]
    ) -> Optional[float]:
        """
        Berechnet Cohen's d Effect Size.
        
        Interpretation:
        - |d| < 0.2: negligible
        - 0.2 <= |d| < 0.5: small
        - 0.5 <= |d| < 0.8: medium
        - |d| >= 0.8: large
        """
        if len(values_a) < 2 or len(values_b) < 2:
            return None
        
        mean_a = statistics.mean(values_a)
        mean_b = statistics.mean(values_b)
        
        var_a = statistics.variance(values_a)
        var_b = statistics.variance(values_b)
        
        # Pooled standard deviation
        n_a = len(values_a)
        n_b = len(values_b)
        
        pooled_std = ((((n_a - 1) * var_a) + ((n_b - 1) * var_b)) / (n_a + n_b - 2)) ** 0.5
        
        if pooled_std == 0:
            return 0.0
        
        return (mean_a - mean_b) / pooled_std
    
    def get_summary(self, comparisons: List[ComparisonMetric]) -> str:
        """Generiert Text-Zusammenfassung der Vergleiche"""
        lines = [
            "=" * 70,
            "STRATEGIE-VERGLEICH (Statistische Analyse)",
            "=" * 70,
            f"Signifikanz-Level: α = {self.significance_level}",
            "",
        ]
        
        for comp in comparisons:
            sig_marker = "***" if comp.is_significant else ""
            
            lines.extend([
                f"\n{comp.strategy_a} vs {comp.strategy_b} ({comp.metric_name}):",
                f"  {comp.strategy_a}: μ = {comp.mean_a:.2f}, σ = {comp.std_a:.2f}",
                f"  {comp.strategy_b}: μ = {comp.mean_b:.2f}, σ = {comp.std_b:.2f}",
            ])
            
            if comp.p_value is not None:
                lines.append(f"  p-value: {comp.p_value:.4f} {sig_marker}")
            
            if comp.effect_size is not None:
                effect_label = self._interpret_effect_size(comp.effect_size)
                lines.append(f"  Effect Size (Cohen's d): {comp.effect_size:.3f} ({effect_label})")
            
            if comp.winner:
                lines.append(f"  🏆 Winner: {comp.winner}")
        
        lines.append("\n" + "=" * 70)
        
        return "\n".join(lines)
    
    def _interpret_effect_size(self, d: float) -> str:
        """Interpretiert Effect Size"""
        d = abs(d)
        if d < 0.2:
            return "negligible"
        elif d < 0.5:
            return "small"
        elif d < 0.8:
            return "medium"
        else:
            return "large"
    
    def create_ranking(
        self,
        results: Dict[str, List[float]],
        metric_name: str = "flows"
    ) -> List[Tuple[str, float, int]]:
        """
        Erstellt Ranking basierend auf Durchschnittswerten.
        
        Args:
            results: Dict mit {strategy_name: [values]}
            metric_name: Name der Metrik
            
        Returns:
            Liste von (strategy_name, mean_value, rank) Tupeln
        """
        means = [
            (name, statistics.mean(values) if values else 0)
            for name, values in results.items()
        ]
        
        # Sortiere absteigend
        sorted_means = sorted(means, key=lambda x: x[1], reverse=True)
        
        return [
            (name, mean, rank + 1)
            for rank, (name, mean) in enumerate(sorted_means)
        ]
    
    def export_results(
        self,
        comparisons: List[ComparisonMetric]
    ) -> Dict:
        """Exportiert Ergebnisse als Dictionary"""
        return {
            'significance_level': self.significance_level,
            'comparisons': [
                {
                    'metric': c.metric_name,
                    'strategy_a': c.strategy_a,
                    'strategy_b': c.strategy_b,
                    'mean_a': c.mean_a,
                    'mean_b': c.mean_b,
                    'std_a': c.std_a,
                    'std_b': c.std_b,
                    'p_value': c.p_value,
                    'effect_size': c.effect_size,
                    'is_significant': c.is_significant,
                    'winner': c.winner
                }
                for c in comparisons
            ]
        }
