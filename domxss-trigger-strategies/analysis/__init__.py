"""
DOM XSS Trigger Strategies - Analysis Package
Auswertung von Taint-Flows, Coverage und Vulnerabilities
"""

from .coverage import CoverageAnalyzer, CoverageSnapshot
from .vulnerability import VulnerabilityDetector, ExploitabilityAnalysis
from .metrics import (
    StrategyMetrics,
    CoverageMetrics,
    TaintMetrics,
    EfficiencyMetrics,
    ComparisonResult
)

__all__ = [
    # Analyzers
    'CoverageAnalyzer',
    'CoverageSnapshot',
    'VulnerabilityDetector',
    'ExploitabilityAnalysis',
    
    # Metrics
    'StrategyMetrics',
    'CoverageMetrics',
    'TaintMetrics',
    'EfficiencyMetrics',
    'ComparisonResult',
]
