"""
DOM XSS Trigger Strategies - Evaluation Package
Wissenschaftliche Evaluation und Benchmarking
"""

from .benchmark_runner import BenchmarkRunner, BenchmarkConfig, BenchmarkResult
from .strategy_comparator import StrategyComparator, StatisticalTest

__all__ = [
    'BenchmarkRunner',
    'BenchmarkConfig',
    'BenchmarkResult',
    'StrategyComparator',
    'StatisticalTest',
]
