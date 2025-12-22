"""
DOM XSS Trigger Strategies - JSON Reporter
Generiert JSON-Reports für Analyse-Ergebnisse
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Union

from analysis.metrics import StrategyMetrics, ComparisonResult

logger = logging.getLogger(__name__)


class JSONReporter:
    """
    Generiert JSON-Reports.
    
    Unterstützt:
    - Einzelne Strategie-Metriken
    - Strategie-Vergleiche
    - Vulnerability-Listen
    """
    
    @staticmethod
    def save_metrics(metrics: StrategyMetrics, output_path: Union[str, Path]):
        """
        Speichert StrategyMetrics als JSON.
        
        Args:
            metrics: StrategyMetrics Objekt
            output_path: Ziel-Dateipfad
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report = {
            'report_type': 'strategy_metrics',
            'generated_at': datetime.now().isoformat(),
            'metrics': metrics.to_dict()
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"📄 JSON-Report gespeichert: {output_path}")
    
    @staticmethod
    def save_comparison(comparison: ComparisonResult, output_path: Union[str, Path]):
        """
        Speichert ComparisonResult als JSON.
        
        Args:
            comparison: ComparisonResult Objekt
            output_path: Ziel-Dateipfad
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report = {
            'report_type': 'strategy_comparison',
            'generated_at': datetime.now().isoformat(),
            'url': comparison.url,
            'comparison_timestamp': comparison.timestamp.isoformat(),
            'strategies': [s.to_dict() for s in comparison.strategies],
            'rankings': comparison.get_rankings(),
            'summary_table': comparison.to_summary_table(),
            'winners': {
                metric: comparison.get_winner(metric)
                for metric in ['flows_found', 'vulnerabilities', 'coverage', 'efficiency']
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"📄 Comparison-Report gespeichert: {output_path}")
    
    @staticmethod
    def save_vulnerabilities(vulnerabilities: list, output_path: Union[str, Path]):
        """
        Speichert Vulnerability-Liste als JSON.
        
        Args:
            vulnerabilities: Liste von XSSVulnerability Objekten
            output_path: Ziel-Dateipfad
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report = {
            'report_type': 'vulnerabilities',
            'generated_at': datetime.now().isoformat(),
            'total_count': len(vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in vulnerabilities]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"📄 Vulnerability-Report gespeichert: {output_path}")
    
    @staticmethod
    def load_metrics(input_path: Union[str, Path]) -> dict:
        """Lädt JSON-Report"""
        with open(input_path, 'r', encoding='utf-8') as f:
            return json.load(f)
