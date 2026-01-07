"""
DOM XSS Trigger Strategies - Metrics
Datenstrukturen für Strategie-Metriken und Vergleiche
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class CoverageMetrics:
    """Code-Coverage Metriken"""
    js_functions_total: int = 0
    js_functions_executed: int = 0
    js_lines_total: int = 0
    js_lines_executed: int = 0
    event_handlers_total: int = 0
    event_handlers_triggered: int = 0
    dom_elements_total: int = 0
    dom_elements_interacted: int = 0
    
    @property
    def js_function_coverage(self) -> float:
        if self.js_functions_total == 0:
            return 0.0
        return self.js_functions_executed / self.js_functions_total
    
    @property
    def js_line_coverage(self) -> float:
        if self.js_lines_total == 0:
            return 0.0
        return self.js_lines_executed / self.js_lines_total
    
    @property
    def event_handler_coverage(self) -> float:
        if self.event_handlers_total == 0:
            return 0.0
        return self.event_handlers_triggered / self.event_handlers_total
    
    @property
    def dom_coverage(self) -> float:
        if self.dom_elements_total == 0:
            return 0.0
        return self.dom_elements_interacted / self.dom_elements_total
    
    def to_dict(self) -> Dict:
        return {
            'js_functions_total': self.js_functions_total,
            'js_functions_executed': self.js_functions_executed,
            'js_function_coverage': self.js_function_coverage,
            'js_lines_total': self.js_lines_total,
            'js_lines_executed': self.js_lines_executed,
            'js_line_coverage': self.js_line_coverage,
            'event_handlers_total': self.event_handlers_total,
            'event_handlers_triggered': self.event_handlers_triggered,
            'event_handler_coverage': self.event_handler_coverage,
            'dom_elements_total': self.dom_elements_total,
            'dom_elements_interacted': self.dom_elements_interacted,
            'dom_coverage': self.dom_coverage
        }


@dataclass
class TaintMetrics:
    """Taint-Flow Metriken"""
    total_flows: int = 0
    unique_flows: int = 0
    exploitable_flows: int = 0
    unique_source_sink_pairs: int = 0
    
    # Nach Source-Typ
    flows_from_url: int = 0
    flows_from_storage: int = 0
    flows_from_dom: int = 0
    flows_from_user_input: int = 0
    
    # Nach Sink-Typ
    flows_to_html_injection: int = 0
    flows_to_js_execution: int = 0
    flows_to_url_redirect: int = 0
    
    # Nach Severity
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'total_flows': self.total_flows,
            'unique_flows': self.unique_flows,
            'exploitable_flows': self.exploitable_flows,
            'unique_source_sink_pairs': self.unique_source_sink_pairs,
            'by_source': {
                'url': self.flows_from_url,
                'storage': self.flows_from_storage,
                'dom': self.flows_from_dom,
                'user_input': self.flows_from_user_input
            },
            'by_sink': {
                'html_injection': self.flows_to_html_injection,
                'js_execution': self.flows_to_js_execution,
                'url_redirect': self.flows_to_url_redirect
            },
            'by_severity': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count
            }
        }


@dataclass
class EfficiencyMetrics:
    """Effizienz-Metriken"""
    total_duration_seconds: float = 0.0
    actions_performed: int = 0
    actions_successful: int = 0
    actions_failed: int = 0
    
    @property
    def actions_per_second(self) -> float:
        if self.total_duration_seconds == 0:
            return 0.0
        return self.actions_performed / self.total_duration_seconds
    
    @property
    def success_rate(self) -> float:
        if self.actions_performed == 0:
            return 0.0
        return self.actions_successful / self.actions_performed
    
    def to_dict(self) -> Dict:
        return {
            'duration_seconds': self.total_duration_seconds,
            'actions_performed': self.actions_performed,
            'actions_successful': self.actions_successful,
            'actions_failed': self.actions_failed,
            'actions_per_second': self.actions_per_second,
            'success_rate': self.success_rate
        }


@dataclass
class StrategyMetrics:
    """Gesamtmetriken einer Strategie-Ausführung"""
    strategy_name: str
    url: str
    run_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Sub-Metriken
    coverage: CoverageMetrics = field(default_factory=CoverageMetrics)
    taint: TaintMetrics = field(default_factory=TaintMetrics)
    efficiency: EfficiencyMetrics = field(default_factory=EfficiencyMetrics)
    
    # DOM-Metriken
    initial_dom_size: int = 0
    final_dom_size: int = 0
    max_dom_size: int = 0
    dom_states_visited: int = 0
    
    # Candidate-Metriken
    total_candidates_found: int = 0
    unique_candidates_executed: int = 0
    
    @property
    def dom_growth_ratio(self) -> float:
        if self.initial_dom_size == 0:
            return 1.0
        return self.final_dom_size / self.initial_dom_size
    
    @property
    def candidate_execution_rate(self) -> float:
        if self.total_candidates_found == 0:
            return 0.0
        return self.unique_candidates_executed / self.total_candidates_found
    
    @property
    def flows_per_action(self) -> float:
        if self.efficiency.actions_performed == 0:
            return 0.0
        return self.taint.total_flows / self.efficiency.actions_performed
    
    @property
    def flows_per_second(self) -> float:
        if self.efficiency.total_duration_seconds == 0:
            return 0.0
        return self.taint.total_flows / self.efficiency.total_duration_seconds
    
    def to_dict(self) -> Dict:
        return {
            'strategy_name': self.strategy_name,
            'url': self.url,
            'run_id': self.run_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'coverage': self.coverage.to_dict() if self.coverage else {},
            'taint': self.taint.to_dict() if self.taint else {},
            'efficiency': self.efficiency.to_dict() if self.efficiency else {},
            'dom': {
                'initial_size': self.initial_dom_size,
                'final_size': self.final_dom_size,
                'max_size': self.max_dom_size,
                'growth_ratio': self.dom_growth_ratio,
                'states_visited': self.dom_states_visited
            },
            'candidates': {
                'total_found': self.total_candidates_found,
                'unique_executed': self.unique_candidates_executed,
                'execution_rate': self.candidate_execution_rate
            },
            'derived': {
                'flows_per_action': self.flows_per_action,
                'flows_per_second': self.flows_per_second
            }
        }


@dataclass
class ComparisonResult:
    """Ergebnis eines Strategie-Vergleichs"""
    url: str
    timestamp: datetime
    strategies: List[StrategyMetrics] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'strategy_count': len(self.strategies),
            'strategies': [s.to_dict() for s in self.strategies]
        }
    
    def to_summary_table(self) -> List[Dict]:
        """Erstellt Zusammenfassungs-Tabelle für alle Strategien"""
        rows = []
        
        for strategy in self.strategies:
            row = {
                'strategy': strategy.strategy_name,
                'flows': strategy.taint.total_flows if strategy.taint else 0,
                'vulnerabilities': strategy.taint.exploitable_flows if strategy.taint else 0,
                'coverage': f"{(strategy.coverage.dom_coverage * 100):.1f}%" if strategy.coverage else "0.0%",
                'efficiency': f"{strategy.flows_per_action:.2f}",
                'duration': f"{strategy.efficiency.total_duration_seconds:.1f}s" if strategy.efficiency else "0.0s"
            }
            rows.append(row)
        
        return rows
    
    def get_rankings(self) -> Dict[str, Dict[str, int]]:
        """Erstellt Rankings für verschiedene Metriken"""
        if not self.strategies:
            return {}
        
        metrics_to_rank = {
            'flows_found': lambda s: s.taint.total_flows if s.taint else 0,
            'vulnerabilities': lambda s: s.taint.exploitable_flows if s.taint else 0,
            'coverage': lambda s: s.coverage.dom_coverage if s.coverage else 0,
            'efficiency': lambda s: s.flows_per_action
        }
        
        rankings = {}
        
        for metric_name, getter in metrics_to_rank.items():
            # Sortiere nach Metrik (absteigend)
            sorted_strategies = sorted(
                self.strategies,
                key=getter,
                reverse=True
            )
            
            rankings[metric_name] = {
                s.strategy_name: rank + 1
                for rank, s in enumerate(sorted_strategies)
            }
        
        return rankings
    
    def get_winner(self, metric: str) -> Optional[str]:
        """Gibt den Gewinner für eine bestimmte Metrik zurück"""
        rankings = self.get_rankings()
        
        if metric not in rankings:
            return None
        
        metric_rankings = rankings[metric]
        
        # Finde Strategie mit Rang 1
        for strategy_name, rank in metric_rankings.items():
            if rank == 1:
                return strategy_name
        
        return None
