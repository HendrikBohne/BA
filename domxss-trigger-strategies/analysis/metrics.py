"""
DOM XSS Trigger Strategies - Evaluation Metrics
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
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
        return self.js_functions_executed / max(1, self.js_functions_total)
    
    @property
    def js_line_coverage(self) -> float:
        return self.js_lines_executed / max(1, self.js_lines_total)
    
    @property
    def event_handler_coverage(self) -> float:
        return self.event_handlers_triggered / max(1, self.event_handlers_total)
    
    @property
    def dom_coverage(self) -> float:
        return self.dom_elements_interacted / max(1, self.dom_elements_total)


@dataclass
class TaintMetrics:
    """Taint-Flow Metriken"""
    total_flows: int = 0
    unique_flows: int = 0
    exploitable_flows: int = 0
    unique_source_sink_pairs: int = 0
    
    flows_from_url: int = 0
    flows_from_storage: int = 0
    flows_from_dom: int = 0
    flows_from_user_input: int = 0
    
    flows_to_html_injection: int = 0
    flows_to_js_execution: int = 0
    flows_to_url_redirect: int = 0
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


@dataclass
class EfficiencyMetrics:
    """Effizienz-Metriken"""
    total_duration_seconds: float = 0.0
    actions_performed: int = 0
    actions_successful: int = 0
    actions_failed: int = 0
    
    @property
    def success_rate(self) -> float:
        return self.actions_successful / max(1, self.actions_performed)
    
    @property
    def actions_per_second(self) -> float:
        return self.actions_performed / max(0.1, self.total_duration_seconds)


@dataclass
class StrategyMetrics:
    """Vollständige Metriken für eine Strategie"""
    strategy_name: str
    url: str
    run_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    coverage: CoverageMetrics = field(default_factory=CoverageMetrics)
    taint: TaintMetrics = field(default_factory=TaintMetrics)
    efficiency: EfficiencyMetrics = field(default_factory=EfficiencyMetrics)
    
    initial_dom_size: int = 0
    final_dom_size: int = 0
    max_dom_size: int = 0
    dom_states_visited: int = 0
    total_candidates_found: int = 0
    unique_candidates_executed: int = 0
    
    @property
    def dom_growth_ratio(self) -> float:
        return self.final_dom_size / max(1, self.initial_dom_size)
    
    @property
    def candidate_execution_rate(self) -> float:
        return self.unique_candidates_executed / max(1, self.total_candidates_found)
    
    @property
    def flows_per_action(self) -> float:
        return self.taint.total_flows / max(1, self.efficiency.actions_performed)
    
    @property
    def flows_per_second(self) -> float:
        return self.taint.total_flows / max(0.1, self.efficiency.total_duration_seconds)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'meta': {
                'strategy': self.strategy_name,
                'url': self.url,
                'run_id': self.run_id,
                'timestamp': self.timestamp.isoformat()
            },
            'coverage': {
                'js_function_coverage': self.coverage.js_function_coverage,
                'js_line_coverage': self.coverage.js_line_coverage,
                'dom_coverage': self.coverage.dom_coverage,
            },
            'taint': {
                'total_flows': self.taint.total_flows,
                'unique_flows': self.taint.unique_flows,
                'exploitable_flows': self.taint.exploitable_flows,
            },
            'efficiency': {
                'duration_seconds': self.efficiency.total_duration_seconds,
                'actions_performed': self.efficiency.actions_performed,
                'success_rate': self.efficiency.success_rate,
                'flows_per_action': self.flows_per_action,
            },
            'dom': {
                'initial_size': self.initial_dom_size,
                'final_size': self.final_dom_size,
                'growth_ratio': self.dom_growth_ratio,
            }
        }


@dataclass
class ComparisonResult:
    """Strategie-Vergleich"""
    url: str
    timestamp: datetime = field(default_factory=datetime.now)
    strategies: List[StrategyMetrics] = field(default_factory=list)
    
    def get_rankings(self) -> Dict[str, Dict[str, int]]:
        if not self.strategies:
            return {}
        
        rankings = {}
        metrics = [
            ('flows_found', lambda s: s.taint.total_flows),
            ('vulnerabilities', lambda s: s.taint.exploitable_flows),
            ('coverage', lambda s: s.coverage.js_function_coverage),
            ('efficiency', lambda s: s.flows_per_action),
        ]
        
        for name, extractor in metrics:
            sorted_strats = sorted(self.strategies, key=extractor, reverse=True)
            rankings[name] = {s.strategy_name: i + 1 for i, s in enumerate(sorted_strats)}
        
        return rankings
    
    def get_winner(self, metric: str = 'vulnerabilities') -> Optional[str]:
        rankings = self.get_rankings()
        if metric not in rankings:
            return None
        for name, rank in rankings[metric].items():
            if rank == 1:
                return name
        return None
