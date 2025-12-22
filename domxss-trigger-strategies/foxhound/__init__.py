"""
DOM XSS Trigger Strategies - Foxhound Package
Foxhound Browser Integration für Taint-Tracking
"""

from .taint_flow import (
    TaintFlow,
    TaintSource,
    TaintSink,
    PropagationStep,
    XSSVulnerability,
    SourceType,
    SinkType,
    Severity
)
from .controller import FoxhoundController
from .taint_parser import TaintLogParser

__all__ = [
    # Data Classes
    'TaintFlow',
    'TaintSource',
    'TaintSink',
    'PropagationStep',
    'XSSVulnerability',
    
    # Enums
    'SourceType',
    'SinkType',
    'Severity',
    
    # Controller & Parser
    'FoxhoundController',
    'TaintLogParser',
]
