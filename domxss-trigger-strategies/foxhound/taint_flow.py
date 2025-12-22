"""
DOM XSS Trigger Strategies - Taint Flow Data Structures
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SourceType(Enum):
    URL = "url"
    STORAGE = "storage"
    DOM = "dom"
    API = "api"
    USER_INPUT = "user_input"


class SinkType(Enum):
    HTML_INJECTION = "html_injection"
    JS_EXECUTION = "js_execution"
    URL_REDIRECT = "url_redirect"
    ATTRIBUTE = "attribute"
    STYLE = "style"


@dataclass
class TaintSource:
    name: str
    type: SourceType
    value: str
    location: Optional[str] = None


@dataclass
class TaintSink:
    name: str
    type: SinkType
    element: Optional[str] = None
    location: Optional[str] = None


@dataclass
class PropagationStep:
    operation: str
    input_value: str
    output_value: str
    location: Optional[str] = None


@dataclass
class TaintFlow:
    id: str
    source: TaintSource
    sink: TaintSink
    propagation: List[PropagationStep] = field(default_factory=list)
    
    url: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    triggered_by_action: Optional[str] = None
    
    is_exploitable: bool = False
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    
    def __hash__(self):
        return hash((self.source.name, self.sink.name, len(self.propagation)))
    
    @property
    def path_summary(self) -> str:
        ops = " → ".join([self.source.name] + 
                        [s.operation for s in self.propagation] +
                        [self.sink.name])
        return ops
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source': {'name': self.source.name, 'type': self.source.type.value, 'value': self.source.value[:100]},
            'sink': {'name': self.sink.name, 'type': self.sink.type.value, 'element': self.sink.element},
            'propagation': [{'operation': s.operation} for s in self.propagation],
            'url': self.url,
            'is_exploitable': self.is_exploitable,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'path_summary': self.path_summary
        }


@dataclass
class XSSVulnerability:
    id: str
    flows: List[TaintFlow]
    severity: Severity
    category: str
    source_summary: str
    sink_summary: str
    
    proof_of_concept: Optional[str] = None
    cwe_id: str = "CWE-79"
    owasp_category: str = "A03:2021"
    remediation: str = ""
    url: str = ""
    found_at: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'severity': self.severity.value,
            'category': self.category,
            'source': self.source_summary,
            'sink': self.sink_summary,
            'proof_of_concept': self.proof_of_concept,
            'cwe_id': self.cwe_id,
            'remediation': self.remediation,
            'url': self.url,
            'confidence': self.confidence,
            'flow_count': len(self.flows)
        }
