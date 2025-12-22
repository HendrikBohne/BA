"""
SPA Detection Tool - Detection Result Dataclass
Einheitliches Ergebnis-Format fÃ¼r alle Detektoren
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class DetectionResult:
    """Ergebnis eines einzelnen Detektors"""
    signal_name: str
    detected: bool
    confidence: float  # 0.0 - 1.0
    evidence: Dict[str, Any]
    description: str
    error: Optional[str] = None

    