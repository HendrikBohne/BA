"""
DOM XSS Trigger Strategies - Taint Log Parser
Parst Foxhound Taint-Logs in strukturierte TaintFlow Objekte
"""
import re
import logging
from typing import List, Dict, Optional
from datetime import datetime
import uuid

from .taint_flow import (
    TaintFlow, TaintSource, TaintSink, PropagationStep,
    SourceType, SinkType, Severity
)

logger = logging.getLogger(__name__)


class TaintLogParser:
    """
    Parser für Foxhound Taint-Logs.
    
    Konvertiert rohe Log-Einträge in strukturierte TaintFlow Objekte.
    Unterstützt verschiedene Log-Formate (Foxhound, Pseudo-Tracking).
    """
    
    # Source-Pattern Mapping
    SOURCE_PATTERNS = {
        r'location\.hash': ('location.hash', SourceType.URL),
        r'location\.search': ('location.search', SourceType.URL),
        r'location\.pathname': ('location.pathname', SourceType.URL),
        r'location\.href': ('location.href', SourceType.URL),
        r'document\.URL': ('document.URL', SourceType.URL),
        r'document\.referrer': ('document.referrer', SourceType.URL),
        r'localStorage': ('localStorage', SourceType.STORAGE),
        r'sessionStorage': ('sessionStorage', SourceType.STORAGE),
        r'document\.cookie': ('document.cookie', SourceType.STORAGE),
        r'window\.name': ('window.name', SourceType.DOM),
        r'postMessage|message\.data': ('postMessage.data', SourceType.DOM),
        r'input\.value|\.value': ('input.value', SourceType.USER_INPUT),
    }
    
    # Sink-Pattern Mapping
    SINK_PATTERNS = {
        r'innerHTML': ('innerHTML', SinkType.HTML_INJECTION),
        r'outerHTML': ('outerHTML', SinkType.HTML_INJECTION),
        r'document\.write': ('document.write', SinkType.HTML_INJECTION),
        r'insertAdjacentHTML': ('insertAdjacentHTML', SinkType.HTML_INJECTION),
        r'\beval\b': ('eval', SinkType.JS_EXECUTION),
        r'\bFunction\b': ('Function', SinkType.JS_EXECUTION),
        r'setTimeout': ('setTimeout', SinkType.JS_EXECUTION),
        r'setInterval': ('setInterval', SinkType.JS_EXECUTION),
        r'location\.href\s*=': ('location.href', SinkType.URL_REDIRECT),
        r'location\.assign': ('location.assign', SinkType.URL_REDIRECT),
        r'location\.replace': ('location.replace', SinkType.URL_REDIRECT),
        r'window\.open': ('window.open', SinkType.URL_REDIRECT),
    }
    
    def __init__(self):
        self.parsed_flows: List[TaintFlow] = []
    
    def parse(self, logs: List[Dict]) -> List[TaintFlow]:
        """
        Parst eine Liste von Taint-Logs.
        
        Args:
            logs: Rohe Log-Einträge
            
        Returns:
            Liste von TaintFlow Objekten
        """
        self.parsed_flows = []
        
        if not logs:
            return []
        
        for log_entry in logs:
            flow = self._parse_entry(log_entry)
            if flow:
                self.parsed_flows.append(flow)
        
        # Deduplizierung
        unique_flows = self._deduplicate(self.parsed_flows)
        
        logger.info(f"📊 {len(logs)} Logs → {len(unique_flows)} unique Flows")
        
        return unique_flows
    
    def _parse_entry(self, entry: Dict) -> Optional[TaintFlow]:
        """Parst einen einzelnen Log-Eintrag"""
        
        if not entry:
            return None
        
        # Format 1: Pseudo-Tracking Flow (aus Browser)
        if entry.get('type') == 'flow':
            return self._parse_pseudo_flow(entry)
        
        # Format 2: Console-Log mit [TAINT] Prefix
        text = entry.get('text', '')
        if '[TAINT]' in text:
            return self._parse_console_log(entry)
        
        # Format 3: Foxhound native Format
        if 'source' in entry and 'sink' in entry:
            return self._parse_foxhound_native(entry)
        
        return None
    
    def _parse_pseudo_flow(self, entry: Dict) -> Optional[TaintFlow]:
        """Parst Pseudo-Tracking Flow aus Browser"""
        sink_name = entry.get('sink', '')
        value = entry.get('value', '')
        element = entry.get('element', '')
        
        # Sink identifizieren
        sink_info = self._identify_sink(sink_name)
        if not sink_info:
            return None
        
        sink = TaintSink(
            name=sink_info[0],
            type=sink_info[1],
            element=element
        )
        
        # Source aus Value ableiten (heuristisch)
        source_info = self._infer_source_from_value(value)
        
        source = TaintSource(
            name=source_info[0],
            type=source_info[1],
            value=value[:500] if value else ''
        )
        
        return TaintFlow(
            id=str(uuid.uuid4())[:8],
            source=source,
            sink=sink,
            timestamp=datetime.fromtimestamp(entry.get('timestamp', 0) / 1000)
                      if entry.get('timestamp') else datetime.now()
        )
    
    def _parse_console_log(self, entry: Dict) -> Optional[TaintFlow]:
        """Parst Console-Log mit [TAINT] Prefix"""
        text = entry.get('text', '')
        
        # Format: [TAINT] Source: location.hash = value
        # oder:   [TAINT] Sink: innerHTML = value
        
        source_match = re.search(r'\[TAINT\]\s*Source:\s*(\S+)\s*=\s*(.+)', text)
        sink_match = re.search(r'\[TAINT\]\s*Sink:\s*(\S+)\s*=\s*(.+)', text)
        
        if sink_match:
            sink_name = sink_match.group(1)
            value = sink_match.group(2)
            
            sink_info = self._identify_sink(sink_name)
            if not sink_info:
                return None
            
            sink = TaintSink(
                name=sink_info[0],
                type=sink_info[1]
            )
            
            # Source heuristisch ableiten
            source_info = self._infer_source_from_value(value)
            
            source = TaintSource(
                name=source_info[0],
                type=source_info[1],
                value=value[:500] if value else ''
            )
            
            return TaintFlow(
                id=str(uuid.uuid4())[:8],
                source=source,
                sink=sink,
                timestamp=datetime.now()
            )
        
        return None
    
    def _parse_foxhound_native(self, entry: Dict) -> Optional[TaintFlow]:
        """Parst natives Foxhound-Format"""
        source_data = entry.get('source', {})
        sink_data = entry.get('sink', {})
        propagation_data = entry.get('propagation', [])
        
        # Source
        source_info = self._identify_source(source_data.get('name', ''))
        if not source_info:
            source_info = ('unknown', SourceType.DOM)
        
        source = TaintSource(
            name=source_info[0],
            type=source_info[1],
            value=str(source_data.get('value', ''))[:500],
            location=source_data.get('location')
        )
        
        # Sink
        sink_info = self._identify_sink(sink_data.get('name', ''))
        if not sink_info:
            return None
        
        sink = TaintSink(
            name=sink_info[0],
            type=sink_info[1],
            element=sink_data.get('element'),
            location=sink_data.get('location')
        )
        
        # Propagation
        propagation = [
            PropagationStep(
                operation=step.get('operation', ''),
                input_value=str(step.get('input', ''))[:200],
                output_value=str(step.get('output', ''))[:200],
                location=step.get('location')
            )
            for step in propagation_data
        ]
        
        return TaintFlow(
            id=str(uuid.uuid4())[:8],
            source=source,
            sink=sink,
            propagation=propagation,
            timestamp=datetime.now()
        )
    
    def _identify_source(self, text: str) -> Optional[tuple]:
        """Identifiziert Source aus Text"""
        if not text:
            return None
        for pattern, info in self.SOURCE_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                return info
        return None
    
    def _identify_sink(self, text: str) -> Optional[tuple]:
        """Identifiziert Sink aus Text"""
        if not text:
            return None
        for pattern, info in self.SINK_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                return info
        return None
    
    def _infer_source_from_value(self, value: str) -> tuple:
        """
        Versucht Source aus dem Wert abzuleiten.
        """
        if not value:
            return ('unknown', SourceType.DOM)
        
        value = str(value)
        
        # URL-Parameter
        if re.search(r'[?&][^=]+=', value) or value.startswith('#'):
            return ('location.hash', SourceType.URL)
        
        # JSON-artig
        if value.startswith('{') or value.startswith('['):
            return ('localStorage', SourceType.STORAGE)
        
        # HTML-Tags
        if re.search(r'<[a-z]+[^>]*>', value, re.IGNORECASE):
            return ('user_input', SourceType.USER_INPUT)
        
        # Default
        return ('unknown', SourceType.DOM)
    
    def _deduplicate(self, flows: List[TaintFlow]) -> List[TaintFlow]:
        """Entfernt Duplikate basierend auf Source+Sink+Path"""
        seen = set()
        unique = []
        
        for flow in flows:
            key = (flow.source.name, flow.sink.name, len(flow.propagation))
            if key not in seen:
                seen.add(key)
                unique.append(flow)
        
        return unique
    
    def get_statistics(self) -> Dict:
        """Gibt Statistiken über geparste Flows zurück"""
        if not self.parsed_flows:
            return {'total': 0}
        
        return {
            'total': len(self.parsed_flows),
            'by_source_type': {
                st.value: len([f for f in self.parsed_flows if f.source.type == st])
                for st in SourceType
            },
            'by_sink_type': {
                st.value: len([f for f in self.parsed_flows if f.sink.type == st])
                for st in SinkType
            },
            'unique_source_sink_pairs': len(set(
                (f.source.name, f.sink.name) for f in self.parsed_flows
            ))
        }
