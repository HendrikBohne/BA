"""
DOM XSS Trigger Strategies - Taint Log Parser
"""
import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from .taint_flow import TaintFlow, TaintSource, TaintSink, PropagationStep, SourceType, SinkType

logger = logging.getLogger(__name__)


class TaintLogParser:
    """Parser für Foxhound Taint-Logs"""
    
    PATTERNS = {
        'foxhound_flow': re.compile(r'TAINT:\s*(?P<source>\S+)\s*->\s*(?P<sink>\S+)', re.I),
        'innerHTML': re.compile(r'\[TAINT\]\s*innerHTML:\s*(?P<element>\S+)?\s*(?P<value>.+)?', re.I),
        'eval': re.compile(r'\[TAINT\]\s*eval:\s*(?P<value>.+)', re.I),
    }
    
    SOURCE_TYPES = {
        'location': SourceType.URL, 'hash': SourceType.URL, 'search': SourceType.URL,
        'localStorage': SourceType.STORAGE, 'sessionStorage': SourceType.STORAGE,
        'postMessage': SourceType.DOM, 'input': SourceType.USER_INPUT,
    }
    
    SINK_TYPES = {
        'innerHTML': SinkType.HTML_INJECTION, 'outerHTML': SinkType.HTML_INJECTION,
        'document.write': SinkType.HTML_INJECTION, 'eval': SinkType.JS_EXECUTION,
        'Function': SinkType.JS_EXECUTION, 'setTimeout': SinkType.JS_EXECUTION,
        'location': SinkType.URL_REDIRECT, 'href': SinkType.URL_REDIRECT,
    }
    
    def __init__(self):
        self._flow_counter = 0
        
    def parse_logs(self, logs: List[Dict[str, Any]]) -> List[TaintFlow]:
        """Parst Log-Einträge zu TaintFlows"""
        flows = []
        
        for log in logs:
            try:
                flow = self._parse_single_log(log)
                if flow:
                    flows.append(flow)
            except Exception as e:
                logger.debug(f"Log-Parse-Fehler: {e}")
        
        unique = self._deduplicate(flows)
        logger.info(f"📊 {len(unique)} unique Flows (von {len(logs)} Logs)")
        return unique
    
    def _parse_single_log(self, log: Dict[str, Any]) -> Optional[TaintFlow]:
        if isinstance(log, dict) and 'sink' in log:
            return self._parse_dict_log(log)
        
        text = str(log.get('text', log) if isinstance(log, dict) else log)
        return self._parse_text_log(text)
    
    def _parse_dict_log(self, log: Dict[str, Any]) -> Optional[TaintFlow]:
        self._flow_counter += 1
        sink_name = log['sink']
        
        return TaintFlow(
            id=f"flow_{self._flow_counter}",
            source=TaintSource(
                name=log.get('source', 'user_input'),
                type=self._categorize_source(log.get('source', '')),
                value=str(log.get('value', ''))[:200]
            ),
            sink=TaintSink(
                name=sink_name,
                type=self._categorize_sink(sink_name),
                element=log.get('element')
            )
        )
    
    def _parse_text_log(self, text: str) -> Optional[TaintFlow]:
        for pattern_name, pattern in self.PATTERNS.items():
            match = pattern.search(text)
            if match:
                self._flow_counter += 1
                
                if pattern_name == 'innerHTML':
                    return TaintFlow(
                        id=f"flow_{self._flow_counter}",
                        source=TaintSource("user_input", SourceType.USER_INPUT, match.group('value') or ''),
                        sink=TaintSink("innerHTML", SinkType.HTML_INJECTION, match.group('element'))
                    )
                elif pattern_name == 'eval':
                    return TaintFlow(
                        id=f"flow_{self._flow_counter}",
                        source=TaintSource("user_input", SourceType.USER_INPUT, match.group('value') or ''),
                        sink=TaintSink("eval", SinkType.JS_EXECUTION)
                    )
                elif pattern_name == 'foxhound_flow':
                    src = match.group('source')
                    snk = match.group('sink')
                    return TaintFlow(
                        id=f"flow_{self._flow_counter}",
                        source=TaintSource(src, self._categorize_source(src), ""),
                        sink=TaintSink(snk, self._categorize_sink(snk))
                    )
        return None
    
    def _categorize_source(self, name: str) -> SourceType:
        for key, stype in self.SOURCE_TYPES.items():
            if key.lower() in name.lower():
                return stype
        return SourceType.USER_INPUT
    
    def _categorize_sink(self, name: str) -> SinkType:
        for key, stype in self.SINK_TYPES.items():
            if key.lower() in name.lower():
                return stype
        return SinkType.HTML_INJECTION
    
    def _deduplicate(self, flows: List[TaintFlow]) -> List[TaintFlow]:
        seen = set()
        unique = []
        for flow in flows:
            key = (flow.source.name, flow.sink.name, flow.sink.element)
            if key not in seen:
                seen.add(key)
                unique.append(flow)
        return unique
