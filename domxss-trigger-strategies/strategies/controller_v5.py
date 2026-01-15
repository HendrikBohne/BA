"""
DOM XSS Trigger Strategies - Foxhound Controller (v5)
Browser-Steuerung mit echtem Foxhound Taint-Tracking

Änderungen v5:
- Echter Foxhound Taint-Flow Export (nicht mehr Pseudo-Tracking)
- flow_handler.js wird mit add_init_script() injiziert
- expose_binding für __foxhound_taint_report
- Findings werden in strukturierter Liste gesammelt
"""
import asyncio
import logging
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


# IAS Crawling-Studie Header
IAS_HEADERS = {
    'Referer': 'http://ias-lab.de',
    'X-IAS-Project': 'pasiphae'
}


# Foxhound Flow Handler JavaScript
FLOW_HANDLER_JS = """
(function () {
    if (window.__foxhound_flow_handler_installed) return;
    window.__foxhound_flow_handler_installed = true;
    
    function copyFlow(operations) {
        let copy = [];
        for (let i in operations) {
            copy.push({
                op: operations[i].operation,
                param1: operations[i].arguments ? (operations[i].arguments[0] || "") : "",
                param2: operations[i].arguments ? (operations[i].arguments[1] || "") : "",
                param3: operations[i].arguments ? (operations[i].arguments[2] || "") : "",
                location: operations[i].location || {}
            });
        }
        return copy;
    }
    
    function copyTaint(taint) {
        let copy = [];
        for (let i in taint) {
            copy.push({
                begin: taint[i].begin, 
                end: taint[i].end, 
                flow: copyFlow(taint[i].flow || [])
            });
        }
        return copy;
    }
    
    function createSources(taint) {
        let sources = [];
        for (let i in taint) {
            let flow = taint[i].flow;
            if (flow && flow.length > 0) {
                sources.push(flow[flow.length - 1].operation);
            }
        }
        return sources;
    }
    
    function copyFinding(finding) {
        let taint = [];
        let sources = [];
        
        try {
            if (finding.str && finding.str.taint) {
                taint = copyTaint(finding.str.taint);
                sources = createSources(finding.str.taint);
            }
        } catch (e) {}
        
        return {
            "subframe": finding.subframe || false,
            "loc": finding.loc || location.href,
            "parentloc": finding.parentloc || "",
            "referrer": finding.referrer || document.referrer,
            "script": (finding.stack && finding.stack.source) || "",
            "line": (finding.stack && finding.stack.line) || 0,
            "str": String(finding.str || "").substring(0, 1000),
            "sink": finding.sink || "",
            "taint": taint,
            "sources": sources,
            "domain": location.hostname,
            "url": location.href,
            "timestamp": Date.now()
        };
    }
    
    // Foxhound Taint-Report Event Listener
    window.addEventListener("__taintreport", (r) => {
        try {
            let finding = copyFinding(r.detail);
            
            if (typeof __foxhound_taint_report === 'function') {
                __foxhound_taint_report(finding);
            } else {
                window.__foxhound_findings = window.__foxhound_findings || [];
                window.__foxhound_findings.push(finding);
            }
        } catch (e) {}
    });
    
    console.log('[Foxhound] Taint handler installed');
})();
"""


@dataclass
class TaintFlow:
    """Repräsentiert einen einzelnen Taint-Flow"""
    sink: str
    sources: List[str]
    value: str
    url: str
    script: str
    line: int
    taint_chain: List[Dict]
    timestamp: float
    subframe: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def __hash__(self):
        # Für Deduplizierung
        return hash((self.sink, tuple(self.sources), self.url))


@dataclass 
class TaintFinding:
    """Strukturiertes Finding mit Metadaten"""
    flow: TaintFlow
    cookie_banner_accepted: bool = False
    post_reload: bool = False
    confidence: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'flow': self.flow.to_dict(),
            'cookie_banner_accepted': self.cookie_banner_accepted,
            'post_reload': self.post_reload,
            'confidence': self.confidence
        }


class FoxhoundController:
    """
    Controller für Foxhound Browser mit echtem Taint-Tracking.
    """
    
    def __init__(self, foxhound_path: str = None, headless: bool = True, config: Dict[str, Any] = None):
        config = config or {}
        
        self.foxhound_path = foxhound_path or config.get('foxhound_path') or os.environ.get('FOXHOUND_PATH')
        self.headless = headless if headless is not None else config.get('headless', True)
        
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        
        # Taint-Tracking
        self.taint_findings: List[TaintFinding] = []
        self.raw_taint_logs: List[Dict] = []
        self.console_logs: List[Dict] = []
        
        self.is_foxhound = False
        self._foxhound_process = None
        self._cookie_accepted = False
    
    async def start(self):
        """Startet den Browser (Foxhound oder Firefox Fallback)"""
        logger.info("🦊 Starte Foxhound Browser...")
        
        self.playwright = await async_playwright().start()
        
        if self.foxhound_path and Path(self.foxhound_path).exists():
            try:
                logger.info(f"   Foxhound: {self.foxhound_path}")
                await self._start_foxhound()
                self.is_foxhound = True
            except Exception as e:
                logger.warning(f"⚠️ Foxhound-Start fehlgeschlagen: {e}")
                await self._start_firefox_fallback()
        else:
            if self.foxhound_path:
                logger.warning(f"⚠️ Foxhound nicht gefunden: {self.foxhound_path}")
            else:
                logger.warning("⚠️ FOXHOUND_PATH nicht gesetzt, verwende Firefox")
            await self._start_firefox_fallback()
        
        logger.info("✅ Browser gestartet")
    
    async def _start_foxhound(self):
        """Startet Foxhound Browser mit Taint-Tracking"""
        self.browser = await self.playwright.firefox.launch(
            executable_path=self.foxhound_path,
            headless=self.headless,
            args=['--disable-blink-features=AutomationControlled']
        )
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            ignore_https_errors=True,
            extra_http_headers=IAS_HEADERS,
        )
        
        # WICHTIG: Flow Handler VOR der ersten Navigation installieren!
        await self._setup_taint_tracking()
        
        self.context.set_default_timeout(30000)
        self.page = await self.context.new_page()
        
        # Console-Listener
        self.page.on('console', self._on_console_message)
    
    async def _start_firefox_fallback(self):
        """Startet normales Firefox als Fallback"""
        self.browser = await self.playwright.firefox.launch(
            headless=self.headless,
            args=['--disable-blink-features=AutomationControlled']
        )
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            ignore_https_errors=True,
            extra_http_headers=IAS_HEADERS,
        )
        
        # Pseudo-Tracking für Firefox
        await self._setup_pseudo_taint_tracking()
        
        self.context.set_default_timeout(30000)
        self.page = await self.context.new_page()
        self.page.on('console', self._on_console_message)
        
        self.is_foxhound = False
    
    async def _setup_taint_tracking(self):
        """
        Installiert echtes Foxhound Taint-Tracking.
        WICHTIG: Muss VOR der Navigation aufgerufen werden!
        """
        # 1. Flow Handler als Init-Script (wird bei JEDER Navigation ausgeführt)
        await self.context.add_init_script(FLOW_HANDLER_JS)
        
        # 2. Expose Binding für Taint-Reports
        await self.context.expose_binding(
            "__foxhound_taint_report",
            self._handle_taint_report
        )
        
        logger.info("✅ Foxhound Taint-Tracking installiert")
    
    async def _setup_pseudo_taint_tracking(self):
        """Pseudo-Tracking für Firefox (Fallback)"""
        pseudo_tracking_js = """
        (function() {
            if (window.__pseudo_taint_installed) return;
            window.__pseudo_taint_installed = true;
            window.__foxhound_findings = [];
            
            function logSink(sink, value, element) {
                const finding = {
                    sink: sink,
                    str: String(value).substring(0, 500),
                    sources: ['user_input'],
                    url: location.href,
                    domain: location.hostname,
                    script: '',
                    line: 0,
                    taint: [],
                    timestamp: Date.now(),
                    subframe: false
                };
                
                window.__foxhound_findings.push(finding);
                
                if (typeof __foxhound_taint_report === 'function') {
                    __foxhound_taint_report(finding);
                }
            }
            
            // Hook innerHTML
            const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    if (value && /<script|onerror|onload|javascript:/i.test(value)) {
                        logSink('innerHTML', value, this);
                    }
                    return origInnerHTML.set.call(this, value);
                },
                get: origInnerHTML.get
            });
            
            // Hook eval
            const origEval = window.eval;
            window.eval = function(code) {
                logSink('eval', code, null);
                return origEval.apply(this, arguments);
            };
            
            // Hook document.write
            const origWrite = document.write;
            document.write = function(content) {
                logSink('document.write', content, null);
                return origWrite.apply(this, arguments);
            };
        })();
        """
        
        await self.context.add_init_script(pseudo_tracking_js)
        
        try:
            await self.context.expose_binding(
                "__foxhound_taint_report",
                self._handle_taint_report
            )
        except Exception:
            pass  # Binding existiert möglicherweise schon
        
        logger.info("✅ Pseudo-Taint-Tracking installiert (Firefox Fallback)")
    
    async def _handle_taint_report(self, source, finding: Dict):
        """
        Callback für Taint-Reports von Foxhound/Pseudo-Tracking.
        Wird von expose_binding aufgerufen.
        """
        try:
            # Erstelle TaintFlow
            flow = TaintFlow(
                sink=finding.get('sink', 'unknown'),
                sources=finding.get('sources', []),
                value=finding.get('str', ''),
                url=finding.get('url', ''),
                script=finding.get('script', ''),
                line=finding.get('line', 0),
                taint_chain=finding.get('taint', []),
                timestamp=finding.get('timestamp', 0) / 1000,  # ms -> s
                subframe=finding.get('subframe', False)
            )
            
            # Berechne Confidence
            confidence = self._calculate_confidence(flow)
            
            # Erstelle Finding
            taint_finding = TaintFinding(
                flow=flow,
                cookie_banner_accepted=self._cookie_accepted,
                post_reload=False,
                confidence=confidence
            )
            
            # Füge zu Listen hinzu
            self.taint_findings.append(taint_finding)
            self.raw_taint_logs.append(finding)
            
            # Log
            logger.warning(f"🚨 Taint-Flow: {flow.sink} (confidence: {confidence:.0%})")
            logger.debug(f"   Sources: {flow.sources}")
            logger.debug(f"   Value: {flow.value[:100]}...")
            
        except Exception as e:
            logger.error(f"Fehler beim Verarbeiten des Taint-Reports: {e}")
    
    def _calculate_confidence(self, flow: TaintFlow) -> float:
        """Berechnet Confidence-Score für einen Flow"""
        confidence = 0.5  # Basis
        
        # Gefährliche Sinks
        dangerous_sinks = {
            'eval': 0.95,
            'Function': 0.95,
            'innerHTML': 0.85,
            'outerHTML': 0.85,
            'document.write': 0.90,
            'insertAdjacentHTML': 0.80,
            'setTimeout': 0.70,
            'setInterval': 0.70,
        }
        
        for sink, conf in dangerous_sinks.items():
            if sink.lower() in flow.sink.lower():
                confidence = max(confidence, conf)
                break
        
        # Gefährliche Sources erhöhen Confidence
        dangerous_sources = ['location', 'document.URL', 'document.referrer', 'window.name', 'postMessage']
        for source in flow.sources:
            if any(ds in str(source) for ds in dangerous_sources):
                confidence = min(0.98, confidence + 0.1)
                break
        
        # XSS-Patterns im Value
        xss_patterns = ['<script', 'onerror', 'onload', 'javascript:', 'alert(', 'eval(']
        if any(p in flow.value.lower() for p in xss_patterns):
            confidence = min(0.98, confidence + 0.1)
        
        return confidence
    
    def _on_console_message(self, msg):
        """Verarbeitet Console-Nachrichten"""
        try:
            text = msg.text
            
            self.console_logs.append({
                'type': msg.type,
                'text': text,
                'timestamp': asyncio.get_event_loop().time()
            })
            
            # Prüfe auf XSS-Marker
            if 'XSS_DETECTED' in text:
                logger.warning(f"🚨 XSS Marker detected: {text}")
                
        except Exception:
            pass
    
    async def navigate(self, url: str, wait_until: str = 'networkidle') -> bool:
        """Navigiert zu einer URL"""
        try:
            response = await self.page.goto(url, wait_until=wait_until, timeout=30000)
            
            if response and response.status >= 400:
                logger.warning(f"⚠️ HTTP {response.status} für {url}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Navigation fehlgeschlagen: {e}")
            return False
    
    async def start_taint_tracking(self):
        """
        Legacy-Methode für Kompatibilität.
        Taint-Tracking wird jetzt automatisch in start() eingerichtet.
        """
        logger.info("✅ Foxhound Taint-Tracking Listener aktiv")
        
        # Versuche auch Findings aus dem Browser zu holen (falls Binding nicht funktioniert)
        try:
            browser_findings = await self.page.evaluate("""
                () => window.__foxhound_findings || []
            """)
            
            for finding in browser_findings:
                await self._handle_taint_report(None, finding)
                
        except Exception:
            pass
    
    async def get_taint_logs(self) -> List[Dict]:
        """Gibt alle gesammelten Taint-Logs zurück"""
        # Hole auch Findings aus dem Browser (Fallback)
        try:
            browser_findings = await self.page.evaluate("""
                () => window.__foxhound_findings || []
            """)
            
            for finding in browser_findings:
                # Prüfe ob schon vorhanden
                if finding not in self.raw_taint_logs:
                    self.raw_taint_logs.append(finding)
                    await self._handle_taint_report(None, finding)
                    
        except Exception:
            pass
        
        return self.raw_taint_logs
    
    def get_findings(self) -> List[TaintFinding]:
        """Gibt strukturierte Findings zurück"""
        return self.taint_findings
    
    def get_unique_flows(self) -> List[TaintFlow]:
        """Gibt deduplizierte Flows zurück"""
        seen = set()
        unique = []
        
        for finding in self.taint_findings:
            flow_hash = hash(finding.flow)
            if flow_hash not in seen:
                seen.add(flow_hash)
                unique.append(finding.flow)
        
        return unique
    
    def export_findings(self, filepath: str):
        """Exportiert Findings als JSON"""
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'is_foxhound': self.is_foxhound,
            'total_findings': len(self.taint_findings),
            'unique_flows': len(self.get_unique_flows()),
            'findings': [f.to_dict() for f in self.taint_findings]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 Findings exportiert: {filepath}")
    
    def export_findings_betreuer_format(self, filepath: str, base_url: str = ""):
        """
        Exportiert Findings im Format des Betreuers (Nightcrawler-kompatibel).
        
        Format:
        {
            "findings": [
                {
                    "pid": ...,
                    "base_url": ...,
                    "subpage": false,
                    "cookie_banner_accepted": ...,
                    "post_reload": false,
                    "cookies": [...],
                    "subframe": ...,
                    "loc": ...,
                    "parentloc": ...,
                    "referrer": ...,
                    "script": ...,
                    "line": ...,
                    "str": ...,
                    "sink": ...,
                    "taint": [...],
                    "sources": [...],
                    "domain": ...,
                    "hash": ...
                }
            ]
        }
        """
        import hashlib
        
        findings_export = []
        
        for i, finding in enumerate(self.taint_findings):
            flow = finding.flow
            
            # Hash berechnen (wie im Betreuer-Code)
            hash_input = f"{flow.sink}:{':'.join(flow.sources)}:{flow.url}"
            flow_hash = hashlib.md5(hash_input.encode()).hexdigest()
            
            finding_dict = {
                "pid": i,
                "base_url": base_url or flow.url,
                "subpage": False,
                "cookie_banner_accepted": finding.cookie_banner_accepted,
                "post_reload": finding.post_reload,
                "cookies": [],  # Könnte aus Browser geholt werden
                "subframe": flow.subframe,
                "loc": flow.url,
                "parentloc": "",
                "referrer": "",
                "script": flow.script,
                "line": flow.line,
                "str": flow.value[:1000],  # Gekürzt wie im Original
                "sink": flow.sink,
                "taint": flow.taint_chain,
                "sources": flow.sources,
                "domain": flow.url.split('/')[2] if '://' in flow.url else '',
                "hash": flow_hash,
                "confidence": finding.confidence
            }
            
            findings_export.append(finding_dict)
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "is_foxhound": self.is_foxhound,
            "base_url": base_url,
            "total_findings": len(findings_export),
            "findings": findings_export
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 Findings exportiert (Betreuer-Format): {filepath}")
        logger.info(f"   {len(findings_export)} Findings gespeichert")
    
    def set_cookie_accepted(self, accepted: bool = True):
        """Markiert dass Cookie-Banner akzeptiert wurde"""
        self._cookie_accepted = accepted
    
    def get_findings_betreuer_format(self, base_url: str = "") -> List[Dict]:
        """
        Gibt Findings im Betreuer-Format zurück (ohne Datei-Export).
        Nützlich für direkte Weiterverarbeitung.
        """
        import hashlib
        
        findings_export = []
        
        for i, finding in enumerate(self.taint_findings):
            flow = finding.flow
            
            hash_input = f"{flow.sink}:{':'.join(flow.sources)}:{flow.url}"
            flow_hash = hashlib.md5(hash_input.encode()).hexdigest()
            
            finding_dict = {
                "pid": i,
                "base_url": base_url or flow.url,
                "subpage": False,
                "cookie_banner_accepted": finding.cookie_banner_accepted,
                "post_reload": finding.post_reload,
                "subframe": flow.subframe,
                "loc": flow.url,
                "script": flow.script,
                "line": flow.line,
                "str": flow.value[:1000],
                "sink": flow.sink,
                "taint": flow.taint_chain,
                "sources": flow.sources,
                "domain": flow.url.split('/')[2] if '://' in flow.url else '',
                "hash": flow_hash,
                "confidence": finding.confidence
            }
            
            findings_export.append(finding_dict)
        
        return findings_export
    
    def clear_findings(self):
        """Löscht alle gesammelten Findings"""
        self.taint_findings = []
        self.raw_taint_logs = []
        self.console_logs = []
    
    async def stop(self):
        """Stoppt den Browser"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            
            logger.info("✅ Foxhound gestoppt")
            
        except Exception as e:
            logger.error(f"Fehler beim Stoppen: {e}")
    
    async def new_context(self) -> Page:
        """Erstellt einen neuen Browser-Context und Page"""
        if self.context:
            await self.context.close()
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            ignore_https_errors=True,
            extra_http_headers=IAS_HEADERS,
        )
        
        # Taint-Tracking für neuen Context
        if self.is_foxhound:
            await self._setup_taint_tracking()
        else:
            await self._setup_pseudo_taint_tracking()
        
        self.context.set_default_timeout(30000)
        self.page = await self.context.new_page()
        self.page.on('console', self._on_console_message)
        
        # Findings löschen für neuen Context
        self.clear_findings()
        
        return self.page
