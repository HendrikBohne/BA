"""
DOM XSS Trigger Strategies - Foxhound Controller (Fixed v3)
Browser-Steuerung mit Foxhound Taint-Tracking
"""
import asyncio
import logging
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger(__name__)


class FoxhoundController:
    """
    Controller für Foxhound Browser mit Taint-Tracking.
    
    Foxhound ist ein modifizierter Firefox mit eingebautem Taint-Tracking.
    Falls Foxhound nicht verfügbar ist, wird normales Firefox als Fallback verwendet.
    """
    
    def __init__(self, foxhound_path: str = None, headless: bool = True, config: Dict[str, Any] = None):
        """
        Args:
            foxhound_path: Pfad zur Foxhound-Binary (oder FOXHOUND_PATH env var)
            headless: Browser im Headless-Modus starten
            config: Optionale Konfiguration (für Kompatibilität)
        """
        # Config verarbeiten
        config = config or {}
        
        # Prüfe Environment Variable falls kein Pfad angegeben
        self.foxhound_path = foxhound_path or config.get('foxhound_path') or os.environ.get('FOXHOUND_PATH')
        self.headless = headless if headless is not None else config.get('headless', True)
        
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        
        self.taint_logs: List[Dict] = []
        self.is_foxhound = False
        self._foxhound_process = None
    
    async def start(self):
        """Startet den Browser (Foxhound oder Firefox Fallback)"""
        logger.info("🦊 Starte Foxhound Browser...")
        
        self.playwright = await async_playwright().start()
        
        # Versuche Foxhound zu starten
        if self.foxhound_path and Path(self.foxhound_path).exists():
            try:
                logger.info(f"   Foxhound: {self.foxhound_path}")
                await self._start_foxhound()
                self.is_foxhound = True
            except Exception as e:
                logger.warning(f"⚠️ Foxhound-Start fehlgeschlagen: {e}")
                logger.warning("   Verwende Firefox Fallback")
                await self._start_firefox_fallback()
        else:
            if self.foxhound_path:
                logger.warning(f"⚠️ Foxhound nicht gefunden: {self.foxhound_path}")
            else:
                logger.warning("⚠️ FOXHOUND_PATH nicht gesetzt, verwende Firefox")
            await self._start_firefox_fallback()
        
        logger.info("✅ Browser gestartet")
    
    async def _start_foxhound(self):
        """Startet Foxhound Browser"""
        self.browser = await self.playwright.firefox.launch(
            executable_path=self.foxhound_path,
            headless=self.headless,
            args=[
                '--disable-blink-features=AutomationControlled',
            ]
        )
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            ignore_https_errors=True,
        )
        
        self.context.set_default_timeout(30000)
        self.page = await self.context.new_page()
    
    async def _start_firefox_fallback(self):
        """Startet normales Firefox als Fallback"""
        self.browser = await self.playwright.firefox.launch(
            headless=self.headless,
            args=[
                '--disable-blink-features=AutomationControlled',
            ]
        )
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            ignore_https_errors=True,
        )
        
        self.context.set_default_timeout(30000)
        self.page = await self.context.new_page()
        
        self.is_foxhound = False
    
    async def navigate(self, url: str, wait_until: str = 'networkidle') -> bool:
        """
        Navigiert zu einer URL.
        """
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
        Aktiviert Taint-Tracking.
        """
        self.taint_logs = []
        
        # Console-Listener für Taint-Logs
        self.page.on('console', self._on_console_message)
        
        # Injiziere Taint-Tracking Hooks
        await self._inject_taint_hooks()
        
        logger.info("✅ Foxhound Taint-Tracking Listener aktiv")
    
    def _on_console_message(self, msg):
        """Verarbeitet Console-Nachrichten (Taint-Logs)"""
        try:
            text = msg.text
            
            # Foxhound Taint-Log Format
            if '[TAINT]' in text or 'taint' in text.lower():
                self.taint_logs.append({
                    'type': 'console',
                    'text': text,
                    'timestamp': asyncio.get_event_loop().time()
                })
            
            # XSS Detection Marker
            if 'XSS_DETECTED' in text or 'XSS' in text:
                logger.warning(f"🚨 XSS detected: {text}")
                self.taint_logs.append({
                    'type': 'xss_detected',
                    'text': text,
                    'timestamp': asyncio.get_event_loop().time()
                })
                
        except Exception as e:
            pass
    
    async def _inject_taint_hooks(self):
        """
        Injiziert JavaScript-Hooks für Pseudo-Taint-Tracking.
        """
        try:
            await self.page.evaluate(r"""
                () => {
                    if (window.__taint_hooks_installed) return;
                    window.__taint_hooks_installed = true;
                    window.__taint_flows = [];
                    
                    // Helper: Log taint flow
                    function logTaint(sink, value, element) {
                        const flow = {
                            type: 'flow',
                            sink: sink,
                            value: String(value).substring(0, 500),
                            element: element ? element.tagName : null,
                            timestamp: Date.now(),
                            url: window.location.href
                        };
                        window.__taint_flows.push(flow);
                        console.log('[TAINT] ' + sink + ' = ' + String(value).substring(0, 100));
                    }
                    
                    // Hook: Element.innerHTML setter
                    const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                    Object.defineProperty(Element.prototype, 'innerHTML', {
                        set: function(value) {
                            // Check for potential XSS patterns
                            if (value && typeof value === 'string') {
                                const dangerous = /<script|onerror|onload|javascript:|eval\(|alert\(/i.test(value);
                                if (dangerous || value.length > 50) {
                                    logTaint('innerHTML', value, this);
                                }
                            }
                            return originalInnerHTMLDescriptor.set.call(this, value);
                        },
                        get: originalInnerHTMLDescriptor.get
                    });
                    
                    // Hook: Element.outerHTML setter
                    const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
                    if (originalOuterHTMLDescriptor && originalOuterHTMLDescriptor.set) {
                        Object.defineProperty(Element.prototype, 'outerHTML', {
                            set: function(value) {
                                if (value && typeof value === 'string') {
                                    logTaint('outerHTML', value, this);
                                }
                                return originalOuterHTMLDescriptor.set.call(this, value);
                            },
                            get: originalOuterHTMLDescriptor.get
                        });
                    }
                    
                    // Hook: document.write
                    const originalWrite = document.write;
                    document.write = function(content) {
                        logTaint('document.write', content, null);
                        return originalWrite.apply(this, arguments);
                    };
                    
                    // Hook: eval
                    const originalEval = window.eval;
                    window.eval = function(code) {
                        logTaint('eval', code, null);
                        return originalEval.apply(this, arguments);
                    };
                    
                    // Hook: Function constructor
                    const originalFunction = window.Function;
                    window.Function = function() {
                        const code = Array.from(arguments).join(', ');
                        logTaint('Function', code, null);
                        return originalFunction.apply(this, arguments);
                    };
                    
                    // Hook: setTimeout/setInterval with string
                    const originalSetTimeout = window.setTimeout;
                    window.setTimeout = function(handler, timeout) {
                        if (typeof handler === 'string') {
                            logTaint('setTimeout', handler, null);
                        }
                        return originalSetTimeout.apply(this, arguments);
                    };
                    
                    const originalSetInterval = window.setInterval;
                    window.setInterval = function(handler, timeout) {
                        if (typeof handler === 'string') {
                            logTaint('setInterval', handler, null);
                        }
                        return originalSetInterval.apply(this, arguments);
                    };
                    
                    // Hook: insertAdjacentHTML
                    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
                    Element.prototype.insertAdjacentHTML = function(position, text) {
                        if (text && typeof text === 'string') {
                            logTaint('insertAdjacentHTML', text, this);
                        }
                        return originalInsertAdjacentHTML.apply(this, arguments);
                    };
                    
                    console.log('[TAINT] Hooks installed - monitoring sinks');
                }
            """)
        except Exception as e:
            logger.debug(f"Taint-Hooks Injection Fehler: {e}")
    
    async def get_taint_logs(self) -> List[Dict]:
        """
        Sammelt alle Taint-Logs.
        """
        try:
            # Hole Flows aus dem Browser
            browser_flows = await self.page.evaluate("""
                () => {
                    return window.__taint_flows || [];
                }
            """)
            
            # Kombiniere mit Console-Logs
            all_logs = self.taint_logs + browser_flows
            
            return all_logs
            
        except Exception as e:
            logger.error(f"Fehler beim Abrufen der Taint-Logs: {e}")
            return self.taint_logs
    
    async def inject_xss_payload(self, payload: str, target: str = 'hash'):
        """
        Injiziert einen XSS-Payload für Testing.
        """
        try:
            current_url = self.page.url
            
            if target == 'hash':
                new_url = current_url.split('#')[0] + '#' + payload
                await self.page.goto(new_url)
            elif target == 'search':
                base = current_url.split('?')[0]
                new_url = base + '?q=' + payload
                await self.page.goto(new_url)
            
            await asyncio.sleep(0.5)
            
        except Exception as e:
            logger.error(f"Payload-Injection Fehler: {e}")
    
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
            if self._foxhound_process:
                self._foxhound_process.terminate()
            
            logger.info("✅ Foxhound gestoppt")
            
        except Exception as e:
            logger.error(f"Fehler beim Stoppen: {e}")
    
    async def new_context(self) -> Page:
        """Erstellt einen neuen Browser-Context und Page"""
        if self.context:
            await self.context.close()
        
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            ignore_https_errors=True,
        )
        self.context.set_default_timeout(30000)
        self.page = await self.context.new_page()
        
        return self.page