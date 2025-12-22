"""
DOM XSS Trigger Strategies - Foxhound Controller (patched)
Steuert den Foxhound Taint-Tracking Browser.

Fixes:
- Accepts unexpected keyword argument `config` (backward compatible with main.py)
- Reads config values if provided (dict or object)
- Adds early init script to collect foxhound taint events (best-effort)

Notes:
- Foxhound binary is provided via `foxhound_path` (CLI --foxhound-path) or env FOXHOUND_PATH
- Uses Playwright firefox.launch(executable_path=...) to run a custom Firefox/Foxhound build.
"""

import os
import json
import logging
import asyncio
from typing import Optional, List, Dict, Any
from pathlib import Path

from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger(__name__)


# Best-effort: collect foxhound-provided taint events if they are dispatched in the page,
# and keep an in-page buffer we can read out later.
FOXHOUND_TAINT_INIT_SCRIPT = r"""
(() => {
  try {
    if (window.__foxhound_taint_hook_installed) return;
    window.__foxhound_taint_hook_installed = true;

    window.__foxhound_taint_logs = window.__foxhound_taint_logs || [];

    // Some forks dispatch custom events. We listen to a few likely names (best-effort).
    const eventNames = ["__taintreport", "taintreport", "TAINT_REPORT", "foxhound:taint"];
    for (const name of eventNames) {
      window.addEventListener(name, (e) => {
        try {
          const detail = e && (e.detail ?? e);
          window.__foxhound_taint_logs.push({
            type: "event",
            name,
            detail,
            ts: Date.now()
          });

          // Optional: mirror to console so the Python side can pick it up even without evaluate()
          // Keep it short to avoid huge logs.
          let s = "";
          try { s = JSON.stringify(detail); } catch (_) { s = String(detail); }
          console.log("[TAINT_EVENT]", name, s.slice(0, 500));
        } catch (_) {}
      }, true);
    }

    console.log("[FOXHOUND] taint hook installed");
  } catch (_) {}
})();
"""


class FoxhoundController:
    """
    Controller für den Foxhound Browser.

    Foxhound ist ein modifizierter Firefox mit Taint-Tracking.
    """

    def __init__(
        self,
        foxhound_path: Optional[str] = None,
        headless: bool = False,
        timeout: int = 30000,
        config: Optional[Any] = None,
        **_ignored_kwargs: Any,
    ):
        """
        Accepts `config` for compatibility with callers that pass config=...
        - If `config` is a dict or an object with attributes, we try to read:
          foxhound_path / headless / timeout
        - Unknown kwargs are ignored intentionally to avoid hard crashes.
        """

        # Pull values from config if provided (non-breaking)
        cfg_foxhound_path = None
        cfg_headless = None
        cfg_timeout = None

        if config is not None:
            if isinstance(config, dict):
                cfg_foxhound_path = config.get("foxhound_path")
                cfg_headless = config.get("headless")
                cfg_timeout = config.get("timeout")
            else:
                cfg_foxhound_path = getattr(config, "foxhound_path", None)
                cfg_headless = getattr(config, "headless", None)
                cfg_timeout = getattr(config, "timeout", None)

        # Precedence: explicit args > config > env
        resolved_path = foxhound_path or cfg_foxhound_path or os.environ.get("FOXHOUND_PATH")
        self.foxhound_path = resolved_path
        self.headless = headless if headless is not None else (cfg_headless if cfg_headless is not None else False)
        self.timeout = timeout if timeout is not None else (cfg_timeout if cfg_timeout is not None else 30000)

        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        self._taint_logs: List[Dict[str, Any]] = []
        self._console_logs: List[str] = []

    async def start(self):
        """Startet den Browser"""
        logger.info("🦊 Starte Foxhound Browser...")

        self.playwright = await async_playwright().start()

        launch_args = [
            # Keep minimal; some Chromium-only flags can be ignored/harmless, but don't add many.
            "--disable-blink-features=AutomationControlled",
        ]

        # Launch either Foxhound binary or bundled Playwright Firefox.
        if self.foxhound_path and Path(self.foxhound_path).exists():
            logger.info(f"   Foxhound: {self.foxhound_path}")
            self.browser = await self.playwright.firefox.launch(
                executable_path=self.foxhound_path,
                headless=self.headless,
                args=launch_args,
            )
        else:
            logger.warning("   ⚠️ Foxhound nicht gefunden, verwende Firefox")
            self.browser = await self.playwright.firefox.launch(
                headless=self.headless,
                args=launch_args,
            )

        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            locale="de-DE",
            timezone_id="Europe/Berlin",
            ignore_https_errors=True,
        )

        self.context.set_default_timeout(self.timeout)

        # Early instrumentation (runs for every page/navigation in this context)
        # Useful to hook events before app code runs.
        await self.context.add_init_script(script=FOXHOUND_TAINT_INIT_SCRIPT)

        self.page = await self.context.new_page()
        self.page.on("console", self._on_console)

        logger.info("✅ Browser gestartet")

    def _on_console(self, msg):
        """Sammelt Console-Logs"""
        text = msg.text
        self._console_logs.append(text)

        # Anything taint-ish from console.
        if "TAINT" in text or "taint" in text.lower() or "TAINT_EVENT" in text:
            self._taint_logs.append(
                {
                    "type": getattr(msg, "type", "console"),
                    "text": text,
                }
            )
            logger.debug(f"[TAINT] {text[:200]}")

    async def navigate(self, url: str, wait_until: str = "networkidle") -> Page:
        """Navigiert zur URL"""
        if not self.page:
            raise RuntimeError("Browser not started. Call await start() first.")

        logger.info(f"🌐 Navigiere zu: {url}")

        self._taint_logs.clear()
        self._console_logs.clear()

        await self.page.goto(url, wait_until=wait_until)
        await asyncio.sleep(2)

        return self.page

    async def get_taint_logs(self) -> List[Dict[str, Any]]:
        """Gibt Taint-Logs zurück (console + in-page buffer)"""
        if not self.page:
            return self._taint_logs.copy()

        # Best-effort: read out foxhound buffer + custom buffer.
        try:
            foxhound_logs = await self.page.evaluate(
                """
                () => {
                  const a = window.__foxhound_taint_logs || [];
                  const b = (window.TaintLog && typeof window.TaintLog.getAll === 'function')
                    ? window.TaintLog.getAll()
                    : [];
                  return [...a, ...b];
                }
                """
            )
            if isinstance(foxhound_logs, list):
                for log in foxhound_logs:
                    # Dedup roughly (stringify compare)
                    try:
                        key = json.dumps(log, sort_keys=True, default=str)
                    except Exception:
                        key = str(log)
                    if not any(
                        (json.dumps(x, sort_keys=True, default=str) if isinstance(x, (dict, list)) else str(x)) == key
                        for x in self._taint_logs
                    ):
                        if isinstance(log, dict):
                            self._taint_logs.append(log)
                        else:
                            self._taint_logs.append({"type": "taint", "text": str(log)})
        except Exception:
            pass

        return self._taint_logs.copy()

    async def get_console_logs(self) -> List[str]:
        """Gibt alle Console-Logs zurück (für Debugging)"""
        return self._console_logs.copy()

    async def inject_taint_tracker(self):
        """Injiziert Custom Taint-Tracker (JS-Sink Hooks)"""
        if not self.page:
            raise RuntimeError("Browser not started. Call await start() first.")

        await self.page.evaluate(
            """
            () => {
              if (window.__custom_taint_tracker) return;
              window.__custom_taint_tracker = true;
              window.__taint_flows = window.__taint_flows || [];

              const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
              if (origInnerHTML && origInnerHTML.set && origInnerHTML.get) {
                Object.defineProperty(Element.prototype, 'innerHTML', {
                  set: function(value) {
                    try {
                      if (typeof value === 'string' && value.includes('<')) {
                        window.__taint_flows.push({
                          sink: 'innerHTML',
                          element: this.tagName + (this.id ? '#' + this.id : ''),
                          value: value.substring(0, 200),
                          timestamp: Date.now()
                        });
                        console.log('[TAINT] innerHTML:', value.substring(0, 80));
                      }
                    } catch (_) {}
                    return origInnerHTML.set.call(this, value);
                  },
                  get: origInnerHTML.get
                });
              }

              const origEval = window.eval;
              window.eval = function(code) {
                try {
                  window.__taint_flows.push({
                    sink: 'eval',
                    value: String(code).substring(0, 200),
                    timestamp: Date.now()
                  });
                  console.log('[TAINT] eval:', String(code).substring(0, 80));
                } catch (_) {}
                return origEval.call(this, code);
              };

              console.log('[TAINT-TRACKER] Injected');
            }
            """
        )
        logger.info("✅ Taint-Tracker injiziert")

    async def get_custom_taint_flows(self) -> List[Dict[str, Any]]:
        """Holt Flows vom Custom Tracker"""
        if not self.page:
            return []
        try:
            flows = await self.page.evaluate("() => window.__taint_flows || []")
            return flows if isinstance(flows, list) else []
        except Exception:
            return []

    async def clear_state(self):
        """Setzt Browser-State zurück"""
        try:
            if self.context:
                await self.context.clear_cookies()
            if self.page:
                await self.page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
            self._taint_logs.clear()
            self._console_logs.clear()
        except Exception as e:
            logger.warning(f"State-Reset fehlgeschlagen: {e}")

    async def stop(self):
        """Beendet den Browser"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.error(f"Browser-Stop fehlgeschlagen: {e}")

    async def start_taint_tracking(self):
        """
        Aktiviert Foxhound-Taint-Report Sammlung.
        Foxhound feuert bei einem gefundenen Flow das __taintreport-Event.
        Wir sammeln report.detail in window.__foxhound_taint_logs.
        """
        if not self.context or not self.page:
            raise RuntimeError("Browser not started. Call await start() first.")

        script = """
        (() => {
          if (window.__fh_taint_listener_installed) return;
          window.__fh_taint_listener_installed = true;

          window.__foxhound_taint_logs = window.__foxhound_taint_logs || [];

          window.addEventListener("__taintreport", (report) => {
            try {
              window.__foxhound_taint_logs.push(report.detail);
              // optional: kurze Console-Ausgabe, damit man was sieht
              console.log("[TAINTREPORT]", JSON.stringify(report.detail).slice(0, 400));
            } catch (e) {}
          }, true);
        })();
        """

        # 1) Für zukünftige Navigations/Frames (läuft bei jeder neuen Page/Navi im Context)
        await self.context.add_init_script(script=script)

        # 2) Für die aktuell geladene Seite sofort aktivieren
        await self.page.evaluate(script)

        logger.info("✅ Foxhound Taint-Tracking Listener aktiv")


    # In foxhound/controller.py innerhalb von class FoxhoundController ergänzen:

    async def new_context(self) -> Page:
        """
        Erstellt einen frischen BrowserContext + Page (Session-Isolation pro Strategie).
        """
        if not self.browser:
            raise RuntimeError("Browser not started. Call await start() first.")

        # alte Session schließen
        try:
            if self.page:
                await self.page.close()
        except Exception:
            pass
        try:
            if self.context:
                await self.context.close()
        except Exception:
            pass

        # neue Session erstellen
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            locale='de-DE',
            timezone_id='Europe/Berlin',
            ignore_https_errors=True
        )
        self.context.set_default_timeout(self.timeout)

        # falls du add_init_script nutzt (z.B. taint listener), hier wieder setzen:
        # await self.context.add_init_script(script=...)

        self.page = await self.context.new_page()
        self.page.on("console", self._on_console)

        return self.page
