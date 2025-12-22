"""
SPA Detection Tool - Network Activity Detector (v4 - mit Baseline/Post-Click)
Signal 2: XHR/Fetch statt Dokument-Navigations

ÄNDERUNGEN v4:
- Trennung von Baseline (Initial Load) und Post-Click Requests
- Filterung von Analytics/Tracking Requests
- Nur Post-Click API-Calls zählen als starkes SPA-Signal
"""
import asyncio
import logging
from typing import List, Dict
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


# Domains die ignoriert werden (Analytics, Tracking, Ads)
IGNORED_DOMAINS = [
    'google-analytics.com', 'googletagmanager.com', 'google.com/pagead',
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'facebook.com/tr', 'facebook.net', 'connect.facebook',
    'analytics', 'tracking', 'pixel', 'beacon',
    'hotjar.com', 'fullstory.com', 'mouseflow.com',
    'segment.io', 'segment.com', 'mixpanel.com',
    'amplitude.com', 'heapanalytics.com',
    'newrelic.com', 'nr-data.net',
    'sentry.io', 'bugsnag.com',
    'cloudflare.com/cdn-cgi', 'challenges.cloudflare.com',
    'recaptcha', 'hcaptcha',
    'ads.', 'ad.', 'adserver', 'adservice',
    'criteo.com', 'outbrain.com', 'taboola.com',
    'linkedin.com/px', 'twitter.com/i/jot',
    'tiktok.com/api/v1/log', 'tiktok.com/captcha'
]


class NetworkActivityDetector:
    """Signal 2: XHR/Fetch statt Dokument-Navigations (v4)"""
    
    def __init__(self):
        # Gesamt
        self.xhr_requests: List[Dict] = []
        self.fetch_requests: List[Dict] = []
        self.document_requests: List[Dict] = []
        self.json_responses = 0
        
        # NEU: Baseline vs. Post-Click
        self.baseline_api_requests: List[Dict] = []
        self.postclick_api_requests: List[Dict] = []
        
        # Tracking
        self._listeners_setup = False
        self._baseline_end_time = None
        self._current_click_window = None
        self._click_windows: List[Dict] = []
        
        # Baseline endet nach 3 Sekunden
        self._baseline_duration_sec = 3.0
        self._start_time = None
        
    async def setup_listeners(self, page):
        """Richtet Request-Listener ein"""
        try:
            if self._listeners_setup:
                return
            
            self._start_time = asyncio.get_event_loop().time()
            
            page.on("request", self._on_request)
            page.on("response", self._on_response)
            self._listeners_setup = True
            logger.info("Network-Listener eingerichtet (v4 - Baseline/Post-Click)")
            
        except Exception as e:
            logger.error(f"Fehler beim Setup der Network-Listener: {e}")
    
    def _is_ignored_url(self, url: str) -> bool:
        """Prüft ob URL ignoriert werden soll (Analytics/Tracking)"""
        url_lower = url.lower()
        for pattern in IGNORED_DOMAINS:
            if pattern in url_lower:
                return True
        return False
    
    def _on_request(self, request):
        try:
            resource_type = request.resource_type
            timestamp = asyncio.get_event_loop().time()
            url = request.url
            
            # Ignoriere Analytics/Tracking
            if self._is_ignored_url(url):
                return
            
            request_data = {
                'url': url,
                'method': request.method,
                'timestamp': timestamp,
                'resource_type': resource_type
            }
            
            # Kategorisieren
            if resource_type == "xhr":
                self.xhr_requests.append(request_data)
            elif resource_type == "fetch":
                self.fetch_requests.append(request_data)
            elif resource_type == "document":
                self.document_requests.append(request_data)
                return  # Document-Requests nicht als API zählen
            else:
                return  # Andere Typen ignorieren
            
            # In Baseline oder Post-Click einsortieren
            if self._start_time is None:
                self._start_time = timestamp
            
            time_since_start = timestamp - self._start_time
            
            if time_since_start <= self._baseline_duration_sec:
                # BASELINE Phase
                self.baseline_api_requests.append(request_data)
            elif self._current_click_window:
                # POST-CLICK Phase (aktives Fenster)
                self.postclick_api_requests.append(request_data)
                self._current_click_window['requests'].append(request_data)
            else:
                # Nach Baseline, aber kein aktives Click-Window
                # Trotzdem als Post-Click zählen (könnte verzögerte SPA-Aktivität sein)
                self.postclick_api_requests.append(request_data)
                
        except Exception as e:
            logger.error(f"Request-Tracking Fehler: {e}")
    
    def _on_response(self, response):
        try:
            url = response.url
            
            # Ignoriere Analytics/Tracking
            if self._is_ignored_url(url):
                return
            
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' in content_type or 'application/ld+json' in content_type:
                self.json_responses += 1
        except Exception as e:
            logger.error(f"Response-Tracking Fehler: {e}")
    
    def start_click_window(self, label: str = "click"):
        """Startet ein neues Click-Measurement-Window"""
        timestamp = asyncio.get_event_loop().time()
        
        # Schließe vorheriges Fenster
        if self._current_click_window:
            self._current_click_window['end_time'] = timestamp
            self._click_windows.append(self._current_click_window)
        
        self._current_click_window = {
            'label': label,
            'start_time': timestamp,
            'end_time': None,
            'requests': []
        }
        logger.debug(f"Network Click-Window gestartet: {label}")
    
    def end_click_window(self):
        """Beendet das aktuelle Click-Measurement-Window"""
        if self._current_click_window:
            timestamp = asyncio.get_event_loop().time()
            self._current_click_window['end_time'] = timestamp
            self._click_windows.append(self._current_click_window)
            logger.debug(f"Network Click-Window beendet: {len(self._current_click_window['requests'])} Requests")
            self._current_click_window = None
    
    def analyze(self) -> DetectionResult:
        """
        Analysiert Netzwerkaktivität mit Fokus auf POST-CLICK Aktivität.
        
        WICHTIG: Nur Post-Click API-Calls zählen als starkes SPA-Signal!
        Baseline-Requests (Initial Load) werden weniger gewichtet.
        """
        try:
            total_api_requests = len(self.xhr_requests) + len(self.fetch_requests)
            baseline_count = len(self.baseline_api_requests)
            postclick_count = len(self.postclick_api_requests)
            doc_requests = len(self.document_requests)
            
            detected = False
            confidence = 0.0
            reasons = []
            
            # ============================================
            # NEUE LOGIK: Post-Click ist das Haupt-Signal
            # ============================================
            
            # Starkes Signal: Viele Post-Click API Requests
            if postclick_count >= 10:
                detected = True
                confidence = 0.85
                reasons.append(f"high_postclick_api={postclick_count}")
            
            elif postclick_count >= 5:
                detected = True
                confidence = 0.70
                reasons.append(f"moderate_postclick_api={postclick_count}")
            
            elif postclick_count >= 2:
                detected = True
                confidence = 0.50
                reasons.append(f"some_postclick_api={postclick_count}")
            
            # Schwaches Signal: Nur Baseline-Aktivität
            elif baseline_count >= 20 and postclick_count < 2:
                # Viel Baseline aber wenig Post-Click → wahrscheinlich MPA mit lazy-load
                detected = False
                confidence = 0.0
                reasons.append(f"only_baseline_api={baseline_count}")
            
            # JSON-Responses als unterstützendes Signal
            if detected and self.json_responses >= 5:
                confidence = min(0.95, confidence + 0.1)
                reasons.append(f"json_responses={self.json_responses}")
            
            # Document-Requests als Gegen-Signal
            if doc_requests >= 3:
                confidence = max(0.0, confidence - 0.15)
                reasons.append(f"many_doc_requests={doc_requests}")
            
            # Ratio als zusätzliches Signal (nur wenn Post-Click vorhanden)
            if postclick_count > 0 and doc_requests > 0:
                ratio = postclick_count / doc_requests
                if ratio >= 5:
                    confidence = min(0.95, confidence + 0.1)
                    reasons.append(f"good_ratio={ratio:.1f}")
            
            evidence = {
                # Baseline vs. Post-Click (NEU!)
                'baseline_api_requests': baseline_count,
                'postclick_api_requests': postclick_count,
                'click_windows': len(self._click_windows),
                
                # Gesamt
                'xhr_count': len(self.xhr_requests),
                'fetch_count': len(self.fetch_requests),
                'total_api_requests': total_api_requests,
                'document_requests': doc_requests,
                'json_responses': self.json_responses,
                
                # Ratio
                'postclick_to_doc_ratio': postclick_count / max(1, doc_requests),
                
                # Samples
                'sample_baseline': [r['url'][:80] for r in self.baseline_api_requests[:3]],
                'sample_postclick': [r['url'][:80] for r in self.postclick_api_requests[:3]],
                
                'detection_reasons': reasons
            }
            
            if detected:
                description = (
                    f"API-Aktivität erkannt (Post-Click): {postclick_count} Requests. "
                    f"Baseline: {baseline_count} Requests. Document: {doc_requests}."
                )
            else:
                description = (
                    f"Keine SPA-typische API-Aktivität. Post-Click: {postclick_count}. "
                    f"Baseline: {baseline_count}. Document: {doc_requests}."
                )
            
            return DetectionResult(
                signal_name="Network Activity Pattern",
                detected=detected,
                confidence=round(confidence, 2),
                evidence=evidence,
                description=description
            )
            
        except Exception as e:
            logger.error(f"Fehler bei Network-Analyse: {e}")
            return DetectionResult(
                signal_name="Network Activity Pattern",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )
