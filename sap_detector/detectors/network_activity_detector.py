"""
SPA Detection Tool - Network Activity Detector
Signal 2: XHR/Fetch statt Dokument-Navigations
"""
import asyncio
import logging
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


class NetworkActivityDetector:
    """Signal 2: XHR/Fetch statt Dokument-Navigations"""
    
    def __init__(self):
        self.xhr_requests = []
        self.fetch_requests = []
        self.document_requests = []
        self.json_responses = 0
        self._listeners_setup = False
        
    async def setup_listeners(self, page):
        """Richtet Request-Listener ein"""
        try:
            if self._listeners_setup:
                return
            
            page.on("request", self._on_request)
            page.on("response", self._on_response)
            self._listeners_setup = True
            logger.info("Network-Listener eingerichtet")
            
        except Exception as e:
            logger.error(f"Fehler beim Setup der Network-Listener: {e}")
    
    def _on_request(self, request):
        try:
            resource_type = request.resource_type
            timestamp = asyncio.get_event_loop().time()
            
            request_data = {
                'url': request.url,
                'method': request.method,
                'timestamp': timestamp
            }
            
            if resource_type == "xhr":
                self.xhr_requests.append(request_data)
            elif resource_type == "fetch":
                self.fetch_requests.append(request_data)
            elif resource_type == "document":
                self.document_requests.append(request_data)
                
        except Exception as e:
            logger.error(f"Request-Tracking Fehler: {e}")
    
    def _on_response(self, response):
        try:
            # Zähle JSON-Responses
            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' in content_type or 'application/ld+json' in content_type:
                self.json_responses += 1
        except Exception as e:
            logger.error(f"Response-Tracking Fehler: {e}")
    
    def analyze(self) -> DetectionResult:
        """Analysiert Netzwerkaktivität"""
        try:
            api_requests = len(self.xhr_requests) + len(self.fetch_requests)
            doc_requests = len(self.document_requests)
            
            detected = False
            confidence = 0.0
            
            # Starkes Signal: Viele API-Calls, wenige Documents
            if api_requests >= 5 and doc_requests <= 2:
                detected = True
                ratio = api_requests / max(1, doc_requests)
                confidence = min(0.95, 0.5 + (ratio / 20.0))
            # Mittleres Signal
            elif api_requests >= 3 and doc_requests <= 2:
                detected = True
                confidence = 0.7
            # Schwaches Signal
            elif api_requests >= 2 and doc_requests == 1:
                detected = True
                confidence = 0.5
            
            # Bonus für viele JSON-Responses
            if detected and self.json_responses >= 3:
                confidence = min(0.95, confidence + 0.1)
            
            evidence = {
                'xhr_count': len(self.xhr_requests),
                'fetch_count': len(self.fetch_requests),
                'total_api_requests': api_requests,
                'document_requests': doc_requests,
                'json_responses': self.json_responses,
                'ratio': api_requests / max(1, doc_requests),
                'sample_api_calls': (self.xhr_requests + self.fetch_requests)[:5]
            }
            
            return DetectionResult(
                signal_name="Network Activity Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"API-Requests: {api_requests}, Document-Requests: {doc_requests}, JSON: {self.json_responses}"
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