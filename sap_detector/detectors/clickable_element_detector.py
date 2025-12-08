"""
SPA Detection Tool - Clickable Element Detector
Signal 5: Klickbare Elemente ohne echtes href
"""
import logging
from .detection_result import DetectionResult

logger = logging.getLogger(__name__)


class ClickableElementDetector:
    """Signal 5: Klickbare Elemente ohne echtes href"""
    
    async def scan_dom(self, page) -> DetectionResult:
        """Scannt das DOM nach Clickable-Patterns"""
        try:
            data = await page.evaluate("""
                () => {
                    try {
                        const realLinks = document.querySelectorAll(
                            'a[href]:not([href^="#"]):not([href^="javascript:"]):not([href=""])'
                        );
                        const realLinkCount = realLinks.length;
                        
                        const clickables = document.querySelectorAll(
                            'div[onclick], span[onclick], button:not([type="submit"]), ' +
                            '[role="button"], [role="link"]'
                        );
                        const fakeClickableCount = clickables.length;
                        
                        const withCursor = document.querySelectorAll(
                            '[style*="cursor: pointer"], [style*="cursor:pointer"], ' +
                            '.clickable, .pointer, .click'
                        );
                        const cursorPointerCount = withCursor.length;
                        
                        const routerLinks = document.querySelectorAll(
                            '[routerlink], [to], [data-route], [href^="/"], ' +
                            '.router-link, .nav-link, [class*="link"]'
                        );
                        const routerLinkCount = routerLinks.length;
                        
                        const hasReact = !!document.querySelector('[data-reactroot], [data-react-app]');
                        const hasVue = !!document.querySelector('[data-v-], #app.__vue__');
                        const hasAngular = !!document.querySelector('[ng-version], [ng-app]');
                        
                        return {
                            realLinks: realLinkCount,
                            fakeClickables: fakeClickableCount,
                            cursorPointers: cursorPointerCount,
                            routerLinks: routerLinkCount,
                            total: document.querySelectorAll('*').length,
                            hasReact,
                            hasVue,
                            hasAngular
                        };
                    } catch (e) {
                        console.error('DOM scan error:', e);
                        return {
                            realLinks: 0,
                            fakeClickables: 0,
                            cursorPointers: 0,
                            routerLinks: 0,
                            total: 0,
                            hasReact: false,
                            hasVue: false,
                            hasAngular: false
                        };
                    }
                }
            """)
            
            fake_total = data['fakeClickables'] + data['routerLinks']
            real_total = data['realLinks']
            
            detected = False
            confidence = 0.0
            framework_detected = data['hasReact'] or data['hasVue'] or data['hasAngular']
            
            if data['routerLinks'] >= 5:
                detected = True
                confidence = 0.8
            elif fake_total >= 10 and real_total > 0:
                ratio = fake_total / real_total
                if ratio >= 0.5:
                    detected = True
                    confidence = min(0.85, 0.5 + (ratio / 4.0))
            elif fake_total >= 5:
                detected = True
                confidence = 0.4
            
            if detected and framework_detected:
                confidence = min(0.95, confidence + 0.1)
            
            evidence = {
                'real_links': real_total,
                'fake_clickables': data['fakeClickables'],
                'router_links': data['routerLinks'],
                'cursor_pointers': data['cursorPointers'],
                'fake_to_real_ratio': fake_total / max(1, real_total),
                'total_elements': data['total'],
                'framework': 'React' if data['hasReact'] else 'Vue' if data['hasVue'] else 'Angular' if data['hasAngular'] else 'None'
            }
            
            return DetectionResult(
                signal_name="Clickable Element Pattern",
                detected=detected,
                confidence=confidence,
                evidence=evidence,
                description=f"Fake-Clickables: {fake_total}, Real-Links: {real_total}, Framework: {evidence['framework']}"
            )
            
        except Exception as e:
            logger.error(f"Fehler bei Clickable-Analyse: {e}")
            return DetectionResult(
                signal_name="Clickable Element Pattern",
                detected=False,
                confidence=0.0,
                evidence={},
                description="Analyse fehlgeschlagen",
                error=str(e)
            )
