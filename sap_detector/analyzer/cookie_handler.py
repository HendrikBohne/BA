"""
SPA Detection Tool - Cookie Handler
Automatisches Cookie-Banner Handling
"""
import asyncio
import logging
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

logger = logging.getLogger(__name__)


class CookieHandler:
    """Automatisches Cookie-Banner Handling"""
    
    # Bekannte Cookie-Banner Selektoren
    COOKIE_SELECTORS = [
        # Allgemeine Begriffe
        'button:has-text("Accept")',
        'button:has-text("Akzeptieren")',
        'button:has-text("Accept all")',
        'button:has-text("Alle akzeptieren")',
        'button:has-text("Agree")',
        'button:has-text("Zustimmen")',
        'button:has-text("OK")',
        'button:has-text("Got it")',
        'button:has-text("Verstanden")',
        'button:has-text("Allow")',
        'button:has-text("Erlauben")',
        'button:has-text("Continue")',
        'button:has-text("Weiter")',
        
        # ID-basierte Selektoren
        '#onetrust-accept-btn-handler',
        '#accept-cookies',
        '#acceptCookies',
        '#cookie-accept',
        '#cookieAccept',
        '.accept-cookies',
        '.cookie-accept',
        
        # Klassen-basierte Selektoren
        '[class*="accept"][class*="cookie"]',
        '[class*="cookie"][class*="accept"]',
        '[class*="consent"][class*="accept"]',
        '[class*="accept"][class*="all"]',
        
        # Data-Attribute
        '[data-testid*="accept"]',
        '[data-testid*="cookie"]',
        '[data-test*="accept"]',
        '[data-test*="cookie"]',
        
        # ARIA-Labels
        '[aria-label*="Accept"]',
        '[aria-label*="Akzeptieren"]',
        '[aria-label*="cookie"]',
        
        # OneTrust
        '.onetrust-close-btn-handler',
        '#onetrust-button-group button',
        
        # Cookie-Bot
        '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
        
        # Quantcast
        '.qc-cmp2-summary-buttons button',
        
        # TrustArc
        '#truste-consent-button',
        
        # Generische Fallbacks
        'button[id*="cookie"]',
        'button[class*="cookie"]',
        'a[id*="cookie"]',
        'a[class*="cookie"]',
    ]
    
    @staticmethod
    async def handle_cookies(page: Page, timeout: int = 5000) -> bool:
        """
        Versucht Cookie-Banner automatisch zu akzeptieren
        Returns: True wenn Banner gefunden und geklickt wurde
        """
        try:
            logger.info("🍪 Suche nach Cookie-Banner...")
            await asyncio.sleep(1)
            
            for selector in CookieHandler.COOKIE_SELECTORS:
                try:
                    element = await page.wait_for_selector(selector, timeout=1000, state='visible')
                    
                    if element:
                        await element.click(timeout=2000)
                        logger.info(f"✅ Cookie-Banner akzeptiert (Selector: {selector})")
                        await asyncio.sleep(1)
                        return True
                        
                except PlaywrightTimeout:
                    continue
                except Exception as e:
                    logger.debug(f"Cookie-Klick fehlgeschlagen für {selector}: {e}")
                    continue
            
            logger.info("ℹ️  Kein Cookie-Banner gefunden (oder bereits akzeptiert)")
            return False
            
        except Exception as e:
            logger.warning(f"Cookie-Handling Fehler: {e}")
            return False
    
    @staticmethod
    async def close_popups(page: Page):
        """Schließt zusätzliche Popups (Newsletter, etc.)"""
        try:
            close_selectors = [
                'button[aria-label*="Close"]',
                'button[aria-label*="Schließen"]',
                '.close',
                '.modal-close',
                '[class*="close"][class*="button"]',
                '[data-dismiss="modal"]',
            ]
            
            for selector in close_selectors:
                try:
                    element = await page.wait_for_selector(selector, timeout=1000, state='visible')
                    if element:
                        await element.click(timeout=2000)
                        logger.info(f"✅ Popup geschlossen: {selector}")
                        await asyncio.sleep(0.5)
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Popup-Close Fehler: {e}")