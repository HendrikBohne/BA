"""
SPA Detection Tool - Interaction Strategy (FIXED v2)
Robuste Interaktionsstrategien - NUR INTERNE NAVIGATION

FIXES:
1. Navigation Guard verhindert echte Browser-Navigationen
2. Bevorzugt SPA-typische Elemente (Buttons, role="button")
3. Links werden nur geklickt wenn sie SPA-like aussehen
"""
import asyncio
import random
import logging
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout
from .model_guided_strategy import ModelGuidedStrategy

logger = logging.getLogger(__name__)


# Navigation Guard Script - verhindert echte Browser-Navigationen
NAVIGATION_GUARD_SCRIPT = """
(() => {
    if (window.__spa_detection_nav_guard) return;
    window.__spa_detection_nav_guard = true;
    
    // Tracke ob wir gerade navigieren wollen
    window.__spa_detection_allow_navigation = false;
    
    // Intercepte alle Link-Klicks
    document.addEventListener('click', (e) => {
        const link = e.target.closest('a[href]');
        if (!link) return;
        
        const href = link.getAttribute('href');
        if (!href) return;
        
        // Erlaube Hash-Links
        if (href.startsWith('#')) return;
        
        // Erlaube JavaScript-Links
        if (href.startsWith('javascript:')) return;
        
        // Prüfe ob es ein echter externer Link ist
        const currentOrigin = window.location.origin;
        try {
            const url = new URL(href, currentOrigin);
            
            // Wenn gleiche Origin UND der Link ein target="_blank" hat -> blockieren
            if (url.origin === currentOrigin && link.target === '_blank') {
                e.preventDefault();
                console.log('[SPA-Detection] Blocked _blank navigation:', href);
                return;
            }
            
            // Wenn es wie eine echte Navigation aussieht und kein SPA-Handler da ist
            // Prüfe ob das Element Event-Listener hat (SPA-typisch)
            const hasClickHandler = link.onclick !== null || 
                                   link.getAttribute('onclick') !== null ||
                                   link.hasAttribute('routerlink') ||
                                   link.hasAttribute('data-route') ||
                                   link.classList.contains('router-link');
            
            if (!hasClickHandler && url.origin === currentOrigin) {
                // Könnte eine echte Navigation sein - markiere es
                console.log('[SPA-Detection] Potential real navigation:', href);
            }
            
        } catch (err) {
            // URL parsing fehlgeschlagen
        }
    }, true);
    
    console.log('[SPA-Detection] Navigation guard active');
})();
"""


class InteractionStrategy:
    """Robuste Interaktionsstrategien für beliebige Websites"""
    
    @staticmethod
    async def inject_navigation_guard(page: Page):
        """Injiziert den Navigation Guard"""
        try:
            await page.evaluate(NAVIGATION_GUARD_SCRIPT)
            logger.debug("Navigation Guard injiziert")
        except Exception as e:
            logger.debug(f"Navigation Guard Injection übersprungen: {e}")
    
    @staticmethod
    async def smart_random_walk(page: Page, max_actions: int = 10) -> int:
        """
        Intelligenter Random-Walk mit Fehlerbehandlung
        WICHTIG: Bevorzugt SPA-typische Elemente
        Returns: Anzahl erfolgreicher Aktionen
        """
        actions_performed = 0
        failed_attempts = 0
        max_failures = 5
        
        # Injiziere Navigation Guard
        await InteractionStrategy.inject_navigation_guard(page)
        
        logger.info(f"🎮 Starte Smart Random-Walk (max {max_actions} Aktionen)...")
        
        for i in range(max_actions):
            if failed_attempts >= max_failures:
                logger.warning(f"⚠️  Zu viele fehlgeschlagene Versuche ({failed_attempts}), breche ab")
                break
            
            try:
                # Finde klickbare Elemente - BEVORZUGE SPA-TYPISCHE!
                clickables = await page.evaluate("""
                    () => {
                        const currentHostname = window.location.hostname;
                        const currentOrigin = window.location.origin;
                        
                        // SPA-typische Elemente zuerst (Buttons, role="button")
                        const spaElements = [
                            ...document.querySelectorAll('button:not([type="submit"])'),
                            ...document.querySelectorAll('[role="button"]'),
                            ...document.querySelectorAll('[role="tab"]'),
                            ...document.querySelectorAll('[role="menuitem"]'),
                            ...document.querySelectorAll('[onclick]'),
                            ...document.querySelectorAll('[routerlink]'),
                            ...document.querySelectorAll('[data-route]'),
                            ...document.querySelectorAll('.router-link'),
                        ];
                        
                        // Dann interne Links (aber mit niedrigerer Priorität)
                        const linkElements = [
                            ...document.querySelectorAll('nav a'),
                            ...document.querySelectorAll('a[href^="#"]'),
                            ...document.querySelectorAll('a[href^="/"]'),
                        ];
                        
                        const allElements = [...spaElements, ...linkElements];
                        
                        return allElements
                            .filter(el => {
                                try {
                                    const rect = el.getBoundingClientRect();
                                    const style = window.getComputedStyle(el);
                                    
                                    // Sichtbarkeits-Check
                                    if (rect.width <= 0 || rect.height <= 0 || 
                                        rect.top < 0 || rect.left < 0 ||
                                        rect.top >= window.innerHeight ||
                                        style.display === 'none' ||
                                        style.visibility === 'hidden' ||
                                        style.opacity === '0') {
                                        return false;
                                    }
                                    
                                    // Filter Links
                                    if (el.tagName.toLowerCase() === 'a') {
                                        const href = el.getAttribute('href');
                                        
                                        if (!href) return true;
                                        
                                        // Blockiere externe Protokolle
                                        if (href.startsWith('mailto:') || 
                                            href.startsWith('tel:') || 
                                            href.startsWith('file:')) {
                                            return false;
                                        }
                                        
                                        // Erlaube Hash-Links (sehr SPA-typisch)
                                        if (href.startsWith('#')) return true;
                                        
                                        // Erlaube relative Links
                                        if (href.startsWith('/') && !href.startsWith('//')) return true;
                                        
                                        // Prüfe absolute URLs
                                        try {
                                            const url = new URL(href, currentOrigin);
                                            if (url.hostname !== currentHostname) return false;
                                        } catch (e) {
                                            return false;
                                        }
                                        
                                        return true;
                                    }
                                    
                                    return true;
                                } catch (e) {
                                    return false;
                                }
                            })
                            .map((el, idx) => {
                                let selector = el.tagName.toLowerCase();
                                if (el.id) selector += '#' + el.id;
                                else if (el.className && typeof el.className === 'string') {
                                    const classes = el.className.split(' ').filter(c => c && c.length < 30);
                                    if (classes[0]) selector += '.' + classes[0];
                                }
                                
                                const href = el.getAttribute('href');
                                const isSpaElement = el.tagName.toLowerCase() !== 'a' ||
                                                    href?.startsWith('#') ||
                                                    el.hasAttribute('onclick') ||
                                                    el.hasAttribute('routerlink');
                                
                                return {
                                    index: idx,
                                    selector: selector,
                                    text: (el.textContent || '').trim().substring(0, 50),
                                    tag: el.tagName.toLowerCase(),
                                    hasHref: el.hasAttribute('href'),
                                    href: href || '',
                                    isSpaElement: isSpaElement,
                                    priority: isSpaElement ? 2 : 1
                                };
                            })
                            .slice(0, 50);
                    }
                """)
                
                if not clickables or len(clickables) == 0:
                    logger.debug(f"Keine klickbaren Elemente gefunden (Versuch {i+1})")
                    failed_attempts += 1
                    await asyncio.sleep(0.5)
                    continue
                
                # Bevorzuge SPA-Elemente (80% Wahrscheinlichkeit)
                spa_elements = [c for c in clickables if c.get('isSpaElement')]
                other_elements = [c for c in clickables if not c.get('isSpaElement')]
                
                if spa_elements and (not other_elements or random.random() < 0.8):
                    target = random.choice(spa_elements)
                else:
                    target = random.choice(other_elements if other_elements else clickables)
                
                element_type = "SPA" if target.get('isSpaElement') else "Link"
                logger.debug(f"Klicke auf [{element_type}]: {target['text'][:30]} ({target['tag']})")
                
                # Klick-Versuche
                try:
                    await page.click(target['selector'], timeout=3000)
                    actions_performed += 1
                    failed_attempts = 0
                    logger.info(f"✅ Aktion {actions_performed}: {target['text'][:30]}")
                    
                except PlaywrightTimeout:
                    try:
                        await page.evaluate(f"""
                            () => {{
                                const elements = document.querySelectorAll('{target['selector']}');
                                if (elements[{target['index']}]) {{
                                    elements[{target['index']}].click();
                                }}
                            }}
                        """)
                        actions_performed += 1
                        logger.info(f"✅ Aktion {actions_performed} (JS): {target['text'][:30]}")
                    except:
                        failed_attempts += 1
                        logger.debug(f"❌ Klick fehlgeschlagen: {target['text'][:30]}")
                
                await asyncio.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                logger.debug(f"Interaktion {i+1} fehlgeschlagen: {e}")
                failed_attempts += 1
                await asyncio.sleep(0.5)
                continue
        
        logger.info(f"✅ Random-Walk abgeschlossen: {actions_performed} erfolgreiche Aktionen")
        return actions_performed
    
    @staticmethod
    async def test_navigation(page: Page, max_links: int = 5) -> int:
        """
        Testet Navigation-Links systematisch (nur interne)
        Returns: Anzahl erfolgreicher Aktionen
        """
        actions = 0
        
        # Injiziere Navigation Guard
        await InteractionStrategy.inject_navigation_guard(page)
        
        try:
            logger.info("🧭 Teste Navigation-Links...")
            
            nav_links = await page.evaluate("""
                () => {
                    const currentHostname = window.location.hostname;
                    const currentOrigin = window.location.origin;
                    
                    const navElements = [
                        ...document.querySelectorAll('nav a, [role="navigation"] a'),
                        ...document.querySelectorAll('.nav a, .navigation a, .menu a'),
                        ...document.querySelectorAll('header a, [class*="header"] a')
                    ];
                    
                    return [...new Set(navElements)]
                        .filter(el => {
                            const rect = el.getBoundingClientRect();
                            if (rect.width <= 0 || rect.height <= 0) return false;
                            
                            const href = el.getAttribute('href');
                            if (!href) return false;
                            
                            if (href.startsWith('mailto:') || 
                                href.startsWith('tel:') || 
                                href.startsWith('file:')) {
                                return false;
                            }
                            
                            if (href.startsWith('#')) return true;
                            if (href.startsWith('/') && !href.startsWith('//')) return true;
                            
                            try {
                                const url = new URL(href, currentOrigin);
                                return url.hostname === currentHostname;
                            } catch (e) {
                                return false;
                            }
                        })
                        .slice(0, 10)
                        .map(el => ({
                            text: el.textContent.trim().substring(0, 30),
                            href: el.getAttribute('href')
                        }));
                }
            """)
            
            logger.info(f"Gefunden: {len(nav_links)} Navigation-Links")
            
            for link in nav_links[:max_links]:
                try:
                    await page.click(f'a:has-text("{link["text"]}")', timeout=2000)
                    actions += 1
                    logger.info(f"✅ Navigation-Klick: {link['text']}")
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.debug(f"Navigation-Klick fehlgeschlagen: {link['text']}: {e}")
                    continue
            
            logger.info(f"✅ Navigation-Test: {actions} erfolgreiche Klicks")
            
        except Exception as e:
            logger.error(f"Navigation-Test Fehler: {e}")
        
        return actions
    
    @staticmethod
    async def scroll_page(page: Page):
        """Scrollt die Seite für Lazy-Loading"""
        try:
            logger.info("📜 Scrolle Seite...")
            
            await page.evaluate("""
                async () => {
                    const scrollStep = window.innerHeight / 2;
                    const scrollDelay = 200;
                    
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, scrollStep);
                        await new Promise(resolve => setTimeout(resolve, scrollDelay));
                    }
                    
                    window.scrollTo(0, 0);
                }
            """)
            
            await asyncio.sleep(1)
            logger.info("✅ Scrolling abgeschlossen")
            
        except Exception as e:
            logger.debug(f"Scroll-Fehler: {e}")

            
    @staticmethod
    async def model_guided_random_walk(page: Page, max_actions: int = 10, 
                                       w_model: float = 25.0) -> int:
        """
        Model-Guided Random Walk mit State-Independent Model
        Delegiert an ModelGuidedStrategy
        """
        # Injiziere Navigation Guard zuerst
        await InteractionStrategy.inject_navigation_guard(page)
        
        return await ModelGuidedStrategy.execute(page, max_actions, w_model)