"""
SPA Detection Tool - Interaction Strategy
Robuste Interaktionsstrategien - NUR INTERNE NAVIGATION
"""
import asyncio
import random
import logging
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout
from .model_guided_strategy import ModelGuidedStrategy

logger = logging.getLogger(__name__)


class InteractionStrategy:
    """Robuste Interaktionsstrategien für beliebige Websites"""
    
    @staticmethod
    async def smart_random_walk(page: Page, max_actions: int = 10) -> int:
        """
        Intelligenter Random-Walk mit Fehlerbehandlung
        WICHTIG: Klickt nur auf interne Links (bleibt auf gleicher Domain)
        Returns: Anzahl erfolgreicher Aktionen
        """
        actions_performed = 0
        failed_attempts = 0
        max_failures = 5
        
        logger.info(f"🎮 Starte Smart Random-Walk (max {max_actions} Aktionen)...")
        
        for i in range(max_actions):
            if failed_attempts >= max_failures:
                logger.warning(f"⚠️  Zu viele fehlgeschlagene Versuche ({failed_attempts}), breche ab")
                break
            
            try:
                # Finde klickbare Elemente (nur interne Links)
                clickables = await page.evaluate("""
                    () => {
                        const currentHostname = window.location.hostname;
                        const currentOrigin = window.location.origin;
                        
                        const elements = [
                            ...document.querySelectorAll('a, button, [role="button"], [onclick], nav a, .nav-link'),
                            ...document.querySelectorAll('[class*="menu"], [class*="nav"], [class*="link"]')
                        ];
                        
                        return elements
                            .filter(el => {
                                try {
                                    const rect = el.getBoundingClientRect();
                                    const style = window.getComputedStyle(el);
                                    
                                    if (rect.width <= 0 || rect.height <= 0 || 
                                        rect.top < 0 || rect.left < 0 ||
                                        rect.top >= window.innerHeight ||
                                        style.display === 'none' ||
                                        style.visibility === 'hidden' ||
                                        style.opacity === '0') {
                                        return false;
                                    }
                                    
                                    // Filter externe Links
                                    if (el.tagName.toLowerCase() === 'a') {
                                        const href = el.getAttribute('href');
                                        
                                        if (!href) return true;
                                        
                                        if (href.startsWith('mailto:') || 
                                            href.startsWith('tel:') || 
                                            href.startsWith('javascript:') ||
                                            href.startsWith('file:')) {
                                            return false;
                                        }
                                        
                                        if (href.startsWith('#')) return true;
                                        
                                        if (href.startsWith('/') && !href.startsWith('//')) return true;
                                        
                                        if (!href.includes('://') && !href.startsWith('//')) return true;
                                        
                                        try {
                                            const url = new URL(href, currentOrigin);
                                            if (url.hostname === currentHostname) return true;
                                            return false;
                                        } catch (e) {
                                            return false;
                                        }
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
                                
                                return {
                                    index: idx,
                                    selector: selector,
                                    text: (el.textContent || '').trim().substring(0, 50),
                                    tag: el.tagName.toLowerCase(),
                                    hasHref: el.hasAttribute('href'),
                                    href: href || '',
                                    isInternal: true
                                };
                            })
                            .slice(0, 50);
                    }
                """)
                
                if not clickables or len(clickables) == 0:
                    logger.debug(f"Keine klickbaren INTERNEN Elemente gefunden (Versuch {i+1})")
                    failed_attempts += 1
                    await asyncio.sleep(0.5)
                    continue
                
                # Wähle zufälliges Element (bevorzuge interne Links)
                links = [c for c in clickables if c['hasHref']]
                buttons = [c for c in clickables if not c['hasHref']]
                
                # 70% Links, 30% Buttons
                if links and (not buttons or random.random() < 0.7):
                    target = random.choice(links)
                else:
                    target = random.choice(buttons if buttons else clickables)
                
                logger.debug(f"Klicke auf: {target['text'][:30]} ({target['tag']}, href={target['href'][:30] if target['href'] else 'N/A'})")
                
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
        
        logger.info(f"✅ Random-Walk abgeschlossen: {actions_performed} erfolgreiche Aktionen (NUR interne Navigation)")
        return actions_performed
    
    @staticmethod
    async def test_navigation(page: Page, max_links: int = 5) -> int:
        """
        Testet Navigation-Links systematisch (nur interne)
        Returns: Anzahl erfolgreicher Aktionen
        """
        actions = 0
        
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
                                href.startsWith('javascript:') ||
                                href.startsWith('file:')) {
                                return false;
                            }
                            
                            if (href.startsWith('#')) return true;
                            if (href.startsWith('/') && !href.startsWith('//')) return true;
                            if (!href.includes('://') && !href.startsWith('//')) return true;
                            
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
            
            logger.info(f"Gefunden: {len(nav_links)} INTERNE Navigation-Links")
            
            for link in nav_links[:max_links]:
                try:
                    await page.click(f'a:has-text("{link["text"]}")', timeout=2000)
                    actions += 1
                    logger.info(f"✅ Navigation-Klick: {link['text']} (href: {link['href'][:30]})")
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.debug(f"Navigation-Klick fehlgeschlagen: {link['text']}: {e}")
                    continue
            
            logger.info(f"✅ Navigation-Test: {actions} erfolgreiche Klicks (NUR interne Links)")
            
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
        
        Args:
            page: Playwright Page object
            max_actions: Maximale Anzahl Aktionen
            w_model: Model-Gewichtungsparameter (default: 25 aus Paper)
            
        Returns:
            Anzahl erfolgreicher Aktionen
        """
        return await ModelGuidedStrategy.execute(page, max_actions, w_model)