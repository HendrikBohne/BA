"""
SPA Detection Tool - Model-Guided Random Walk Strategy
Implementierung basierend auf: "Improving Behavioral Program Analysis with Environment Models"
https://link.springer.com/chapter/10.1007/978-3-031-49187-0_9
"""
import asyncio
import random
import logging
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

from .state_independent_model import StateIndependentModel

logger = logging.getLogger(__name__)


class ModelGuidedStrategy:
    """
    Model-Guided Random Walk Strategie
    Erweitert Random-Walk mit State-Independent Model zur intelligenten Priorisierung
    """
    
    @staticmethod
    def create_candidate_id(element: dict) -> str:
        """
        Erstellt eindeutigen Identifier für Action Candidate
        
        Args:
            element: Dictionary mit Element-Informationen (tag, text, selector)
            
        Returns:
            Eindeutiger Candidate-ID String
        """
        tag = element.get('tag', 'unknown')
        text = element.get('text', '')[:30]  # Erste 30 Zeichen
        selector = element.get('selector', '')[:50]  # Erste 50 Zeichen
        
        return f"{tag}:{text}:{selector}"
    
    @staticmethod
    async def execute(page: Page, max_actions: int = 10, w_model: float = 25.0) -> int:
        """
        Führt Model-Guided Random Walk aus
        
        Args:
            page: Playwright Page object
            max_actions: Maximale Anzahl Aktionen
            w_model: Model-Gewichtungsparameter (default: 25 aus Paper)
            
        Returns:
            Anzahl erfolgreicher Aktionen
        """
        actions_performed = 0
        failed_attempts = 0
        max_failures = 5
        
        # Initialisiere Model
        model = StateIndependentModel(w_model=w_model)
        
        logger.info(f"🧠 Starte Model-Guided Random-Walk (max {max_actions} Aktionen, w_model={w_model})...")
        
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
                                    
                                    // Sichtbarkeits-Check
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
                                            return url.hostname === currentHostname;
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
                                
                                return {
                                    index: idx,
                                    selector: selector,
                                    text: (el.textContent || '').trim().substring(0, 50),
                                    tag: el.tagName.toLowerCase(),
                                    hasHref: el.hasAttribute('href'),
                                    href: el.getAttribute('href') || ''
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
                
                # Erstelle Candidate-IDs
                candidate_ids = [ModelGuidedStrategy.create_candidate_id(c) for c in clickables]
                
                # Registriere beobachtete Candidates im Model
                model.observe_candidates(candidate_ids)
                
                # Berechne Gewichte für alle Candidates
                weights = []
                for idx, c_id in enumerate(candidate_ids):
                    clickable = clickables[idx]
                    
                    # Basis-Gewicht (Random-Walk Heuristik)
                    base_weight = 1.0
                    
                    # Bevorzuge Links über Buttons
                    if clickable['hasHref']:
                        base_weight = 1.5
                    
                    # Model-basiertes Gewicht berechnen
                    if c_id in model.executed_candidates:
                        # Bereits ausgeführt → gewichte nach unerforschten Nachfolgern
                        final_weight = model.calculate_weight(c_id, base_weight)
                    else:
                        # Noch nicht ausgeführt → höheres Basis-Gewicht (Exploration)
                        final_weight = base_weight * 2.0
                    
                    weights.append(final_weight)
                
                # Wähle Candidate basierend auf Gewichten (probabilistisch)
                total_weight = sum(weights)
                if total_weight == 0:
                    # Fallback: Zufällige Auswahl
                    target_idx = random.randint(0, len(clickables) - 1)
                else:
                    # Weighted random choice
                    rand = random.uniform(0, total_weight)
                    cumsum = 0
                    target_idx = 0
                    for idx, weight in enumerate(weights):
                        cumsum += weight
                        if rand <= cumsum:
                            target_idx = idx
                            break
                
                target = clickables[target_idx]
                target_id = candidate_ids[target_idx]
                
                # Status-Markierung für Logging
                executed = target_id in model.executed_candidates
                status = "✓" if executed else "NEW"
                logger.debug(f"[{status}] Wähle: {target['text'][:30]} (Gewicht: {weights[target_idx]:.2f})")
                
                # Klick-Versuche
                click_success = False
                try:
                    # Methode 1: Direkter Klick
                    await page.click(target['selector'], timeout=3000)
                    click_success = True
                except PlaywrightTimeout:
                    # Methode 2: JavaScript Klick
                    try:
                        await page.evaluate(f"""
                            () => {{
                                const elements = document.querySelectorAll('{target['selector']}');
                                if (elements[{target['index']}]) {{
                                    elements[{target['index']}].click();
                                }}
                            }}
                        """)
                        click_success = True
                    except:
                        failed_attempts += 1
                        logger.debug(f"❌ Klick fehlgeschlagen: {target['text'][:30]}")
                
                if click_success:
                    actions_performed += 1
                    failed_attempts = 0
                    logger.info(f"✅ Aktion {actions_performed}: {target['text'][:30]}")
                    
                    # Warte kurz und beobachte Nachfolger-State
                    await asyncio.sleep(random.uniform(0.5, 1.0))
                    
                    # Erfasse verfügbare Nachfolger nach der Aktion
                    successors_raw = await page.evaluate("""
                        () => {
                            const elements = [
                                ...document.querySelectorAll('a, button, [role="button"]')
                            ].slice(0, 50);
                            
                            return elements.map(el => {
                                let selector = el.tagName.toLowerCase();
                                if (el.id) selector += '#' + el.id;
                                else if (el.className && typeof el.className === 'string') {
                                    const classes = el.className.split(' ').filter(c => c);
                                    if (classes[0]) selector += '.' + classes[0];
                                }
                                return {
                                    selector: selector,
                                    text: (el.textContent || '').trim().substring(0, 50),
                                    tag: el.tagName.toLowerCase()
                                };
                            });
                        }
                    """)
                    
                    successor_ids = [ModelGuidedStrategy.create_candidate_id(s) for s in successors_raw]
                    
                    # Update Model mit ausgeführtem Candidate und seinen Nachfolgern
                    model.execute_candidate(target_id, successor_ids)
                
                # Warte zwischen Aktionen (variabel)
                await asyncio.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                logger.debug(f"Interaktion {i+1} fehlgeschlagen: {e}")
                failed_attempts += 1
                await asyncio.sleep(0.5)
                continue
        
        # Finale Statistiken
        stats = model.get_stats()
        logger.info(f"✅ Model-Guided Random-Walk abgeschlossen: {actions_performed} erfolgreiche Aktionen")
        logger.info(f"📊 Model-Stats: {stats['total_candidates']} Candidates, "
                   f"{stats['executed_candidates']} ausgeführt "
                   f"({stats['execution_rate']:.1%}), "
                   f"∅ {stats['avg_successors']:.1f} Nachfolger")
        
        return actions_performed