#!/usr/bin/env python3
"""
Debug-Skript: Testet ob Kandidaten auf der Seite gefunden werden
"""
import asyncio
import sys
from playwright.async_api import async_playwright

async def debug_candidates(url: str):
    """Testet Kandidaten-Erkennung direkt"""
    print(f"\n🔍 Debug: Teste Kandidaten-Erkennung für {url}\n")
    
    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        print(f"1️⃣ Navigiere zu {url}...")
        await page.goto(url, wait_until='networkidle')
        print("   ✅ Seite geladen")
        
        # Warte kurz
        await asyncio.sleep(2)
        
        # Teste einfache Selektoren
        print("\n2️⃣ Teste einfache Selektoren:")
        
        selectors = [
            ('Links (a)', 'a'),
            ('Buttons', 'button'),
            ('Inputs', 'input'),
            ('Textareas', 'textarea'),
            ('Forms', 'form'),
            ('Klickbare ([onclick])', '[onclick]'),
            ('Alle interaktiven', 'a, button, input, textarea, [onclick]'),
        ]
        
        for name, selector in selectors:
            try:
                count = await page.evaluate(f"""
                    () => document.querySelectorAll('{selector}').length
                """)
                print(f"   {name}: {count} gefunden")
            except Exception as e:
                print(f"   {name}: FEHLER - {e}")
        
        # Teste die vollständige Kandidaten-Logik
        print("\n3️⃣ Teste vollständige Kandidaten-Erkennung:")
        
        try:
            candidates = await page.evaluate("""
                () => {
                    const results = [];
                    const errors = [];
                    
                    try {
                        // Alle interaktiven Elemente
                        const elements = document.querySelectorAll(
                            'input, textarea, button, a[href], [onclick], select, form'
                        );
                        
                        elements.forEach((el, idx) => {
                            try {
                                const rect = el.getBoundingClientRect();
                                const tag = el.tagName.toLowerCase();
                                
                                results.push({
                                    tag: tag,
                                    id: el.id || null,
                                    name: el.name || null,
                                    type: el.type || null,
                                    text: (el.textContent || el.value || '').trim().substring(0, 30),
                                    visible: rect.width > 0 && rect.height > 0,
                                    hasOnclick: el.hasAttribute('onclick'),
                                    href: el.getAttribute('href') || null
                                });
                            } catch (e) {
                                errors.push('Element error: ' + e.message);
                            }
                        });
                    } catch (e) {
                        errors.push('Main error: ' + e.message);
                    }
                    
                    return { results, errors };
                }
            """)
            
            if candidates['errors']:
                print(f"   ⚠️ Fehler: {candidates['errors']}")
            
            print(f"   Gefunden: {len(candidates['results'])} Elemente")
            
            for i, c in enumerate(candidates['results'][:20]):
                vis = "✅" if c['visible'] else "❌"
                onclick = "🖱️" if c['hasOnclick'] else ""
                print(f"   {i+1}. {vis} <{c['tag']}> id={c['id']} name={c['name']} type={c['type']} {onclick}")
                if c['text']:
                    print(f"       Text: '{c['text']}'")
                    
        except Exception as e:
            print(f"   ❌ FEHLER: {e}")
            import traceback
            traceback.print_exc()
        
        # Teste DOM-Struktur
        print("\n4️⃣ DOM-Struktur:")
        try:
            html = await page.content()
            print(f"   HTML-Länge: {len(html)} Zeichen")
            
            # Zeige ersten Teil
            print(f"\n   Erste 1000 Zeichen:")
            print("-" * 60)
            print(html[:1000])
            print("-" * 60)
            
        except Exception as e:
            print(f"   ❌ FEHLER: {e}")
        
        await browser.close()
        print("\n✅ Debug abgeschlossen\n")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080/vulnerable_spa_1/"
    asyncio.run(debug_candidates(url))
