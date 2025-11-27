from playwright.sync_api import sync_playwright

# Dein History-Patch-Skript einmal global definieren
HISTORY_HOOK_SCRIPT = """
(() => {
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    window._pushStateCount = 0;
    window._replaceStateCount = 0;

    history.pushState = function(...args) {
        window._pushStateCount++;
        return originalPushState.apply(this, args);
    };

    history.replaceState = function(...args) {
        window._replaceStateCount++;
        return originalReplaceState.apply(this, args);
    };
})();
"""

def analyze_url(page, url: str) -> dict:
    """
    Lädt die URL im übergebenen Page-Objekt und gibt ein Dict mit
    pushState- und replaceState-Aufrufen zurück.
    """
    page.goto(url, wait_until="networkidle")

    # Counts aus dem Window holen
    result = page.evaluate(
        """
        () => ({
            push: window._pushStateCount ?? 0,
            replace: window._replaceStateCount ?? 0
        })
        """
    )
    return result  # z.B. {'push': 3, 'replace': 1}


def main():
    url_list = [
        "https://stw-on.de/braunschweig/essen/mensen-cafeterien/mensa-1",
        "https://www.jweimar.de",
        "https://open.spotify.com/intl-de",
        "https://www.google.com/maps/@52.2730435,10.529193,6478m/data=!3m1!1e3?entry=ttu&g_ep=EgoyMDI1MTAyMi4wIKXMDSoASAFQAw%3D%3D",
        "https://www.tiktok.com",
        "http://127.0.0.1:5500/SAP%20/test.html?a=1&b=2&c=3"
    ]

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        page = browser.new_page()

        # History-Hook für jede Navigation aktiv machen
        page.add_init_script(HISTORY_HOOK_SCRIPT)

        for url in url_list:
            result = analyze_url(page, url)
            print(f"URL: {url}")
            print(f"  pushState-Aufrufe:   {result['push']}")
            print(f"  replaceState-Aufrufe:{result['replace']}")
            print("-" * 40)

        browser.close()


if __name__ == "__main__":
    main()
