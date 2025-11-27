from selenium import webdriver


addon_path = "https://www.mozilla.org/firefox/download/thanks/?s=direct&utm_campaign=amo-fx-cta-10229&utm_content=rta%3Ad2FwcGFseXplckBjcnVuY2hsYWJ6LmNvbQ&utm_medium=referral&utm_source=addons.mozilla.org"

# Überarbeiten sollte eher auf detection von wappalyzer in Firefox setzen (firefox soll besser sein die daten auszulesen die ich brauche)




def detect_frameworks(url):
    options = webdriver.FirefoxOptions()
    driver = webdriver.Firefox(options=options)
    #driver.install_addon(addon_path, temporary=False)

    # vorausgesetzt: internal_uuid bekannt, z.B. aus extensions.webextensions.uuids
    driver.get(url)
    driver.get(f"moz-extension://{"7421f4b3-5168-4c00-a063-0996b2d2a473"}/options.html")
    html = driver.page_source
    print(html[:500])  # Beispiel: ersten 500 Zeichen



    





detect_frameworks("https://open.spotify.com")
detect_frameworks("https://de.khanacademy.org/")
detect_frameworks("https://www.mi.com/de/")
