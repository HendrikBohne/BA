import time
import re
import requests

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from typing import Dict, Any

# --------- Konfiguration ---------
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141 Safari/537.36"
MARKERS = ("data-reactroot", 'id="__next"', "ng-version", 'id="root"', 'id="app"')
RATIO_THRESHOLD = 1.4       # Verhältnis gerendert/statisch
MIN_ABS_DELTA = 10_000      # Mindestzuwachs an Zeichen

# --------- Utils ---------
def normalize_html(s: str) -> str:
    return re.sub(r"\s+", " ", s or "")

def mk_driver() -> webdriver.Chrome:
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--window-size=1366,768")
    opts.add_argument("--lang=de-DE")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-logging")
    opts.add_argument("--disable-variations")
    opts.add_argument("--disable-field-trial-config")
    opts.add_argument(f"--user-agent={UA}")
    return webdriver.Chrome(options=opts)

def resource_count_total(driver) -> int:
    return driver.execute_script("return performance.getEntriesByType('resource').length")

def resource_count_filtered(driver) -> int:
    # Ignoriere „Rauschen“ (beacon/other). Zähle nur relevante Typen.
    return driver.execute_script("""
        const keep = new Set(['script','link','img','css','xmlhttprequest','fetch']);
        return performance.getEntriesByType('resource')
            .filter(e => keep.has(e.initiatorType)).length;
    """)

def wait_network_idle(driver, quiet_ms=1500, timeout=25, filtered=True):
    """
    Wartet, bis DOM 'complete' ist und anschließend so lange,
    bis während 'quiet_ms' ms die Zahl der Ressourcen stabil bleibt.
    'filtered=True' zählt nur relevante Ressourcentypen.
    """
    WebDriverWait(driver, timeout).until(
        lambda d: d.execute_script("return document.readyState") == "complete"
    )

    count_fn = resource_count_filtered if filtered else resource_count_total
    end = time.time() + timeout
    last = count_fn(driver)
    stable_since = time.time()

    while time.time() < end:
        time.sleep(0.25)  # Polling-Intervall
        current = count_fn(driver)
        if current != last:
            last = current
            stable_since = time.time()
        elif (time.time() - stable_since) * 1000 >= quiet_ms:
            break  # lange genug stabil

    # explizit kein Fehlerwurf hier; Aufrufer kann selbst entscheiden

def dismiss_cookie_if_present(driver, timeout=5):
    """Heuristischer Cookie-Dismiss; ggf. seiten-spezifisch anpassen."""
    try:
        btn = WebDriverWait(driver, timeout).until(
            EC.element_to_be_clickable((
                By.XPATH,
                "//button[contains(., 'Alle akzeptieren') or contains(., 'Akzeptieren') or contains(., 'Accept all') or contains(., 'Accept')]"
            ))
        )
        btn.click()
        wait_network_idle(driver, quiet_ms=800, timeout=10)
    except Exception:
        pass  # kein harter Fail, wenn kein Banner gefunden wird

# --------- Hauptlogik ---------
def fetch_static(url: str, timeout=10) -> str:
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": UA, "Accept-Language": "de-DE,de;q=0.9"},
        )
        return r.text if r.status_code == 200 else ""
    except Exception:
        return ""

def page_source_vs_rendered_dom(url: str, static_timeout=10, render_timeout=25) -> bool:
    # 1) Statische Sicht (ohne JS)
    raw = fetch_static(url, timeout=static_timeout)

    # 2) Gerenderte Sicht (mit JS)
    driver = mk_driver()
    try:
        driver.get(url)
        try:
            wait_network_idle(driver, quiet_ms=1500, timeout=render_timeout, filtered=True)
        except TimeoutException:
            # Bei Hardcore-dynamischen Seiten notfalls weiter ohne „idle“-Garant
            pass

        dismiss_cookie_if_present(driver)  # optional; macht Runs konsistenter

        rendered = driver.execute_script("return document.documentElement.outerHTML")

        # 3) Heuristik
        raw_n = normalize_html(raw)
        rend_n = normalize_html(rendered)
        has_markers = any(m in rend_n for m in MARKERS)

        if raw_n:
            ratio = len(rend_n) / max(len(raw_n), 1)
            big_delta = (len(rend_n) - len(raw_n)) > MIN_ABS_DELTA
            return (ratio > RATIO_THRESHOLD and big_delta) or has_markers
        else:
            # Falls statisch leer/abgewiesen (403/redirect), nur Marker werten
            return has_markers
    finally:
        driver.quit()


