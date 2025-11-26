from page_source_vs_rendered_dom import page_source_vs_rendered_dom
from detect_frameworks_with_selenium import detect_frameworks_with_selenium
from detect_history_api import detect_history_api

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


# --------- Demo ---------
if __name__ == "__main__":
    tests = [
        "https://www.jweimar.de",
        "https://open.spotify.com/intl-de",
        "https://www.google.com/maps/@52.2730435,10.529193,6478m/data=!3m1!1e3?entry=ttu&g_ep=EgoyMDI1MTAyMi4wIKXMDSoASAFQAw%3D%3D",
        "https://www.tiktok.com"
    ]
    for u in tests:
        try:
            print(u, "→", page_source_vs_rendered_dom(u))
            print(u, detect_frameworks_with_selenium(u))
            print(u, "detect history api", detect_history_api(u))
        except Exception as e:
            print(u, "→ ERROR:", type(e).__name__, e)