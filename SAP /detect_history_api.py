from selenium import webdriver

def detect_history_api(url):
   driver = webdriver.Chrome()
   driver.get(url) 
   support = driver.execute_script("""
    return {
    hasPushState: !!(history.pushState),
    hasReplaceState: !!(history.replaceState)
    };
    """)
   return support