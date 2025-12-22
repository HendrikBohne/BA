"""
SPA Detection Tool - Signal Weights Configuration (v4)
Zentrale Konfiguration der Signal-Gewichtung für die SPA-Erkennung

ÄNDERUNGEN v4:
- History-API ist jetzt HARD SIGNAL mit höchstem Gewicht
- DOM und Network reduziert (werden durch Gating weiter reduziert wenn kein Hard Signal)
- Title und Clickable leicht erhöht als unterstützende Signale
"""

# Gewichtung der einzelnen Detektions-Signale
SIGNAL_WEIGHTS = {
    "History-API Navigation": 0.40,      # HARD SIGNAL - höchstes Gewicht!
    "Network Activity Pattern": 0.20,    # Reduziert (war 0.30)
    "DOM Rewriting Pattern": 0.20,       # Reduziert (war 0.25)
    "Title Change Pattern": 0.10,        # Erhöht (war 0.05)
    "Clickable Element Pattern": 0.10    # Gleich
}

# GATING MULTIPLIKATOR
# Wenn kein Hard Signal (History-API) vorhanden ist,
# werden DOM und Network mit diesem Faktor multipliziert
GATING_MULTIPLIER_NO_HARD_SIGNAL = 0.35

# ANTI-SIGNAL PENALTY
# Pro Frame-Navigation ohne entsprechenden History-Call
ANTI_SIGNAL_PENALTY_PER_NAVIGATION = 0.05
ANTI_SIGNAL_PENALTY_MAX = 0.25

# Hinweis zur Logik:
# 
# MIT Hard Signal (History-API detected):
#   - Normale Gewichtung
#   - SPA sehr wahrscheinlich bei Score >= 0.45
#
# OHNE Hard Signal:
#   - DOM/Network zählen nur 35%
#   - SPA nur bei sehr hohem Score UND vielen anderen Signalen
#   - Sonst: "Dynamische Seite" statt "SPA"
