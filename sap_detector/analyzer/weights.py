"""
SPA Detection Tool - Signal Weights Configuration
Zentrale Konfiguration der Signal-Gewichtung für die SPA-Erkennung
"""

# Gewichtung der einzelnen Detektions-Signale
# Die Summe sollte idealerweise 1.0 ergeben
SIGNAL_WEIGHTS = {
    "History-API Navigation": 0.30,      # Stärkstes SPA-Signal
    "Network Activity Pattern": 0.30,     # Sehr charakteristisch
    "DOM Rewriting Pattern": 0.25,        # Sehr charakteristisch
    "Title Change Pattern": 0.05,         # Unterstützend
    "Clickable Element Pattern": 0.10     # Unterstützend
}

# Hinweis: Diese Gewichte können angepasst werden, um die
# Sensitivität der Erkennung für spezifische Signale zu ändern.
# 
# Beispiel: Wenn History-API besonders wichtig ist:
# "History-API Navigation": 0.40,
# "Network Activity Pattern": 0.20,
# "DOM Rewriting Pattern": 0.20,
# "Title Change Pattern": 0.10,
# "Clickable Element Pattern": 0.10