# DOM XSS Trigger Strategies

**Bachelorarbeit-Projekt: Automatisierte Erkennung von Client-Side XSS in Single-Page Applications**

## Überblick

Dieses Tool implementiert drei verschiedene Interaktionsstrategien zur automatisierten Erkennung von DOM-basierten Cross-Site-Scripting (XSS) Schwachstellen in Single-Page Applications. Es nutzt [Foxhound](https://github.com/nicksanderson/nicksanderson.github.io) als Taint-Tracking-Browser, um Datenflüsse von Sources (Benutzereingaben) zu Sinks (gefährliche Operationen) zu verfolgen.

## Die drei Strategien

### 1. Random Walk (`random_walk.py`)
- **Ansatz:** Zufällige Auswahl von Interaktionselementen
- **Zweck:** Baseline für Vergleiche
- **Charakteristik:** Gleichmäßige Exploration ohne Priorisierung

### 2. Model-Guided Random Walk (`model_guided.py`)
- **Ansatz:** State-Independent Model zur Priorisierung unerforschter Pfade
- **Basis:** [Improving Behavioral Program Analysis with Environment Models](https://link.springer.com/chapter/10.1007/978-3-031-49187-0_9)
- **Charakteristik:** Lernt Beziehungen zwischen Aktionen und priorisiert Kandidaten mit hohem Explorationspotential

### 3. DOM Maximizer (`dom_maximizer.py`)
- **Ansatz:** Maximierung der DOM-Größe und -Tiefe
- **Zweck:** Triggern von Lazy-Loading, dynamischen Inhalten und versteckten Funktionalitäten
- **Charakteristik:** Priorisiert Aktionen die neue DOM-Elemente erzeugen

## Installation

```bash
# Repository klonen
git clone <repo-url>
cd domxss-trigger-strategies

# Virtuelle Umgebung erstellen
python -m venv venv
source venv/bin/activate  # Linux/Mac
# oder: venv\Scripts\activate  # Windows

# Dependencies installieren
pip install -r requirements.txt

# Playwright Browser installieren
playwright install firefox

# Foxhound Browser installieren (siehe Dokumentation)
```

## Verwendung

```bash
# Einzelne URL analysieren
python main.py https://target-spa.com

# Bestimmte Strategie verwenden
python main.py https://target-spa.com --strategy model_guided

# Alle Strategien vergleichen
python main.py https://target-spa.com --compare-all

# Mit Report-Ausgabe
python main.py https://target-spa.com --output results/ --format both

# Batch-Analyse mit URL-Liste
python main.py urls.txt --strategy random_walk --output results/

# Headless-Modus
python main.py https://target-spa.com --headless --verbose
```

## CLI Optionen

```
usage: main.py [-h] [--strategy {random_walk,model_guided,dom_maximizer}]
               [--compare-all] [--max-actions N] [--foxhound-path PATH]
               [--headless] [--timeout SECONDS] [--output PATH]
               [--format {json,html,both}] [--verbose] [--quiet]
               target

positional arguments:
  target                Ziel-URL oder Datei mit URLs

Strategie-Optionen:
  --strategy, -s        Interaktionsstrategie (default: model_guided)
  --compare-all, -c     Führe alle Strategien aus und vergleiche
  --max-actions, -n     Maximale Interaktionen (default: 50)

Browser-Optionen:
  --foxhound-path       Pfad zur Foxhound-Installation
  --headless            Browser im Headless-Modus
  --timeout             Timeout pro URL in Sekunden (default: 300)

Ausgabe-Optionen:
  --output, -o          Ausgabeverzeichnis für Reports
  --format, -f          Report-Format: json, html, both (default: both)
  --verbose, -v         Ausführliche Logs
  --quiet, -q           Nur Ergebnisse ausgeben
```

## Projektstruktur

```
domxss-trigger-strategies/
├── main.py                          # CLI Entry Point
├── requirements.txt
├── README.md
│
├── strategies/                       # Die 3 Interaktionsstrategien
│   ├── __init__.py
│   ├── base_strategy.py             # Abstrakte Basisklasse
│   ├── random_walk.py               # Strategie 1: Random Walk
│   ├── model_guided.py              # Strategie 2: Model-Guided
│   └── dom_maximizer.py             # Strategie 3: DOM-Maximierung
│
├── foxhound/                         # Foxhound Browser Integration
│   ├── __init__.py
│   ├── controller.py                # Browser steuern
│   ├── taint_parser.py              # Taint-Logs parsen
│   └── taint_flow.py                # TaintFlow Dataclass
│
├── analysis/                         # Auswertung
│   ├── __init__.py
│   ├── coverage.py                  # Code-Coverage Analyse
│   ├── vulnerability.py             # XSS Detection
│   └── metrics.py                   # Evaluation-Metriken
│
├── reporting/                        # Report-Generierung
│   ├── __init__.py
│   ├── json_reporter.py
│   ├── html_reporter.py
│   └── comparison.py                # Strategie-Vergleich
│
├── config/                           # Konfiguration
│   ├── default.yaml                 # Allgemeine Einstellungen
│   ├── sources.yaml                 # XSS Sources Definition
│   └── sinks.yaml                   # XSS Sinks Definition
│
├── evaluation/                       # Wissenschaftliche Evaluation
│   ├── __init__.py
│   ├── benchmark_runner.py          # Benchmark-Tests
│   ├── strategy_comparator.py       # Statistische Vergleiche
│   └── test_suite/                  # Test-Anwendungen
│
└── utils/                            # Hilfsfunktionen
    ├── __init__.py
    ├── dom_utils.py
    ├── url_utils.py
    └── logging_config.py
```

## Taint-Tracking Konzept

### Sources (Benutzerkontrollierte Eingaben)
- **URL-basiert:** `location.hash`, `location.search`, `document.URL`
- **Storage:** `localStorage`, `sessionStorage`, `document.cookie`
- **DOM:** `window.name`, `postMessage.data`, `input.value`

### Sinks (Gefährliche Operationen)
- **HTML-Injection:** `innerHTML`, `outerHTML`, `document.write`
- **JS-Execution:** `eval`, `Function()`, `setTimeout(string)`
- **URL-Redirect:** `location.href`, `location.assign`, `window.open`

## Evaluation

Die Test-Suite enthält vulnerable SPAs zum Testen:

```bash
# Benchmark gegen Test-Suite ausführen
python -m evaluation.benchmark_runner

# Statistische Analyse
python -m evaluation.strategy_comparator results/
```

## Autor

Hendrik - Bachelorarbeit 2025

## Lizenz

MIT License
