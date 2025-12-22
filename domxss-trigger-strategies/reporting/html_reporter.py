"""
DOM XSS Trigger Strategies - HTML Reporter
Generiert HTML-Reports für Analyse-Ergebnisse
"""
import logging
from pathlib import Path
from datetime import datetime
from typing import Union, List

from analysis.metrics import StrategyMetrics, ComparisonResult

logger = logging.getLogger(__name__)


class HTMLReporter:
    """
    Generiert HTML-Reports mit Visualisierungen.
    """
    
    # HTML Template für Metriken
    METRICS_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOM XSS Analysis Report - {strategy_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5; 
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 30px; 
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.9; font-size: 0.9em; }}
        .card {{ 
            background: white; 
            border-radius: 10px; 
            padding: 20px; 
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .card h2 {{ 
            color: #667eea; 
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }}
        .metrics-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
        }}
        .metric {{ 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{ 
            font-size: 2em; 
            font-weight: bold; 
            color: #667eea;
        }}
        .metric-label {{ 
            font-size: 0.85em; 
            color: #666;
            margin-top: 5px;
        }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .progress-bar {{ 
            height: 8px; 
            background: #e9ecef; 
            border-radius: 4px;
            overflow: hidden;
        }}
        .progress-fill {{ 
            height: 100%; 
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 4px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 DOM XSS Analysis Report</h1>
            <div class="meta">
                <strong>Strategie:</strong> {strategy_name} | 
                <strong>URL:</strong> {url} |
                <strong>Generiert:</strong> {generated_at}
            </div>
        </header>
        
        <div class="card">
            <h2>📊 Übersicht</h2>
            <div class="metrics-grid">
                <div class="metric">
                    <div class="metric-value">{total_flows}</div>
                    <div class="metric-label">Taint-Flows</div>
                </div>
                <div class="metric">
                    <div class="metric-value severity-critical">{exploitable_flows}</div>
                    <div class="metric-label">Exploitable</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{actions_performed}</div>
                    <div class="metric-label">Aktionen</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{duration}s</div>
                    <div class="metric-label">Dauer</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🎯 Effizienz</h2>
            <div class="metrics-grid">
                <div class="metric">
                    <div class="metric-value">{flows_per_action}</div>
                    <div class="metric-label">Flows/Aktion</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{flows_per_second}</div>
                    <div class="metric-label">Flows/Sekunde</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{success_rate}%</div>
                    <div class="metric-label">Erfolgsrate</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{candidate_rate}%</div>
                    <div class="metric-label">Candidate Execution</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📈 DOM-Entwicklung</h2>
            <div class="metrics-grid">
                <div class="metric">
                    <div class="metric-value">{initial_dom}</div>
                    <div class="metric-label">Initial</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{final_dom}</div>
                    <div class="metric-label">Final</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{dom_growth}x</div>
                    <div class="metric-label">Wachstum</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{max_dom}</div>
                    <div class="metric-label">Maximum</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🚨 Vulnerabilities nach Severity</h2>
            <div class="metrics-grid">
                <div class="metric">
                    <div class="metric-value severity-critical">{critical_count}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="metric">
                    <div class="metric-value severity-high">{high_count}</div>
                    <div class="metric-label">High</div>
                </div>
                <div class="metric">
                    <div class="metric-value severity-medium">{medium_count}</div>
                    <div class="metric-label">Medium</div>
                </div>
                <div class="metric">
                    <div class="metric-value severity-low">{low_count}</div>
                    <div class="metric-label">Low</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📍 Flows nach Source-Typ</h2>
            <table>
                <tr><th>Source</th><th>Anzahl</th><th>Anteil</th></tr>
                <tr><td>URL (hash, search)</td><td>{flows_url}</td><td><div class="progress-bar"><div class="progress-fill" style="width: {flows_url_pct}%"></div></div></td></tr>
                <tr><td>Storage (localStorage, sessionStorage)</td><td>{flows_storage}</td><td><div class="progress-bar"><div class="progress-fill" style="width: {flows_storage_pct}%"></div></div></td></tr>
                <tr><td>DOM (window.name, postMessage)</td><td>{flows_dom}</td><td><div class="progress-bar"><div class="progress-fill" style="width: {flows_dom_pct}%"></div></div></td></tr>
                <tr><td>User Input</td><td>{flows_input}</td><td><div class="progress-bar"><div class="progress-fill" style="width: {flows_input_pct}%"></div></div></td></tr>
            </table>
        </div>
        
        <footer style="text-align: center; padding: 20px; color: #666;">
            <p>DOM XSS Trigger Strategies - Bachelorarbeit 2025</p>
        </footer>
    </div>
</body>
</html>
"""
    
    @staticmethod
    def save_metrics(metrics: StrategyMetrics, output_path: Union[str, Path]):
        """Speichert StrategyMetrics als HTML"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = metrics.to_dict()
        taint = data.get('taint', {})
        efficiency = data.get('efficiency', {})
        dom = data.get('dom', {})
        
        total_flows = taint.get('total_flows', 0)
        
        html = HTMLReporter.METRICS_TEMPLATE.format(
            strategy_name=metrics.strategy_name,
            url=metrics.url,
            generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_flows=total_flows,
            exploitable_flows=taint.get('exploitable_flows', 0),
            actions_performed=efficiency.get('actions_performed', 0),
            duration=f"{efficiency.get('duration_seconds', 0):.1f}",
            flows_per_action=f"{metrics.flows_per_action:.2f}",
            flows_per_second=f"{metrics.flows_per_second:.2f}",
            success_rate=f"{efficiency.get('success_rate', 0) * 100:.1f}",
            candidate_rate=f"{metrics.candidate_execution_rate * 100:.1f}",
            initial_dom=dom.get('initial_size', 0),
            final_dom=dom.get('final_size', 0),
            dom_growth=f"{dom.get('growth_ratio', 1):.2f}",
            max_dom=dom.get('max_size', 0),
            critical_count=taint.get('by_severity', {}).get('critical', 0),
            high_count=taint.get('by_severity', {}).get('high', 0),
            medium_count=taint.get('by_severity', {}).get('medium', 0),
            low_count=taint.get('by_severity', {}).get('low', 0),
            flows_url=taint.get('by_source', {}).get('url', 0),
            flows_url_pct=min(100, (taint.get('by_source', {}).get('url', 0) / max(1, total_flows)) * 100),
            flows_storage=taint.get('by_source', {}).get('storage', 0),
            flows_storage_pct=min(100, (taint.get('by_source', {}).get('storage', 0) / max(1, total_flows)) * 100),
            flows_dom=taint.get('by_source', {}).get('dom', 0),
            flows_dom_pct=min(100, (taint.get('by_source', {}).get('dom', 0) / max(1, total_flows)) * 100),
            flows_input=taint.get('by_source', {}).get('user_input', 0),
            flows_input_pct=min(100, (taint.get('by_source', {}).get('user_input', 0) / max(1, total_flows)) * 100),
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"📄 HTML-Report gespeichert: {output_path}")
    
    @staticmethod
    def save_comparison(comparison: ComparisonResult, output_path: Union[str, Path]):
        """Speichert ComparisonResult als HTML"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generiere Tabellen-Rows
        table_rows = ""
        for row in comparison.to_summary_table():
            table_rows += f"""
            <tr>
                <td><strong>{row['strategy']}</strong></td>
                <td>{row['flows']}</td>
                <td>{row['vulnerabilities']}</td>
                <td>{row['coverage']}</td>
                <td>{row['efficiency']}</td>
                <td>{row['duration']}</td>
            </tr>
            """
        
        html = f"""
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Strategie-Vergleich - {comparison.url}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #667eea; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .winner {{ background: #d4edda !important; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>🏁 Strategie-Vergleich</h1>
    <p><strong>URL:</strong> {comparison.url}</p>
    <p><strong>Generiert:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <table>
        <thead>
            <tr>
                <th>Strategie</th>
                <th>Flows</th>
                <th>Vulnerabilities</th>
                <th>Coverage</th>
                <th>Effizienz</th>
                <th>Dauer</th>
            </tr>
        </thead>
        <tbody>
            {table_rows}
        </tbody>
    </table>
    
    <h2>🏆 Gewinner</h2>
    <ul>
        <li><strong>Nach Vulnerabilities:</strong> {comparison.get_winner('vulnerabilities') or 'N/A'}</li>
        <li><strong>Nach Flows:</strong> {comparison.get_winner('flows_found') or 'N/A'}</li>
        <li><strong>Nach Coverage:</strong> {comparison.get_winner('coverage') or 'N/A'}</li>
        <li><strong>Nach Effizienz:</strong> {comparison.get_winner('efficiency') or 'N/A'}</li>
    </ul>
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"📄 HTML-Comparison gespeichert: {output_path}")
