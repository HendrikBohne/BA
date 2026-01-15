#!/usr/bin/env python3
"""
Taint-Flow Analyzer
Analysiert findings_*.json Dateien und kategorisiert nach Gefährlichkeit
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Sink-Kategorien
CRITICAL_SINKS = ['innerHTML', 'outerHTML', 'eval', 'document.write', 'script.src', 'Function', 'setTimeout', 'setInterval']
HIGH_SINKS = ['location.href', 'location.assign', 'location.replace', 'window.open', 'a.href', 'form.action']
MEDIUM_SINKS = ['postMessage', 'document.cookie', 'localStorage.setItem', 'sessionStorage.setItem', 'indexedDB']
LOW_SINKS = ['fetch.url', 'fetch.body', 'img.src', 'XMLHttpRequest', 'navigator.sendBeacon']

# Gefährliche Sources (User-kontrollierbar)
DANGEROUS_SOURCES = ['location.hash', 'location.search', 'location.href', 'document.URL', 'document.referrer', 
                     'window.name', 'postMessage', 'document.cookie', 'localStorage', 'sessionStorage']


def categorize_sink(sink):
    """Kategorisiert einen Sink nach Gefährlichkeit"""
    sink_lower = sink.lower()
    
    for s in CRITICAL_SINKS:
        if s.lower() in sink_lower:
            return 'CRITICAL', '🔴'
    
    for s in HIGH_SINKS:
        if s.lower() in sink_lower:
            return 'HIGH', '🟠'
    
    for s in MEDIUM_SINKS:
        if s.lower() in sink_lower:
            return 'MEDIUM', '🟡'
    
    return 'LOW', '🟢'


def is_source_dangerous(sources):
    """Prüft ob eine Source User-kontrollierbar ist"""
    for source in sources:
        source_lower = str(source).lower()
        for ds in DANGEROUS_SOURCES:
            if ds.lower() in source_lower:
                return True, source
    return False, None


def analyze_flow_chain(taint):
    """Analysiert die Taint-Chain nach Sanitization"""
    sanitizers = ['replace', 'escape', 'encode', 'sanitize', 'filter', 'validate']
    found_sanitizers = []
    
    for t in taint:
        for flow in t.get('flow', []):
            op = flow.get('op', '').lower()
            for san in sanitizers:
                if san in op:
                    found_sanitizers.append(op)
    
    return found_sanitizers


def analyze_findings(filepath):
    """Hauptanalyse einer Findings-Datei"""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    
    print(f"\n{'='*60}")
    print(f"📊 TAINT-FLOW ANALYSE")
    print(f"{'='*60}")
    print(f"Datei: {filepath}")
    print(f"URL: {data.get('base_url', 'N/A')}")
    print(f"Foxhound: {'✅ Ja' if data.get('is_foxhound') else '❌ Nein'}")
    print(f"Gesamt Findings: {len(findings)}")
    print(f"{'='*60}\n")
    
    # Kategorisierung
    by_category = defaultdict(list)
    sink_counts = Counter()
    source_counts = Counter()
    
    for f in findings:
        sink = f.get('sink', 'unknown')
        sources = f.get('sources', [])
        
        category, icon = categorize_sink(sink)
        by_category[category].append(f)
        sink_counts[sink] += 1
        
        for s in sources:
            source_counts[s] += 1
    
    # Zusammenfassung
    print("📈 ZUSAMMENFASSUNG")
    print("-"*40)
    print(f"  🔴 Kritisch:  {len(by_category['CRITICAL']):3d}")
    print(f"  🟠 Hoch:      {len(by_category['HIGH']):3d}")
    print(f"  🟡 Mittel:    {len(by_category['MEDIUM']):3d}")
    print(f"  🟢 Niedrig:   {len(by_category['LOW']):3d}")
    print()
    
    # Top Sinks
    print("🎯 TOP SINKS")
    print("-"*40)
    for sink, count in sink_counts.most_common(10):
        _, icon = categorize_sink(sink)
        print(f"  {icon} {sink}: {count}")
    print()
    
    # Top Sources
    print("📥 TOP SOURCES")
    print("-"*40)
    for source, count in source_counts.most_common(10):
        dangerous, _ = is_source_dangerous([source])
        icon = '⚠️' if dangerous else '  '
        print(f"  {icon} {source}: {count}")
    print()
    
    # Kritische Flows im Detail
    if by_category['CRITICAL']:
        print("🔴 KRITISCHE FLOWS (Potentielle XSS)")
        print("="*60)
        
        for i, f in enumerate(by_category['CRITICAL'][:10], 1):
            sink = f.get('sink')
            sources = f.get('sources', [])
            value = f.get('str', '')[:80]
            script = f.get('script', '').split('/')[-1][:30]
            
            dangerous, dangerous_source = is_source_dangerous(sources)
            sanitizers = analyze_flow_chain(f.get('taint', []))
            
            print(f"\n[{i}] {sink}")
            print(f"    Source: {sources}")
            print(f"    Value: {value}...")
            print(f"    Script: {script}")
            
            if dangerous:
                print(f"    ⚠️  GEFÄHRLICH: Source '{dangerous_source}' ist User-kontrollierbar!")
            
            if sanitizers:
                print(f"    ✅ Sanitizer gefunden: {sanitizers}")
            else:
                print(f"    ❌ Keine Sanitization erkannt!")
            
            # Exploitability Score
            score = 0
            if dangerous:
                score += 50
            if not sanitizers:
                score += 30
            if 'innerHTML' in sink or 'eval' in sink:
                score += 20
            
            if score >= 70:
                print(f"    🚨 EXPLOITABILITY: HOCH ({score}%)")
            elif score >= 40:
                print(f"    ⚠️  EXPLOITABILITY: MITTEL ({score}%)")
            else:
                print(f"    ℹ️  EXPLOITABILITY: NIEDRIG ({score}%)")
    
    # High-Risk Flows
    if by_category['HIGH']:
        print(f"\n\n🟠 HIGH-RISK FLOWS (Redirect/javascript:)")
        print("="*60)
        
        for i, f in enumerate(by_category['HIGH'][:5], 1):
            sink = f.get('sink')
            sources = f.get('sources', [])
            value = f.get('str', '')[:80]
            
            print(f"\n[{i}] {sink}")
            print(f"    Source: {sources}")
            print(f"    Value: {value}...")
    
    print(f"\n{'='*60}")
    print("✅ Analyse abgeschlossen")
    print(f"{'='*60}\n")
    
    return {
        'total': len(findings),
        'critical': len(by_category['CRITICAL']),
        'high': len(by_category['HIGH']),
        'medium': len(by_category['MEDIUM']),
        'low': len(by_category['LOW'])
    }


def main():
    if len(sys.argv) < 2:
        # Finde alle findings_*.json Dateien
        findings_files = list(Path('.').glob('findings_*.json'))
        
        if not findings_files:
            print("❌ Keine findings_*.json Dateien gefunden")
            print("   Usage: python analyze_flows.py <findings.json>")
            sys.exit(1)
        
        print(f"📁 Gefundene Findings-Dateien: {len(findings_files)}")
        
        total_stats = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for fp in findings_files:
            stats = analyze_findings(fp)
            for k, v in stats.items():
                total_stats[k] += v
        
        print("\n" + "="*60)
        print("📊 GESAMTSTATISTIK")
        print("="*60)
        print(f"  Dateien analysiert: {len(findings_files)}")
        print(f"  Gesamt Flows: {total_stats['total']}")
        print(f"  🔴 Kritisch: {total_stats['critical']}")
        print(f"  🟠 Hoch: {total_stats['high']}")
        print(f"  🟡 Mittel: {total_stats['medium']}")
        print(f"  🟢 Niedrig: {total_stats['low']}")
    else:
        analyze_findings(sys.argv[1])


if __name__ == "__main__":
    main()
