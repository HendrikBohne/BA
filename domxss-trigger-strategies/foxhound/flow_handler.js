/* eslint-disable no-unused-vars */
/**
 * Foxhound Flow Handler
 * Fängt echte Taint-Reports von Foxhound ab und sendet sie an Python.
 * 
 * Muss mit add_init_script() VOR der Navigation injiziert werden!
 */
(function () {
    // Verhindere Mehrfach-Installation
    if (window.__foxhound_flow_handler_installed) return;
    window.__foxhound_flow_handler_installed = true;
    
    // Kopiert Flow-Operationen
    function copyFlow(operations) {
        let copy = [];
        for (let i in operations) {
            copy.push({
                op: operations[i].operation,
                param1: operations[i].arguments[0] || "",
                param2: operations[i].arguments[1] || "",
                param3: operations[i].arguments[2] || "",
                location: operations[i].location
            });
        }
        return copy;
    }
    
    // Kopiert Taint-Informationen
    function copyTaint(taint) {
        let copy = [];
        for (let i in taint) {
            copy.push({
                begin: taint[i].begin, 
                end: taint[i].end, 
                flow: copyFlow(taint[i].flow)
            });
        }
        return copy;
    }
    
    // Extrahiert Sources aus Taint-Flow
    function createSources(taint) {
        let sources = [];
        for (let i in taint) {
            let flow = taint[i].flow;
            if (flow && flow.length > 0) {
                sources.push(flow[flow.length - 1].operation);
            }
        }
        return sources;
    }
    
    // Erstellt eine Kopie des Findings
    function copyFinding(finding) {
        let taint = [];
        let sources = [];
        
        // Versuche Taint-Daten zu extrahieren
        try {
            if (finding.str && finding.str.taint) {
                taint = copyTaint(finding.str.taint);
                sources = createSources(finding.str.taint);
            }
        } catch (e) {
            console.log('[FlowHandler] Taint extraction error:', e);
        }
        
        let copy = {
            "subframe": finding.subframe || false,
            "loc": finding.loc || location.href,
            "parentloc": finding.parentloc || "",
            "referrer": finding.referrer || document.referrer,
            "script": (finding.stack && finding.stack.source) || "",
            "line": (finding.stack && finding.stack.line) || 0,
            "str": String(finding.str || "").substring(0, 1000),
            "sink": finding.sink || "",
            "taint": taint,
            "sources": sources,
            "domain": location.hostname,
            "url": location.href,
            "timestamp": Date.now()
        };
        
        return copy;
    }
    
    // Event listener für Foxhound Taint-Reports
    window.addEventListener("__taintreport", (r) => {
        try {
            let finding = copyFinding(r.detail);
            
            // Sende an Python via exposed binding
            if (typeof __foxhound_taint_report === 'function') {
                __foxhound_taint_report(finding);
            } else {
                // Fallback: Speichere in globalem Array
                window.__foxhound_findings = window.__foxhound_findings || [];
                window.__foxhound_findings.push(finding);
                console.log('[FlowHandler] Taint finding stored (no binding):', finding.sink);
            }
        } catch (e) {
            console.log('[FlowHandler] Error processing taint report:', e);
        }
    });
    
    console.log('[FlowHandler] Foxhound taint handler installed');
})();
