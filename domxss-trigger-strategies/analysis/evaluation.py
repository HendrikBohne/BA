#!/usr/bin/env python3
"""
DOM XSS Trigger Strategies - Evaluation Metrics

Based on evaluation methodology:
- JavaScript byte coverage (DevTools Coverage API)
- Security impact (confirmed DOM-XSS cases)
- Efficiency metrics (time to first bug, bugs per hour)
- Statistics (arithmetic mean, median)

Two datasets:
1. Real-world websites (broad sample)
2. Open-source web applications (reproducible containers)
"""
import json
import asyncio
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from statistics import mean, median, stdev

logger = logging.getLogger(__name__)


@dataclass
class CoverageData:
    """JavaScript Coverage Data from DevTools"""
    total_bytes: int = 0
    used_bytes: int = 0
    coverage_percent: float = 0.0
    scripts_total: int = 0
    scripts_covered: int = 0
    
    # Detailed per-script coverage
    script_coverage: List[Dict] = field(default_factory=list)


@dataclass 
class SecurityFinding:
    """A confirmed DOM-XSS vulnerability"""
    sink: str
    source: str
    payload: str
    url: str
    script: str
    line: int
    timestamp: float
    confidence: float
    exploitable: bool = False
    
    # For confirmed cases: payload reached sink and was rendered/executed
    confirmed: bool = False
    rendered: bool = False
    executed: bool = False


@dataclass
class EfficiencyMetrics:
    """Efficiency metrics for a single run"""
    total_duration_seconds: float = 0.0
    time_to_first_flow_seconds: Optional[float] = None
    time_to_first_bug_seconds: Optional[float] = None
    
    # Rates
    flows_per_hour: float = 0.0
    bugs_per_hour: float = 0.0
    actions_per_second: float = 0.0
    
    # Counts
    total_flows: int = 0
    total_bugs: int = 0  # Confirmed DOM-XSS
    total_actions: int = 0


@dataclass
class EvaluationRun:
    """Single evaluation run for one URL with one strategy"""
    url: str
    strategy: str
    timestamp: str
    run_id: str
    
    # Duration
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    
    # Coverage
    coverage: CoverageData = field(default_factory=CoverageData)
    
    # Security
    taint_flows: int = 0
    confirmed_vulnerabilities: int = 0
    findings: List[SecurityFinding] = field(default_factory=list)
    
    # Efficiency
    efficiency: EfficiencyMetrics = field(default_factory=EfficiencyMetrics)
    
    # DOM Metrics
    initial_dom_size: int = 0
    final_dom_size: int = 0
    max_dom_size: int = 0
    
    # Actions
    actions_performed: int = 0
    inputs_filled: int = 0
    payloads_injected: int = 0
    
    # Errors
    errors: List[str] = field(default_factory=list)


@dataclass
class DatasetEvaluation:
    """Evaluation results for an entire dataset"""
    dataset_name: str  # "real_world" or "test_apps"
    timestamp: str
    
    # Runs
    runs: List[EvaluationRun] = field(default_factory=list)
    
    # Aggregated Statistics
    total_urls: int = 0
    successful_urls: int = 0
    failed_urls: int = 0
    
    # Coverage Statistics (mean, median)
    coverage_mean: float = 0.0
    coverage_median: float = 0.0
    coverage_stdev: float = 0.0
    
    # Security Statistics
    total_flows: int = 0
    total_confirmed_bugs: int = 0
    urls_with_bugs: int = 0
    
    # Efficiency Statistics
    mean_time_to_first_bug: Optional[float] = None
    median_time_to_first_bug: Optional[float] = None
    mean_bugs_per_hour: float = 0.0
    median_bugs_per_hour: float = 0.0
    
    # Duration
    total_duration_seconds: float = 0.0
    mean_duration_per_url: float = 0.0


class JSCoverageCollector:
    """
    Collects JavaScript byte coverage using Chrome DevTools Protocol.
    Works with Playwright's CDP session.
    """
    
    def __init__(self):
        self.coverage_data: List[Dict] = []
        self._started = False
    
    async def start(self, page) -> bool:
        """Start collecting JS coverage"""
        try:
            # Get CDP session from Playwright
            client = await page.context.new_cdp_session(page)
            
            # Enable profiler and start precise coverage
            await client.send("Profiler.enable")
            await client.send("Profiler.startPreciseCoverage", {
                "callCount": True,
                "detailed": True
            })
            
            self._client = client
            self._started = True
            logger.info("📊 JS Coverage collection started")
            return True
            
        except Exception as e:
            logger.warning(f"⚠️ Could not start JS coverage: {e}")
            logger.warning("   (Coverage requires Chromium, not Firefox/Foxhound)")
            return False
    
    async def stop(self) -> CoverageData:
        """Stop collecting and return coverage data"""
        if not self._started:
            return CoverageData()
        
        try:
            # Get coverage data
            result = await self._client.send("Profiler.takePreciseCoverage")
            await self._client.send("Profiler.stopPreciseCoverage")
            await self._client.send("Profiler.disable")
            
            # Parse coverage
            total_bytes = 0
            used_bytes = 0
            script_coverage = []
            
            for script in result.get('result', []):
                script_url = script.get('url', '')
                
                # Skip internal scripts
                if not script_url or script_url.startswith('chrome://'):
                    continue
                
                functions = script.get('functions', [])
                
                script_total = 0
                script_used = 0
                
                for func in functions:
                    for range_info in func.get('ranges', []):
                        start = range_info.get('startOffset', 0)
                        end = range_info.get('endOffset', 0)
                        count = range_info.get('count', 0)
                        
                        range_bytes = end - start
                        script_total += range_bytes
                        
                        if count > 0:
                            script_used += range_bytes
                
                if script_total > 0:
                    total_bytes += script_total
                    used_bytes += script_used
                    
                    script_coverage.append({
                        'url': script_url[:100],
                        'total_bytes': script_total,
                        'used_bytes': script_used,
                        'coverage': script_used / script_total if script_total > 0 else 0
                    })
            
            coverage = CoverageData(
                total_bytes=total_bytes,
                used_bytes=used_bytes,
                coverage_percent=used_bytes / total_bytes * 100 if total_bytes > 0 else 0,
                scripts_total=len(script_coverage),
                scripts_covered=sum(1 for s in script_coverage if s['coverage'] > 0),
                script_coverage=script_coverage
            )
            
            logger.info(f"📊 JS Coverage: {coverage.coverage_percent:.1f}% "
                       f"({used_bytes:,}/{total_bytes:,} bytes)")
            
            return coverage
            
        except Exception as e:
            logger.warning(f"⚠️ Error collecting coverage: {e}")
            return CoverageData()


class EvaluationManager:
    """
    Manages evaluation runs and computes statistics.
    """
    
    def __init__(self, dataset_name: str = "evaluation"):
        self.dataset_name = dataset_name
        self.runs: List[EvaluationRun] = []
        self.start_time = datetime.now()
        
        # Track first finding times
        self._flow_timestamps: List[float] = []
        self._bug_timestamps: List[float] = []
    
    def start_run(self, url: str, strategy: str) -> EvaluationRun:
        """Start a new evaluation run"""
        import time
        
        run = EvaluationRun(
            url=url,
            strategy=strategy,
            timestamp=datetime.now().isoformat(),
            run_id=f"{strategy}_{len(self.runs)}_{int(time.time())}",
            start_time=time.time()
        )
        
        return run
    
    def finish_run(self, run: EvaluationRun, 
                   coverage: CoverageData = None,
                   findings: List[Dict] = None,
                   actions: int = 0,
                   dom_initial: int = 0,
                   dom_final: int = 0,
                   dom_max: int = 0) -> EvaluationRun:
        """Finish an evaluation run and compute metrics"""
        import time
        
        run.end_time = time.time()
        run.duration_seconds = run.end_time - run.start_time
        
        # Coverage
        if coverage:
            run.coverage = coverage
        
        # DOM
        run.initial_dom_size = dom_initial
        run.final_dom_size = dom_final
        run.max_dom_size = dom_max
        run.actions_performed = actions
        
        # Process findings
        if findings:
            run.taint_flows = len(findings)
            
            confirmed = []
            first_flow_time = None
            first_bug_time = None
            
            for f in findings:
                sink = f.get('sink', '')
                confidence = f.get('confidence', 0.5)
                timestamp = f.get('timestamp', run.start_time)
                
                # Track first flow
                if first_flow_time is None:
                    first_flow_time = timestamp - run.start_time
                
                # Is this a confirmed vulnerability?
                # Critical sinks with high confidence
                is_critical = any(s in sink.lower() for s in 
                    ['innerhtml', 'outerhtml', 'eval', 'document.write', 
                     'script.src', 'function', 'setinterval', 'settimeout'])
                
                is_confirmed = is_critical and confidence >= 0.7
                
                if is_confirmed:
                    confirmed.append(SecurityFinding(
                        sink=sink,
                        source=str(f.get('sources', [])),
                        payload=f.get('str', '')[:200],
                        url=f.get('loc', run.url),
                        script=f.get('script', ''),
                        line=f.get('line', 0),
                        timestamp=timestamp,
                        confidence=confidence,
                        confirmed=True,
                        exploitable=confidence >= 0.8
                    ))
                    
                    if first_bug_time is None:
                        first_bug_time = timestamp - run.start_time
            
            run.findings = confirmed
            run.confirmed_vulnerabilities = len(confirmed)
            
            # Efficiency metrics
            run.efficiency = EfficiencyMetrics(
                total_duration_seconds=run.duration_seconds,
                time_to_first_flow_seconds=first_flow_time,
                time_to_first_bug_seconds=first_bug_time,
                total_flows=run.taint_flows,
                total_bugs=len(confirmed),
                total_actions=actions
            )
            
            # Compute rates (per hour)
            hours = run.duration_seconds / 3600 if run.duration_seconds > 0 else 0.001
            run.efficiency.flows_per_hour = run.taint_flows / hours
            run.efficiency.bugs_per_hour = len(confirmed) / hours
            run.efficiency.actions_per_second = actions / run.duration_seconds if run.duration_seconds > 0 else 0
        
        # Add to runs
        self.runs.append(run)
        
        return run
    
    def compute_dataset_statistics(self) -> DatasetEvaluation:
        """Compute aggregated statistics for the entire dataset"""
        
        eval_result = DatasetEvaluation(
            dataset_name=self.dataset_name,
            timestamp=datetime.now().isoformat(),
            runs=self.runs,
            total_urls=len(self.runs)
        )
        
        if not self.runs:
            return eval_result
        
        # Success/Failure counts
        successful = [r for r in self.runs if r.coverage.total_bytes > 0 or r.taint_flows > 0]
        eval_result.successful_urls = len(successful)
        eval_result.failed_urls = len(self.runs) - len(successful)
        
        # Coverage statistics
        coverages = [r.coverage.coverage_percent for r in self.runs if r.coverage.total_bytes > 0]
        if coverages:
            eval_result.coverage_mean = mean(coverages)
            eval_result.coverage_median = median(coverages)
            if len(coverages) > 1:
                eval_result.coverage_stdev = stdev(coverages)
        
        # Security statistics
        eval_result.total_flows = sum(r.taint_flows for r in self.runs)
        eval_result.total_confirmed_bugs = sum(r.confirmed_vulnerabilities for r in self.runs)
        eval_result.urls_with_bugs = sum(1 for r in self.runs if r.confirmed_vulnerabilities > 0)
        
        # Efficiency statistics
        ttfb = [r.efficiency.time_to_first_bug_seconds for r in self.runs 
                if r.efficiency.time_to_first_bug_seconds is not None]
        if ttfb:
            eval_result.mean_time_to_first_bug = mean(ttfb)
            eval_result.median_time_to_first_bug = median(ttfb)
        
        bugs_per_hour = [r.efficiency.bugs_per_hour for r in self.runs]
        if bugs_per_hour:
            eval_result.mean_bugs_per_hour = mean(bugs_per_hour)
            eval_result.median_bugs_per_hour = median(bugs_per_hour)
        
        # Duration
        eval_result.total_duration_seconds = sum(r.duration_seconds for r in self.runs)
        eval_result.mean_duration_per_url = mean([r.duration_seconds for r in self.runs])
        
        return eval_result
    
    def print_summary(self):
        """Print evaluation summary to console"""
        stats = self.compute_dataset_statistics()
        
        print(f"\n{'='*70}")
        print(f"📊 EVALUATION SUMMARY: {stats.dataset_name}")
        print(f"{'='*70}")
        
        print(f"\n📈 DATASET OVERVIEW")
        print(f"   URLs analyzed: {stats.total_urls}")
        print(f"   Successful: {stats.successful_urls}")
        print(f"   Failed: {stats.failed_urls}")
        print(f"   Total duration: {stats.total_duration_seconds:.1f}s ({stats.total_duration_seconds/60:.1f}min)")
        
        print(f"\n📊 JAVASCRIPT COVERAGE")
        print(f"   Mean: {stats.coverage_mean:.1f}%")
        print(f"   Median: {stats.coverage_median:.1f}%")
        if stats.coverage_stdev > 0:
            print(f"   Std Dev: {stats.coverage_stdev:.1f}%")
        
        print(f"\n🔒 SECURITY IMPACT")
        print(f"   Total taint flows: {stats.total_flows}")
        print(f"   Confirmed DOM-XSS: {stats.total_confirmed_bugs}")
        print(f"   URLs with bugs: {stats.urls_with_bugs}")
        
        print(f"\n⚡ EFFICIENCY METRICS")
        if stats.mean_time_to_first_bug is not None:
            print(f"   Time to first bug (mean): {stats.mean_time_to_first_bug:.1f}s")
            print(f"   Time to first bug (median): {stats.median_time_to_first_bug:.1f}s")
        else:
            print(f"   Time to first bug: N/A (no bugs found)")
        print(f"   Bugs per hour (mean): {stats.mean_bugs_per_hour:.2f}")
        print(f"   Bugs per hour (median): {stats.median_bugs_per_hour:.2f}")
        
        print(f"\n{'='*70}")
        
        # Per-strategy breakdown if multiple strategies
        strategies = set(r.strategy for r in self.runs)
        if len(strategies) > 1:
            print(f"\n📋 PER-STRATEGY BREAKDOWN")
            print(f"-"*70)
            print(f"{'Strategy':<20} {'URLs':>6} {'Coverage':>10} {'Bugs':>6} {'Bugs/h':>10} {'Time':>10}")
            print(f"-"*70)
            
            for strat in sorted(strategies):
                strat_runs = [r for r in self.runs if r.strategy == strat]
                strat_coverage = mean([r.coverage.coverage_percent for r in strat_runs 
                                      if r.coverage.total_bytes > 0] or [0])
                strat_bugs = sum(r.confirmed_vulnerabilities for r in strat_runs)
                strat_bph = mean([r.efficiency.bugs_per_hour for r in strat_runs])
                strat_time = sum(r.duration_seconds for r in strat_runs)
                
                print(f"{strat:<20} {len(strat_runs):>6} {strat_coverage:>9.1f}% {strat_bugs:>6} "
                      f"{strat_bph:>9.2f} {strat_time:>9.1f}s")
            
            print(f"-"*70)
        
        return stats
    
    def export_json(self, filepath: str):
        """Export evaluation results to JSON"""
        stats = self.compute_dataset_statistics()
        
        # Convert to dict (handle dataclasses)
        def to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: to_dict(v) for k, v in asdict(obj).items()}
            elif isinstance(obj, list):
                return [to_dict(i) for i in obj]
            elif isinstance(obj, dict):
                return {k: to_dict(v) for k, v in obj.items()}
            else:
                return obj
        
        export_data = {
            'evaluation_timestamp': datetime.now().isoformat(),
            'dataset': stats.dataset_name,
            'summary': {
                'total_urls': stats.total_urls,
                'successful_urls': stats.successful_urls,
                'failed_urls': stats.failed_urls,
                'total_duration_seconds': stats.total_duration_seconds,
            },
            'coverage': {
                'mean': stats.coverage_mean,
                'median': stats.coverage_median,
                'stdev': stats.coverage_stdev,
            },
            'security': {
                'total_flows': stats.total_flows,
                'confirmed_bugs': stats.total_confirmed_bugs,
                'urls_with_bugs': stats.urls_with_bugs,
            },
            'efficiency': {
                'mean_time_to_first_bug': stats.mean_time_to_first_bug,
                'median_time_to_first_bug': stats.median_time_to_first_bug,
                'mean_bugs_per_hour': stats.mean_bugs_per_hour,
                'median_bugs_per_hour': stats.median_bugs_per_hour,
            },
            'runs': [to_dict(r) for r in self.runs]
        }
        
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"📄 Evaluation exported: {filepath}")
    
    def export_csv(self, filepath: str):
        """Export evaluation results to CSV for analysis"""
        import csv
        
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'url', 'strategy', 'duration_s', 
                'coverage_percent', 'js_bytes_total', 'js_bytes_used',
                'taint_flows', 'confirmed_bugs',
                'time_to_first_bug_s', 'bugs_per_hour',
                'dom_initial', 'dom_final', 'dom_max',
                'actions', 'inputs_filled', 'payloads_injected'
            ])
            
            # Data rows
            for run in self.runs:
                writer.writerow([
                    run.url,
                    run.strategy,
                    f"{run.duration_seconds:.1f}",
                    f"{run.coverage.coverage_percent:.1f}",
                    run.coverage.total_bytes,
                    run.coverage.used_bytes,
                    run.taint_flows,
                    run.confirmed_vulnerabilities,
                    f"{run.efficiency.time_to_first_bug_seconds:.1f}" if run.efficiency.time_to_first_bug_seconds else "N/A",
                    f"{run.efficiency.bugs_per_hour:.2f}",
                    run.initial_dom_size,
                    run.final_dom_size,
                    run.max_dom_size,
                    run.actions_performed,
                    run.inputs_filled,
                    run.payloads_injected
                ])
        
        logger.info(f"📄 CSV exported: {filepath}")


# Standalone test
if __name__ == "__main__":
    # Create test evaluation
    eval_mgr = EvaluationManager(dataset_name="test_dataset")
    
    # Simulate some runs
    import random
    import time
    
    test_urls = [
        "https://example-spa-1.com",
        "https://example-spa-2.com",
        "https://example-spa-3.com"
    ]
    
    for url in test_urls:
        run = eval_mgr.start_run(url, "random_walk")
        time.sleep(0.1)  # Simulate work
        
        # Fake coverage
        coverage = CoverageData(
            total_bytes=random.randint(50000, 200000),
            used_bytes=random.randint(10000, 100000)
        )
        coverage.coverage_percent = coverage.used_bytes / coverage.total_bytes * 100
        
        # Fake findings
        findings = [
            {'sink': 'innerHTML', 'confidence': 0.85, 'sources': ['location.hash'], 
             'str': '<img onerror=alert(1)>', 'timestamp': time.time()}
        ] if random.random() > 0.5 else []
        
        eval_mgr.finish_run(
            run,
            coverage=coverage,
            findings=findings,
            actions=random.randint(20, 50),
            dom_initial=500,
            dom_final=random.randint(500, 2000)
        )
    
    # Print summary
    eval_mgr.print_summary()
    
    # Export
    eval_mgr.export_json("/tmp/test_evaluation.json")
    eval_mgr.export_csv("/tmp/test_evaluation.csv")
