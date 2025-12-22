"""
DOM XSS Trigger Strategies - Benchmark Runner
Führt systematische Benchmarks für wissenschaftliche Evaluation durch
"""
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import json

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkConfig:
    """Konfiguration für Benchmark-Runs"""
    
    # Zu testende URLs
    urls: List[str] = field(default_factory=list)
    
    # Zu testende Strategien
    strategies: List[str] = field(default_factory=lambda: ['random_walk', 'model_guided', 'dom_maximizer'])
    
    # Anzahl Wiederholungen pro URL/Strategie
    repetitions: int = 3
    
    # Maximale Aktionen pro Run
    max_actions: int = 50
    
    # Timeout pro URL in Sekunden
    timeout_seconds: int = 300
    
    # Foxhound-Einstellungen
    headless: bool = True
    foxhound_path: Optional[str] = None
    
    # Output
    output_dir: str = "benchmark_results"
    
    # Randomisierung
    randomize_order: bool = True
    seed: Optional[int] = None


@dataclass
class BenchmarkResult:
    """Ergebnis eines kompletten Benchmark-Runs"""
    
    config: BenchmarkConfig
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Ergebnisse pro URL
    url_results: Dict[str, List[Any]] = field(default_factory=dict)
    
    # Aggregierte Statistiken
    aggregated_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Fehler
    errors: List[Dict] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0
    
    @property
    def success_rate(self) -> float:
        total = len(self.config.urls) * len(self.config.strategies) * self.config.repetitions
        successful = sum(
            len(comparisons) 
            for comparisons in self.url_results.values()
        )
        return successful / max(1, total)
    
    def to_dict(self) -> Dict:
        return {
            'config': {
                'urls': self.config.urls,
                'strategies': self.config.strategies,
                'repetitions': self.config.repetitions,
                'max_actions': self.config.max_actions
            },
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'success_rate': self.success_rate,
            'url_results': {
                url: [c.to_dict() if hasattr(c, 'to_dict') else str(c) for c in comparisons]
                for url, comparisons in self.url_results.items()
            },
            'aggregated_stats': self.aggregated_stats,
            'errors': self.errors
        }


class BenchmarkRunner:
    """
    Führt systematische Benchmarks durch.
    
    Features:
    - Mehrfache Wiederholungen für statistische Signifikanz
    - Randomisierte Ausführungsreihenfolge
    - Automatische Fehlerbehandlung
    - Progress-Tracking
    - Aggregation über alle Runs
    """
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.result = BenchmarkResult(
            config=config,
            started_at=datetime.now()
        )
        
        # Output-Verzeichnis erstellen
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def run(self) -> BenchmarkResult:
        """
        Führt den kompletten Benchmark durch.
        
        Returns:
            BenchmarkResult mit allen Ergebnissen
        """
        logger.info("=" * 60)
        logger.info("🏁 BENCHMARK GESTARTET")
        logger.info("=" * 60)
        logger.info(f"URLs: {len(self.config.urls)}")
        logger.info(f"Strategien: {self.config.strategies}")
        logger.info(f"Wiederholungen: {self.config.repetitions}")
        logger.info(f"Gesamt-Runs: {self._total_runs}")
        logger.info("=" * 60)
        
        # Import hier um zirkuläre Imports zu vermeiden
        from main import DOMXSSAnalyzer
        
        # Analyzer initialisieren
        analyzer = DOMXSSAnalyzer()
        
        try:
            await analyzer.setup(
                foxhound_path=self.config.foxhound_path,
                headless=self.config.headless
            )
            
            # Erstelle Ausführungsplan
            execution_plan = self._create_execution_plan()
            
            completed = 0
            for url, rep_num in execution_plan:
                try:
                    logger.info(f"\n📊 [{completed + 1}/{len(execution_plan)}] "
                               f"URL: {url}, Wiederholung: {rep_num + 1}")
                    
                    # Führe Vergleich durch
                    comparison = await analyzer.compare_strategies(
                        url=url,
                        strategies=self.config.strategies,
                        max_actions=self.config.max_actions
                    )
                    
                    # Speichere Ergebnis
                    if url not in self.result.url_results:
                        self.result.url_results[url] = []
                    self.result.url_results[url].append(comparison)
                    
                    completed += 1
                    
                except asyncio.TimeoutError:
                    self._log_error(url, rep_num, "Timeout")
                except Exception as e:
                    self._log_error(url, rep_num, str(e))
            
            # Aggregiere Ergebnisse
            self._aggregate_results()
            
        finally:
            await analyzer.cleanup()
        
        self.result.completed_at = datetime.now()
        
        # Speichere Ergebnisse
        self._save_results()
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ BENCHMARK ABGESCHLOSSEN")
        logger.info(f"Dauer: {self.result.duration_seconds:.1f}s")
        logger.info(f"Erfolgsrate: {self.result.success_rate:.1%}")
        logger.info("=" * 60)
        
        return self.result
    
    @property
    def _total_runs(self) -> int:
        return len(self.config.urls) * self.config.repetitions
    
    def _create_execution_plan(self) -> List[tuple]:
        """Erstellt Ausführungsplan (optional randomisiert)"""
        import random
        
        plan = [
            (url, rep)
            for url in self.config.urls
            for rep in range(self.config.repetitions)
        ]
        
        if self.config.randomize_order:
            if self.config.seed is not None:
                random.seed(self.config.seed)
            random.shuffle(plan)
        
        return plan
    
    def _log_error(self, url: str, rep: int, error: str):
        """Loggt einen Fehler"""
        error_entry = {
            'url': url,
            'repetition': rep,
            'error': error,
            'timestamp': datetime.now().isoformat()
        }
        self.result.errors.append(error_entry)
        logger.error(f"❌ Fehler bei {url} (Rep {rep + 1}): {error}")
    
    def _aggregate_results(self):
        """Aggregiert Ergebnisse über alle Runs"""
        from reporting.comparison import ComparisonReporter
        
        all_comparisons = []
        for url, comparisons in self.result.url_results.items():
            all_comparisons.extend(comparisons)
        
        if all_comparisons:
            self.result.aggregated_stats = ComparisonReporter.aggregate_runs(all_comparisons)
    
    def _save_results(self):
        """Speichert alle Ergebnisse"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON-Report
        json_path = self.output_dir / f"benchmark_{timestamp}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.result.to_dict(), f, indent=2, default=str)
        logger.info(f"📄 JSON gespeichert: {json_path}")
        
        # Zusammenfassung
        summary_path = self.output_dir / f"benchmark_{timestamp}_summary.txt"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(self._generate_summary())
        logger.info(f"📄 Summary gespeichert: {summary_path}")
    
    def _generate_summary(self) -> str:
        """Generiert Text-Zusammenfassung"""
        lines = [
            "=" * 60,
            "BENCHMARK ZUSAMMENFASSUNG",
            "=" * 60,
            f"Gestartet: {self.result.started_at}",
            f"Beendet: {self.result.completed_at}",
            f"Dauer: {self.result.duration_seconds:.1f}s",
            f"Erfolgsrate: {self.result.success_rate:.1%}",
            "",
            "-" * 60,
            "KONFIGURATION",
            "-" * 60,
            f"URLs: {len(self.config.urls)}",
            f"Strategien: {', '.join(self.config.strategies)}",
            f"Wiederholungen: {self.config.repetitions}",
            f"Max. Aktionen: {self.config.max_actions}",
            "",
        ]
        
        # Aggregierte Stats
        if self.result.aggregated_stats:
            lines.extend([
                "-" * 60,
                "AGGREGIERTE ERGEBNISSE",
                "-" * 60,
            ])
            
            for strategy, stats in self.result.aggregated_stats.get('strategies', {}).items():
                lines.append(f"\n{strategy}:")
                for metric, values in stats.items():
                    if isinstance(values, dict):
                        lines.append(f"  {metric}: μ={values.get('mean', 0):.2f}, "
                                   f"σ={values.get('std', 0):.2f}")
        
        # Fehler
        if self.result.errors:
            lines.extend([
                "",
                "-" * 60,
                f"FEHLER ({len(self.result.errors)})",
                "-" * 60,
            ])
            for err in self.result.errors[:10]:  # Max 10 Fehler anzeigen
                lines.append(f"  {err['url']}: {err['error']}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


async def run_benchmark_cli(
    urls: List[str],
    strategies: List[str] = None,
    repetitions: int = 3,
    max_actions: int = 50,
    output_dir: str = "benchmark_results"
) -> BenchmarkResult:
    """
    Convenience-Funktion für CLI-Aufruf.
    """
    config = BenchmarkConfig(
        urls=urls,
        strategies=strategies or ['random_walk', 'model_guided', 'dom_maximizer'],
        repetitions=repetitions,
        max_actions=max_actions,
        output_dir=output_dir
    )
    
    runner = BenchmarkRunner(config)
    return await runner.run()
