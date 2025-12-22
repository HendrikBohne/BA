"""
DOM XSS Trigger Strategies - Logging Configuration
Zentrale Logging-Konfiguration
"""
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional


# Globaler Logger-Cache
_loggers = {}


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    format_string: str = None
):
    """
    Konfiguriert das Logging-System.
    
    Args:
        level: Log-Level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optionaler Pfad zur Log-Datei
        format_string: Optionales Format-String
    """
    # Default Format
    if format_string is None:
        format_string = '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
    
    # Root Logger konfigurieren
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Entferne existierende Handler
    root_logger.handlers = []
    
    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        '%(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File Handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(format_string, datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Reduziere Noise von externen Bibliotheken
    logging.getLogger('playwright').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Gibt einen Logger für das angegebene Modul zurück.
    
    Args:
        name: Name des Moduls (typischerweise __name__)
        
    Returns:
        Logger-Instanz
    """
    if name not in _loggers:
        _loggers[name] = logging.getLogger(name)
    return _loggers[name]


def create_run_logger(run_id: str, output_dir: str = "logs") -> logging.Logger:
    """
    Erstellt einen Logger für einen spezifischen Analyse-Run.
    
    Args:
        run_id: Eindeutige Run-ID
        output_dir: Ausgabe-Verzeichnis für Logs
        
    Returns:
        Logger mit File-Handler für diesen Run
    """
    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / f"{run_id}.log"
    
    logger = logging.getLogger(f"run.{run_id}")
    logger.setLevel(logging.DEBUG)
    
    # File Handler für diesen Run
    handler = logging.FileHandler(log_file, encoding='utf-8')
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(handler)
    
    return logger


class LogContext:
    """
    Context-Manager für strukturiertes Logging.
    
    Verwendung:
        with LogContext(logger, "Analyse von URL"):
            # Code hier
    """
    
    def __init__(self, logger: logging.Logger, message: str, level: int = logging.INFO):
        self.logger = logger
        self.message = message
        self.level = level
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.log(self.level, f"▶ START: {self.message}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.log(self.level, f"✅ DONE: {self.message} ({duration:.2f}s)")
        else:
            self.logger.error(f"❌ FAILED: {self.message} ({duration:.2f}s) - {exc_val}")
        
        return False  # Exception nicht unterdrücken
