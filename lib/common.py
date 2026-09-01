"""Shared utilities for redproxy components."""
import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from enum import Enum

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()


class LogLevel(Enum):
    SUCCESS = "green"
    WARNING = "yellow"
    ERROR = "red"
    INFO = "cyan"
    DEBUG = "white"


COLOR_MAP = {
    LogLevel.SUCCESS: Fore.GREEN,
    LogLevel.WARNING: Fore.YELLOW,
    LogLevel.ERROR: Fore.RED,
    LogLevel.INFO: Fore.CYAN,
    LogLevel.DEBUG: "",
}


def setup_logging(component: str, output_dir: str = "output") -> logging.Logger:
    """Configure logging for a component with file + console output."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"redproxy.{component}")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        fh = logging.FileHandler(
            Path(output_dir) / f"{component}.log",
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            '{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
        ))
        logger.addHandler(fh)

        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S'))
        logger.addHandler(ch)

    return logger


def log(logger: logging.Logger, message: str, level: LogLevel = LogLevel.DEBUG):
    """Log with color to console and plain to file."""
    color = COLOR_MAP.get(level, "")
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {color}{message}{Style.RESET_ALL}")

    log_method = {
        LogLevel.SUCCESS: logger.info,
        LogLevel.WARNING: logger.warning,
        LogLevel.ERROR: logger.error,
        LogLevel.INFO: logger.info,
        LogLevel.DEBUG: logger.debug,
    }.get(level, logger.info)
    log_method(message)


def load_env_vars(required: list) -> dict:
    """Load and validate required environment variables."""
    missing = [v for v in required if os.getenv(v) is None]
    if missing:
        raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")
    return {v: os.getenv(v) for v in required}


def read_lines(filepath: str) -> list:
    """Read non-empty lines from a file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"File is empty: {filepath}")
    return lines


def save_results(results: list, output_dir: str = "output", filename: str = "results.json"):
    """Save structured results as JSON (append mode)."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    outpath = Path(output_dir) / filename

    existing = []
    if outpath.exists():
        try:
            existing = json.loads(outpath.read_text())
        except (json.JSONDecodeError, Exception):
            pass

    existing.extend(results)
    outpath.write_text(json.dumps(existing, indent=2, default=str))
    return outpath
