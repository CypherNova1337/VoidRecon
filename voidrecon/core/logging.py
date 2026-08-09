"""Console + file logging built on Rich when available."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.logging import RichHandler

    _HAS_RICH = True
    console = Console(stderr=True)
except Exception:  # pragma: no cover
    _HAS_RICH = False
    console = None  # type: ignore

_LOGGER_NAME = "voidrecon"


def setup_logging(level: str = "info", logfile: str | Path | None = None) -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if _HAS_RICH:
        handler: logging.Handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            show_path=False,
            markup=True,
            log_time_format="[%H:%M:%S]",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:  # pragma: no cover
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)

    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

    return logger


def get_logger(module: str | None = None) -> logging.Logger:
    base = logging.getLogger(_LOGGER_NAME)
    return base.getChild(module) if module else base
