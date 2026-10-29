"""Structured log helper: `[incident_id][agent][stage] message` (CLAUDE.md §14)."""
from typing import Any


def format_log(incident_id: str, agent: str, stage: str, message: str) -> str:
    return f"[{incident_id}][{agent}][{stage}] {message}"


def log(logger: Any, incident_id: str, agent: str, stage: str, message: str, level: str = "info") -> None:
    """Log through any logger-like object (uagents ctx.logger or stdlib logging.Logger)."""
    getattr(logger, level)(format_log(incident_id, agent, stage, message))


def configure_console_utf8() -> None:
    """Let emoji stage markers print on Windows consoles that default to cp1252."""
    import sys

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")
