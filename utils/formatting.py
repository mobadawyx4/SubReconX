"""Formatting helpers for terminal and text reports."""

from __future__ import annotations

import sys
import time
from typing import Iterable

_COLORS = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
}


def supports_color() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)()) and sys.platform != "win32"


def colorize(text: str, color: str, *, enabled: bool | None = None) -> str:
    if enabled is None:
        enabled = supports_color()
    if not enabled or color not in _COLORS:
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def human_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {rest}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def human_bytes(num: int | float) -> str:
    num = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def truncate(text: str, width: int = 100, suffix: str = "...") -> str:
    text = "" if text is None else str(text)
    if len(text) <= width:
        return text
    return text[: max(0, width - len(suffix))] + suffix


def table(headers: list[str], rows: Iterable[Iterable[str]], max_width: int = 48) -> str:
    rows = [[truncate(str(cell), max_width) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            if idx < len(widths):
                widths[idx] = max(widths[idx], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = [
        "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in rows
    ]
    return "\n".join([line, sep, *body])


def progress_line(phase: str, current: int, total: int, extra: str = "") -> str:
    if total <= 0:
        return f"[{phase}] {extra}".rstrip()
    pct = int(current / total * 100)
    bar_len = 24
    filled = int(bar_len * current / total)
    bar = "#" * filled + "." * (bar_len - filled)
    return f"[{phase}] [{bar}] {current}/{total} ({pct}%) {extra}".rstrip()


def timestamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
