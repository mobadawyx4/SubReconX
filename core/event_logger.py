"""Console/event logging with phase and counter tracking."""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field

from utils.formatting import colorize, timestamp


@dataclass
class EventLogger:
    quiet: bool = False
    verbose: bool = False
    colors: bool | None = None
    counters: Counter = field(default_factory=Counter)
    errors: list[dict] = field(default_factory=list)
    phase: str = "init"

    def _emit(self, text: str, color: str | None = None) -> None:
        if self.quiet:
            return
        if color:
            text = colorize(text, color, enabled=self.colors)
        print(text, file=sys.stdout, flush=True)

    def banner(self, tool: str, version: str) -> None:
        if self.quiet:
            return
        line = f"{tool} v{version} - passive & active reconnaissance"
        self._emit(line, "cyan")
        self._emit("-" * len(line), "dim")

    def info(self, message: str) -> None:
        self._emit(f"[*] {message}")

    def debug(self, message: str) -> None:
        if self.verbose:
            self._emit(f"[d] {message}", "dim")

    def success(self, message: str) -> None:
        self._emit(f"[+] {message}", "green")

    def warn(self, message: str) -> None:
        self._emit(f"[!] {message}", "yellow")

    def error(self, message: str, phase: str | None = None) -> None:
        phase = phase or self.phase
        self.errors.append({"phase": phase, "message": message, "time": timestamp()})
        self._emit(f"[-] {message}", "red")

    def start_phase(self, name: str, description: str = "") -> None:
        self.phase = name
        suffix = f" - {description}" if description else ""
        self._emit(f"\n== {name.upper()}{suffix} ==", "bold")

    def end_phase(self, name: str, summary: str = "") -> None:
        if summary:
            self._emit(f"[ok] {name}: {summary}", "green")

    def result(self, label: str, value: int) -> None:
        self.counters[label] += int(value)
        self._emit(f"    {label}: {value}")

    def set_count(self, label: str, value: int) -> None:
        self.counters[label] = int(value)

    def get_count(self, label: str) -> int:
        return int(self.counters.get(label, 0))

    def summary(self) -> None:
        if self.quiet:
            return
        self._emit("\n== SUMMARY ==", "bold")
        for label, value in sorted(self.counters.items()):
            self._emit(f"  {label:<28} {value}")
        if self.errors:
            self._emit(f"  {'errors':<28} {len(self.errors)}", "yellow")
