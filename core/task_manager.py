"""Small task/phase state tracker used by the orchestrator."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class TaskState:
    name: str
    status: TaskStatus = TaskStatus.PENDING
    started_at: float | None = None
    finished_at: float | None = None
    summary: str = ""
    error: str = ""

    @property
    def duration(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "duration_seconds": round(self.duration, 3),
            "summary": self.summary,
            "error": self.error,
        }


@dataclass
class TaskManager:
    tasks: dict[str, TaskState] = field(default_factory=dict)

    def register(self, name: str) -> TaskState:
        state = TaskState(name=name)
        self.tasks[name] = state
        return state

    def start(self, name: str) -> TaskState:
        state = self.tasks.get(name) or self.register(name)
        state.status = TaskStatus.RUNNING
        state.started_at = time.time()
        return state

    def finish(self, name: str, summary: str = "") -> None:
        state = self.tasks.get(name) or self.register(name)
        state.status = TaskStatus.DONE
        state.finished_at = time.time()
        state.summary = summary

    def fail(self, name: str, error: str) -> None:
        state = self.tasks.get(name) or self.register(name)
        state.status = TaskStatus.FAILED
        state.finished_at = time.time()
        state.error = error

    def skip(self, name: str, reason: str = "") -> None:
        state = self.tasks.get(name) or self.register(name)
        state.status = TaskStatus.SKIPPED
        state.summary = reason

    def as_list(self) -> list[dict]:
        return [task.as_dict() for task in self.tasks.values()]
