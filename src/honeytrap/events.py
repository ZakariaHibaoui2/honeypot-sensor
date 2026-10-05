"""Event model and thread-safe JSON-lines sink."""
from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def clean(value: str | bytes, limit: int = 512) -> str:
    """Make attacker-controlled input safe to store and display: decode, strip control chars, truncate."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)
    return value[:limit]


@dataclass
class Event:
    service: str
    event: str                 # connect | banner | login | command | request | disconnect | rejected
    src_ip: str
    src_port: int
    session: str
    timestamp: str = field(default_factory=_now)
    data: dict = field(default_factory=dict)


class Sink:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.events: list[Event] = []
        self._lock = threading.Lock()

    def emit(self, ev: Event) -> None:
        with self._lock:
            self.events.append(ev)
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")


def load(path: str | Path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out
