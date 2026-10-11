"""Append-only JSONL audit trail of every tool call and its outcome."""
from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path = "audit/audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: object) -> None:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
