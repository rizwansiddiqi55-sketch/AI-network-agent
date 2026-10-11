"""Tools exposed to the model. Phase 1: evidence files only. Live devices are
optional, read-only, and gated by safety.classify()."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

from .audit import AuditLog
from .safety import VENDORS, Risk, classify, redact

MAX_BYTES = 200_000

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_evidence",
        "description": "List evidence files (configs, 'show' output, logs, notes) available for analysis.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_evidence",
        "description": "Read one evidence file by relative path. Secrets are redacted. Large files are truncated.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "search_evidence",
        "description": "Case-insensitive substring search across all evidence files; returns file:line matches.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "run_readonly_command",
        "description": (
            "Run ONE read-only CLI command on a device from the approved inventory. Commands that are not "
            "provably read-only are refused; use propose_change for those."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["device", "command"],
        },
    },
    {
        "name": "propose_change",
        "description": (
            "Record a proposed configuration change for human review. NEVER executes anything. Include risk "
            "class, expected impact, validation commands and rollback."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "commands": {"type": "array", "items": {"type": "string"}},
                "risk": {"type": "string", "enum": ["LOW", "HIGH", "CRITICAL"]},
                "impact": {"type": "string"},
                "validation": {"type": "array", "items": {"type": "string"}},
                "rollback": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["device", "commands", "risk", "impact", "validation", "rollback"],
        },
    },
]


class DeviceRunner(Protocol):
    def run(self, device: dict[str, Any], command: str) -> str: ...


class NetmikoRunner:
    """Optional live access. Credentials come from env vars, never from the model."""

    _TYPES = {"cisco": "cisco_ios", "fortinet": "fortinet", "paloalto": "paloalto_panos"}

    def run(self, device: dict[str, Any], command: str) -> str:
        from netmiko import ConnectHandler  # lazy: only needed for live mode

        conn = ConnectHandler(
            device_type=self._TYPES[device["vendor"]],
            host=device["host"],
            username=os.environ["NETAGENT_USER"],
            password=os.environ["NETAGENT_PASS"],
            timeout=20,
        )
        try:
            return conn.send_command(command, read_timeout=30)
        finally:
            conn.disconnect()


class Toolbox:
    def __init__(
        self,
        evidence_dir: str | Path = "evidence",
        inventory: dict[str, dict[str, Any]] | None = None,
        runner: DeviceRunner | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.root = Path(evidence_dir).resolve()
        self.inventory = inventory or {}
        self.runner = runner
        self.audit = audit or AuditLog()
        self.proposals: list[dict[str, Any]] = []

    # -- dispatch ---------------------------------------------------------
    def call(self, name: str, args: dict[str, Any]) -> str:
        try:
            result = getattr(self, f"_{name}")(**args)
        except Exception as exc:  # surfaced to the model as an error string
            result = f"ERROR: {type(exc).__name__}: {exc}"
        self.audit.record("tool_call", tool=name, args=args, result_preview=result[:300])
        return result

    # -- evidence ---------------------------------------------------------
    def _safe_path(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise PermissionError("path escapes evidence directory")
        return p

    def _files(self) -> list[Path]:
        return sorted(p for p in self.root.rglob("*") if p.is_file())

    def _list_evidence(self) -> str:
        return "\n".join(str(p.relative_to(self.root)) for p in self._files()) or "(no evidence files)"

    def _read_evidence(self, path: str) -> str:
        p = self._safe_path(path)
        data = p.read_bytes()[:MAX_BYTES].decode("utf-8", errors="replace")
        note = "\n[truncated]" if p.stat().st_size > MAX_BYTES else ""
        return redact(data) + note

    def _search_evidence(self, query: str) -> str:
        q = query.lower()
        hits = []
        for p in self._files():
            text = p.read_text(encoding="utf-8", errors="replace")
            for n, line in enumerate(text.splitlines(), 1):
                if q in line.lower():
                    hits.append(f"{p.relative_to(self.root)}:{n}: {redact(line.strip())}")
        return "\n".join(hits[:100]) or "no matches"

    # -- live, read-only --------------------------------------------------
    def _run_readonly_command(self, device: str, command: str) -> str:
        if device not in self.inventory:
            raise KeyError(f"device {device!r} not in approved inventory")
        if self.runner is None:
            raise RuntimeError("live device access is not enabled")
        vendor = self.inventory[device]["vendor"]
        risk = classify(vendor, command)
        if risk is not Risk.READ_ONLY:
            self.audit.record("command_refused", device=device, command=command, risk=risk.name)
            return f"REFUSED: classified {risk.name}, not READ-ONLY. Use propose_change for human approval."
        return redact(self.runner.run(self.inventory[device], command))

    # -- proposals (never executed) ---------------------------------------
    def _propose_change(self, **proposal: Any) -> str:
        self.proposals.append(proposal)
        self.audit.record("change_proposed", **proposal)
        return "Proposal recorded for human review. It has NOT been applied."


def load_inventory(path: str | Path) -> dict[str, dict[str, Any]]:
    inv = json.loads(Path(path).read_text())
    for name, dev in inv.items():
        if dev.get("vendor") not in VENDORS:
            raise ValueError(f"{name}: vendor must be one of {VENDORS}")
    return inv
