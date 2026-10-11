"""Offline fault scenarios: run the agent on planted faults and score the answer.

Scoring is a keyword check on the final answer. It is a cheap regression
signal, not proof of a correct diagnosis; read the transcripts for real review."""
from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent import DEFAULT_MODEL, run_agent
from .audit import AuditLog
from .tools import Toolbox


@dataclass
class Result:
    name: str
    missing: list[str]
    answer: str

    @property
    def passed(self) -> bool:
        return not self.missing


def load_scenarios(root: str | Path = "scenarios") -> dict[str, dict[str, Any]]:
    return {p.parent.name: json.loads(p.read_text()) for p in sorted(Path(root).glob("*/scenario.json"))}


def score(answer: str, expected: list[str]) -> list[str]:
    low = answer.lower()
    return [k for k in expected if k.lower() not in low]


def run_scenario(name: str, root: str | Path = "scenarios", client: Any = None, model: str = DEFAULT_MODEL) -> Result:
    spec = load_scenarios(root)[name]
    with tempfile.TemporaryDirectory() as tmp:
        tb = Toolbox(Path(root) / name, audit=AuditLog(Path(tmp) / "audit.jsonl"))
        answer = run_agent(spec["question"], tb, client=client, model=model)
    return Result(name, score(answer, spec["expected"]), answer)


def main() -> None:
    ap = argparse.ArgumentParser(prog="netagent-eval")
    ap.add_argument("--root", default="scenarios")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    args = ap.parse_args()
    results = [run_scenario(n, args.root, model=args.model) for n in load_scenarios(args.root)]
    for r in results:
        print(f"{'PASS' if r.passed else 'FAIL'}  {r.name}" + (f"  missing: {r.missing}" if r.missing else ""))
    raise SystemExit(0 if all(r.passed for r in results) else 1)


if __name__ == "__main__":
    main()
