from __future__ import annotations

import argparse
import json

from .agent import DEFAULT_MODEL, run_agent
from .tools import NetmikoRunner, Toolbox, load_inventory


def main() -> None:
    ap = argparse.ArgumentParser(prog="netagent", description="Network & security analysis agent")
    ap.add_argument("question", help="Incident description or design request")
    ap.add_argument("--evidence", default="evidence", help="Directory of configs/logs/show output")
    ap.add_argument("--inventory", help="JSON inventory enabling live READ-ONLY device access")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    args = ap.parse_args()

    inventory = load_inventory(args.inventory) if args.inventory else None
    runner = NetmikoRunner() if inventory else None
    tb = Toolbox(args.evidence, inventory, runner)
    print(run_agent(args.question, tb, model=args.model))
    if tb.proposals:
        print("\n--- PROPOSED CHANGES (not applied) ---")
        print(json.dumps(tb.proposals, indent=2))


if __name__ == "__main__":
    main()
