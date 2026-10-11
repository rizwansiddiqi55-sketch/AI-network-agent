# netagent — AI Network Engineer & Cybersecurity Architect

An evidence-driven agent for enterprise network troubleshooting, security incident analysis and secure design (Cisco, Fortinet, Palo Alto). It reads configs, `show` output and logs, ranks root-cause hypotheses, and proposes changes with validation and rollback. **It never applies changes itself.**

## Design decisions

| Choice | Decision | Why |
|---|---|---|
| Platform | Python + Anthropic tool-use loop | Full control of the safety layer; LangGraph can wrap it later if you need multi-step graphs/state |
| Network access | Phase 1: evidence files. Phase 2: live **read-only** SSH | Safe to demo and test with no lab; real value on day one from pasted outputs |
| Scope | Both network + security, one agent | Most real incidents cross both (firewall policy, NAC, VPN, routing) |

## Architecture

```
question ──► agent loop (LLM + system_prompt.md)
               │ tool calls
               ▼
   ┌────────── Toolbox ───────────┐
   │ list/read/search_evidence    │──► evidence/ (redacted, path-confined)
   │ run_readonly_command         │──► safety.classify() ──READ_ONLY──► Netmiko (creds from env, not the model)
   │                              │                       └─other────► REFUSED
   │ propose_change               │──► recorded for a human; never executed
   └──────────────┬───────────────┘
                  ▼
        audit/audit.jsonl (every call, refusal, proposal)
```

Safety is enforced **in code**, not only in the prompt:
- Per-vendor read-only allowlist; default-deny. Chaining (`;`, `&`, backticks, `>`), non-filter pipes, `debug`, `clear`, `copy`, `execute` (except ping/traceroute) are refused. `reload`/`erase`/`reboot`/`restart` classify CRITICAL.
- Secrets (enable/user secrets, SNMP communities, PSKs, keys) are redacted from evidence **and** device output before the model sees them.
- Evidence reads are confined to the evidence directory.
- Device credentials come from `NETAGENT_USER`/`NETAGENT_PASS`, are never exposed to the model, and devices must be in an approved `inventory.json`.

## Use

```bash
pip install -e '.[dev]'          # add ',device' for live Netmiko access
export ANTHROPIC_API_KEY=...
netagent "Users in VLAN 20 cannot reach 10.1.100.10" --evidence evidence/example
```

Live read-only mode (`inventory.json`: `{"sw-access1": {"vendor": "cisco", "host": "10.0.0.5"}}`):

```bash
export NETAGENT_USER=readonly_svc NETAGENT_PASS=...
netagent "..." --inventory inventory.json
```

Use a **read-only/privilege-limited AAA account** as a second layer; the allowlist is not a substitute for least privilege.

## Roadmap

1. **Done (this commit):** prompt, safety gate, redaction, evidence tools, audit log, agent loop, tests.
2. Vendor output parsers (TextFSM/ntc-templates) so the model gets structured routing/ARP/interface data.
3. Security correlation: FortiAnalyzer / Panorama / ISE / SIEM read-only connectors; MITRE ATT&CK mapping.
4. Lab validation in EVE-NG/GNS3 with scripted fault-injection scenarios as regression evals.
5. Approved-change workflow: config diff, ticket/approval gate, backup, apply, post-check, auto-rollback. Last, and human-gated.

## Tests

`pytest` — covers command classification (allow/deny/CRITICAL, injection attempts), redaction, path traversal, "only read-only executes", "proposals never execute", and the agent loop with a fake client. The LLM itself is not covered by these tests; run the example scenario with a real key to evaluate answer quality.
