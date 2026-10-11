"""Command risk classification. The agent can only *execute* READ_ONLY commands;
everything else becomes a proposal that a human must approve and run.

Enforced in code, not in the prompt: the LLM cannot talk its way past this."""
from __future__ import annotations

import enum
import re


class Risk(enum.IntEnum):
    READ_ONLY = 0
    LOW = 1
    HIGH = 2
    CRITICAL = 3


# Shell-ish metacharacters that could chain or smuggle a second command.
_FORBIDDEN_CHARS = re.compile(r"[;&`$<>\n\r]")
# Cisco-style output filters are fine; any other pipe target is not.
_SAFE_PIPE = re.compile(r"^\s*(include|exclude|begin|section|count)\s+\S", re.I)

_CRITICAL = re.compile(
    r"\b(reload|erase|format|factoryreset|factory-reset|shutdown|poweroff|reboot|restart|"
    r"delete|wipe|reset\s+all|write\s+erase|kill)\b",
    re.I,
)
_CONFIG_VERBS = re.compile(
    r"^\s*(configure|conf\s+t|config|set|unset|delete|edit|commit|no|clear|"
    r"copy|write|debug|undebug|request|execute\s+(?!ping|traceroute|tracert))",
    re.I,
)

_READ_ONLY: dict[str, list[re.Pattern[str]]] = {
    "cisco": [re.compile(p, re.I) for p in (r"^show\s+\S", r"^ping\s+\S", r"^traceroute\s+\S")],
    "fortinet": [
        re.compile(p, re.I)
        for p in (
            r"^get\s+\S",
            r"^show\s+\S",
            r"^diagnose\s+(ip\s+arp\s+list|sys\s+session\s+(list|stat)|"
            r"firewall\s+iprope\s+lookup|sys\s+top|hardware\s+deviceinfo|vpn\s+ike\s+gateway\s+list)",
            r"^execute\s+(ping|traceroute)\s+\S",
        )
    ],
    "paloalto": [
        re.compile(p, re.I)
        for p in (
            r"^show\s+\S",
            r"^ping\s+(host\s+)?\S",
            r"^traceroute\s+(host\s+)?\S",
            r"^test\s+routing\s+fib-lookup\s+\S",
        )
    ],
}

VENDORS = tuple(_READ_ONLY)


def classify(vendor: str, command: str) -> Risk:
    """Classify a single CLI command. Unknown/ambiguous input is never READ_ONLY."""
    vendor = vendor.lower()
    if vendor not in _READ_ONLY:
        raise ValueError(f"unsupported vendor {vendor!r}; expected one of {VENDORS}")
    cmd = command.strip()
    if not cmd or _FORBIDDEN_CHARS.search(cmd):
        return Risk.HIGH
    if _CRITICAL.search(cmd):
        return Risk.CRITICAL
    base, *pipes = cmd.split("|")
    if any(not _SAFE_PIPE.match(p) for p in pipes):
        return Risk.HIGH
    if _CONFIG_VERBS.match(base):
        return Risk.HIGH
    if any(p.match(base.strip()) for p in _READ_ONLY[vendor]):
        return Risk.READ_ONLY
    return Risk.HIGH


def is_read_only(vendor: str, command: str) -> bool:
    return classify(vendor, command) is Risk.READ_ONLY


# Secrets are stripped before any device output or config reaches the model.
_REDACTIONS = [
    (re.compile(r"(?im)^(\s*(?:enable\s+)?(?:secret|password)\s+(?:\d\s+)?)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)(snmp-server community\s+)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:key|pre-shared-key|psksecret|passwd|token)\s+(?:\d\s+)?(?:ENC\s+)?)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d\s+)?)\S+"), r"\1<redacted>"),
]


def redact(text: str) -> str:
    for pat, repl in _REDACTIONS:
        text = pat.sub(repl, text)
    return text
