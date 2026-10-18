"""Vercel serverless entrypoint. Evidence-paste mode only: no device access.

Fails closed: without APP_TOKEN configured, every request is refused."""
import hmac
import json
import os
import sys
import tempfile
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from netagent.agent import DEFAULT_MODEL, run_agent  # noqa: E402
from netagent.audit import AuditLog  # noqa: E402
from netagent.tools import Toolbox  # noqa: E402

MAX_QUESTION = 4_000
MAX_EVIDENCE = 150_000


def handle(token: str, body: dict, client=None) -> tuple[int, dict]:
    expected = os.environ.get("APP_TOKEN", "")
    if not expected:
        return 503, {"error": "server not configured: APP_TOKEN is not set"}
    if not hmac.compare_digest(token.encode(), expected.encode()):
        return 401, {"error": "unauthorized"}
    question = str(body.get("question", "")).strip()
    evidence = str(body.get("evidence", ""))
    if not question or len(question) > MAX_QUESTION:
        return 400, {"error": f"question required (max {MAX_QUESTION} chars)"}
    if len(evidence) > MAX_EVIDENCE:
        return 400, {"error": f"evidence too large (max {MAX_EVIDENCE} chars)"}
    if client is None and not os.environ.get("ANTHROPIC_API_KEY"):
        return 503, {"error": "server not configured: ANTHROPIC_API_KEY is not set"}
    with tempfile.TemporaryDirectory() as tmp:
        ev = Path(tmp) / "evidence"
        ev.mkdir()
        if evidence.strip():
            (ev / "pasted_evidence.txt").write_text(evidence, encoding="utf-8")
        tb = Toolbox(ev, audit=AuditLog(Path(tmp) / "audit.jsonl"))
        answer = run_agent(question, tb, client=client, model=os.environ.get("NETAGENT_MODEL", DEFAULT_MODEL))
        return 200, {"answer": answer, "proposals": tb.proposals}


class handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_EVIDENCE + MAX_QUESTION + 1000:
                return self._send(413, {"error": "request too large"})
            body = json.loads(self.rfile.read(length) or b"{}")
            code, payload = handle(self.headers.get("X-Access-Token", ""), body)
        except json.JSONDecodeError:
            code, payload = 400, {"error": "invalid JSON"}
        except Exception:  # never leak internals or keys to the client
            code, payload = 500, {"error": "analysis failed"}
        self._send(code, payload)
