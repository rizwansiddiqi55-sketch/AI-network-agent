from types import SimpleNamespace

from netagent.agent import run_agent
from netagent.audit import AuditLog
from netagent.tools import Toolbox


class FakeRunner:
    def __init__(self):
        self.ran = []

    def run(self, device, command):
        self.ran.append(command)
        return "enable secret 9 $9$leak\nok"


def make_tb(tmp_path, runner=None):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "sw1.txt").write_text("enable secret 9 $9$abc\ninterface Gi0/1\n switchport access vlan 20\n")
    return Toolbox(
        ev,
        inventory={"sw1": {"vendor": "cisco", "host": "10.0.0.1"}},
        runner=runner,
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )


def test_evidence_redacted_and_searchable(tmp_path):
    tb = make_tb(tmp_path)
    assert "$9$abc" not in tb.call("read_evidence", {"path": "sw1.txt"})
    assert "sw1.txt:3" in tb.call("search_evidence", {"query": "vlan 20"})


def test_path_traversal_blocked(tmp_path):
    tb = make_tb(tmp_path)
    (tmp_path / "secret.txt").write_text("x")
    assert tb.call("read_evidence", {"path": "../secret.txt"}).startswith("ERROR: PermissionError")


def test_only_read_only_executes(tmp_path):
    r = FakeRunner()
    tb = make_tb(tmp_path, r)
    assert "$9$leak" not in tb.call("run_readonly_command", {"device": "sw1", "command": "show version"})
    assert tb.call("run_readonly_command", {"device": "sw1", "command": "reload"}).startswith("REFUSED")
    assert tb.call("run_readonly_command", {"device": "unknown", "command": "show version"}).startswith("ERROR")
    assert r.ran == ["show version"]


def test_propose_change_never_executes(tmp_path):
    r = FakeRunner()
    tb = make_tb(tmp_path, r)
    tb.call(
        "propose_change",
        dict(device="sw1", commands=["vlan 20"], risk="LOW", impact="none", validation=["show vlan"], rollback=["no vlan 20"]),
    )
    assert len(tb.proposals) == 1 and r.ran == []


def test_agent_loop_uses_tools_then_answers(tmp_path):
    tb = make_tb(tmp_path)
    tool_use = SimpleNamespace(type="tool_use", id="t1", name="list_evidence", input={})
    text = SimpleNamespace(type="text", text="Root cause: ...")
    replies = [
        SimpleNamespace(stop_reason="tool_use", content=[tool_use]),
        SimpleNamespace(stop_reason="end_turn", content=[text]),
    ]
    client = SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: replies.pop(0)))
    assert run_agent("VLAN 20 cannot reach VLAN 100", tb, client=client) == "Root cause: ..."
