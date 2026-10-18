import importlib.util
from pathlib import Path
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("api_index", Path(__file__).parent.parent / "api" / "index.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


def fake_client(text="Root cause: trunk"):
    t = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: SimpleNamespace(stop_reason="end_turn", content=[t]))
    )


def test_fails_closed_without_token_config(monkeypatch):
    monkeypatch.delenv("APP_TOKEN", raising=False)
    assert api.handle("x", {"question": "q"}, client=fake_client())[0] == 503


def test_wrong_token_rejected(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "s3cret")
    assert api.handle("nope", {"question": "q"}, client=fake_client())[0] == 401


def test_validation(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "s3cret")
    assert api.handle("s3cret", {"question": ""}, client=fake_client())[0] == 400
    big = {"question": "q", "evidence": "x" * (api.MAX_EVIDENCE + 1)}
    assert api.handle("s3cret", big, client=fake_client())[0] == 400


def test_success(monkeypatch):
    monkeypatch.setenv("APP_TOKEN", "s3cret")
    code, body = api.handle("s3cret", {"question": "q", "evidence": "enable secret 9 $9$abc"}, client=fake_client())
    assert code == 200 and body["answer"] == "Root cause: trunk" and body["proposals"] == []
