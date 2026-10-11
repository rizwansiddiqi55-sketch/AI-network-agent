from types import SimpleNamespace

from netagent.evals import load_scenarios, run_scenario, score


def test_scenarios_load_and_plant_a_fault():
    sc = load_scenarios("scenarios")
    assert set(sc) == {"vlan20_trunk_pruned", "ospf_mtu_mismatch", "fw_implicit_deny"}
    assert all(s["question"] and s["expected"] for s in sc.values())


def test_score_reports_missing_keywords():
    assert score("The trunk does not allow VLAN 20", ["vlan 20", "trunk", "allowed"]) == ["allowed"]


def test_run_scenario_with_fake_client():
    text = SimpleNamespace(type="text", text="MTU mismatch leaves OSPF stuck in EXSTART")
    client = SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: SimpleNamespace(stop_reason="end_turn", content=[text]))
    )
    r = run_scenario("ospf_mtu_mismatch", client=client)
    assert r.passed
