import pytest

from netagent.safety import Risk, classify, redact


@pytest.mark.parametrize(
    "vendor,cmd",
    [
        ("cisco", "show ip route"),
        ("cisco", "show running-config | include ospf"),
        ("cisco", "ping 10.0.0.1"),
        ("fortinet", "get router info routing-table all"),
        ("fortinet", "diagnose sys session list"),
        ("fortinet", "execute ping 8.8.8.8"),
        ("paloalto", "show session all"),
        ("paloalto", "show routing route"),
    ],
)
def test_read_only_allowed(vendor, cmd):
    assert classify(vendor, cmd) is Risk.READ_ONLY


@pytest.mark.parametrize(
    "vendor,cmd,expected",
    [
        ("cisco", "configure terminal", Risk.HIGH),
        ("cisco", "clear ip ospf process", Risk.HIGH),
        ("cisco", "debug ip packet", Risk.HIGH),
        ("cisco", "reload", Risk.CRITICAL),
        ("cisco", "write erase", Risk.CRITICAL),
        ("cisco", "show ip route; reload", Risk.HIGH),
        ("cisco", "show run | tee flash:x", Risk.HIGH),
        ("cisco", "show run > flash:x", Risk.HIGH),
        ("cisco", "", Risk.HIGH),
        ("fortinet", "execute reboot", Risk.CRITICAL),
        ("fortinet", "execute factoryreset", Risk.CRITICAL),
        ("fortinet", "diagnose debug enable", Risk.HIGH),
        ("fortinet", "config firewall policy", Risk.HIGH),
        ("paloalto", "set deviceconfig system hostname x", Risk.HIGH),
        ("paloalto", "request restart system", Risk.CRITICAL),
    ],
)
def test_not_read_only(vendor, cmd, expected):
    assert classify(vendor, cmd) is expected


def test_unknown_vendor_rejected():
    with pytest.raises(ValueError):
        classify("juniper", "show version")


def test_redaction():
    cfg = (
        "enable secret 9 $9$abc\n"
        "username admin privilege 15 secret 9 $9$xyz\n"
        "snmp-server community public RO\n"
        " set psksecret ENC abcdef\n"
        "interface Gi0/1\n"
    )
    out = redact(cfg)
    for leaked in ("$9$abc", "$9$xyz", "public", "abcdef"):
        assert leaked not in out
    assert "interface Gi0/1" in out
