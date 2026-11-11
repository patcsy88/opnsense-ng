"""Rule proposal validation and registry entries for rule writes (ADR-0005 step 6)."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.changes.rule_schemas import RuleProposal
from app.opnsense.registry import get_operation

UUID = "ec691b46-6d4c-4fa5-88cc-54589859a1c9"


def make(**kw: Any) -> RuleProposal:
    base: dict[str, Any] = {"action": "pass", "interface": "lan", "description": "Test rule"}
    base.update(kw)
    return RuleProposal(**base)


def test_minimal_rule_gets_safe_defaults() -> None:
    rule = make()
    assert rule.enabled and rule.direction == "in" and rule.protocol == "any"
    assert rule.source == "any" and rule.log is False


def test_accepts_address_forms_and_ports() -> None:
    rule = make(
        protocol="TCP",
        source="10.0.0.0/24",
        destination="web_hosts",
        destination_port="443",
        source_port="1024:2048",
    )
    assert rule.alias_references() == {"web_hosts"}
    assert make(
        destination="10.0.0.5", protocol="UDP", destination_port="web_ports"
    ).alias_references() == {"web_ports"}


@pytest.mark.parametrize(
    "kw",
    [
        {"action": "allow"},
        {"interface": "LAN"},
        {"interface": "lan,wan"},
        {"source": "10.0.0.0/33"},
        {"source": "10.0.0.1/24"},
        {"source": "not an alias"},
        {"destination": "any;drop"},
        {"destination": "pass"},
        {"protocol": "TCP", "destination_port": "70000"},
        {"protocol": "TCP", "destination_port": "90:80"},
        {"protocol": "any", "destination_port": "80"},
        {"protocol": "ICMP", "ip_protocol": "inet6"},
        {"protocol": "IPv6-ICMP", "ip_protocol": "inet6"},
        {"description": "   "},
        {"description": "a\nb"},
        {"gateway": "WAN_GW"},
        {"direction": "both"},
    ],
)
def test_rejects_bad_input(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make(**kw)


def test_risk_reasons() -> None:
    assert make(action="pass").risk_reasons() == ["passes any source to any destination"]
    assert make(action="block").risk_reasons() == []
    assert make(source="10.0.0.0/8").risk_reasons() == []
    assert make(interface="wan", source="10.0.0.0/8").risk_reasons() == [
        "changes the WAN interface"
    ]
    assert len(make(interface="wan").risk_reasons()) == 2


def test_rule_operations_are_registered_as_writes() -> None:
    for op_id in ("add", "update", "delete", "toggle"):
        op = get_operation(f"firewall.rules.{op_id}")
        assert not op.read_only and op.apply_required
        assert op.verified == (op_id == "toggle")
    assert get_operation("firewall.rules.update").resolve_endpoint({"uuid": UUID}).endswith(UUID)
    apply = get_operation("firewall.rules.apply")
    assert apply.endpoint == "/api/firewall/filter/apply" and not apply.read_only
    with pytest.raises(ValueError):
        get_operation("firewall.rules.toggle").resolve_endpoint({"uuid": "../x"})
