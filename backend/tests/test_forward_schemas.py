"""Validation and risk rules for NAT port forward proposals (ADR-0006)."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.changes.forward_schemas import ForwardProposal


def make(**over: Any) -> ForwardProposal:
    base: dict[str, Any] = {
        "interface": "lan",
        "destination": "lanip",
        "destination_port": "8443",
        "target": "10.0.0.5",
        "target_port": "443",
        "description": "Web",
    }
    return ForwardProposal(**{**base, **over})


def test_valid_forward_defaults() -> None:
    f = make()
    assert f.enabled and f.protocol == "TCP" and f.ip_protocol == "inet" and f.source == "any"
    assert f.risk_reasons() == []
    assert f.alias_references() == set()


def test_description_is_required_and_cleaned() -> None:
    with pytest.raises(ValidationError):
        make(description="   ")
    with pytest.raises(ValidationError):
        make(description="a\nb")
    assert make(description="  Web  ").description == "Web"


@pytest.mark.parametrize(
    "over",
    [
        {"interface": "WAN"},
        {"interface": "lan; rm"},
        {"protocol": "ICMP"},
        {"protocol": "any"},
        {"target": "10.0.0.0/24"},
        {"target": "any"},
        {"target": "bad name"},
        {"target_port": "80:90"},
        {"destination_port": "99999"},
        {"ip_protocol": "inet6"},  # IPv4 target with IPv6 selected
        {"source": "10.0.0.0/33"},
        {"unknown_field": "x"},
    ],
)
def test_invalid_forwards_are_refused(over: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make(**over)


def test_interface_address_keyword_and_ipv6() -> None:
    assert make(interface="opt1", destination="opt1ip").destination == "opt1ip"
    f = make(ip_protocol="inet6", target="2001:db8::5", source="2001:db8::/32", destination="lanip")
    assert f.target == "2001:db8::5"
    with pytest.raises(ValidationError):
        make(ip_protocol="inet", source="2001:db8::/32")


def test_alias_references_include_targets_and_ports() -> None:
    f = make(source="Office", target="WebHost", destination_port="WebPorts", target_port="")
    assert f.alias_references() == {"Office", "WebHost", "WebPorts"}


def test_other_interface_keyword_is_treated_as_an_alias_name() -> None:
    # Checked against the firewall's aliases at stage time, where it will not be found.
    assert make(destination="wanip").alias_references() == {"wanip"}
    assert make(target="lanip").alias_references() == {"lanip"}


def test_reserved_alias_names_are_refused() -> None:
    with pytest.raises(ValidationError):
        make(target="pass")


def test_wan_is_high_risk() -> None:
    f = make(interface="wan", destination="wanip")
    assert any("WAN" in r for r in f.risk_reasons())


def test_any_source_with_open_or_ranged_port_is_high_risk() -> None:
    assert make(destination_port="").risk_reasons()
    assert make(destination_port="8000:8100").risk_reasons()
    assert not make(destination_port="8443").risk_reasons()
    assert not make(source="10.1.0.0/16", destination_port="").risk_reasons()
    both = make(interface="wan", destination="wanip", destination_port="")
    assert len(both.risk_reasons()) == 2
