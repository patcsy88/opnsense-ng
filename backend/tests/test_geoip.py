"""Country lookups. The database reader is faked; no .mmdb file or network is used."""

from pathlib import Path
from typing import Any

import httpx
import maxminddb
import pytest
import respx

from app.db.models import Role
from app.geoip import GeoIP, _country
from app.opnsense.normalise import normalise_log, summarise_log
from tests.test_api import create_fw, login_as
from tests.test_changes_api import switch
from tests.test_logs import URL, record


class FakeReader:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, address: str) -> Any:
        self.calls.append(address)
        return {
            "8.8.8.8": {"country": {"iso_code": "us"}},
            "1.1.1.1": {"country": {"iso_code": "AU"}},
            "9.9.9.9": {"country": {"iso_code": "<script>"}},
            "4.4.4.4": {"continent": {}},
        }.get(address)


def test_only_public_addresses_are_looked_up() -> None:
    reader = FakeReader()
    assert _country(reader, "8.8.8.8") == "US"
    for private in (
        "192.168.100.5",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",  # noqa: S104
        "224.0.0.1",
    ):
        assert _country(reader, private) is None
    assert _country(reader, "203.0.113.9") is None  # documentation range
    assert _country(reader, "fe80::1") is None and _country(reader, "not-an-ip") is None
    assert reader.calls == ["8.8.8.8"]


def test_odd_database_values_yield_no_country() -> None:
    reader = FakeReader()
    assert _country(reader, "9.9.9.9") is None
    assert _country(reader, "4.4.4.4") is None
    assert _country(reader, "8.8.4.4") is None


def test_entries_and_summary_carry_country_and_count_by_country() -> None:
    rows = [record(src="8.8.8.8")] * 3 + [record(src="1.1.1.1")] + [record(src="192.168.1.5")] * 2
    rows.append(record(src="8.8.8.8", action="pass"))
    reader = FakeReader()
    lookup = lambda a: _country(reader, a)  # noqa: E731
    s = summarise_log(rows, country=lookup)
    assert {(t.label, t.count) for t in s.blocked_by_country} == {("US", 3), ("AU", 1)}
    tops = {t.label: t.country for t in s.top_blocked_sources}
    assert tops == {"8.8.8.8": "US", "1.1.1.1": "AU", "192.168.1.5": None}
    entries = normalise_log(rows, country=lookup).entries
    assert entries[0].source_country == "US" and entries[4].source_country is None
    plain = summarise_log(rows)
    assert plain.blocked_by_country == [] and all(
        t.country is None for t in plain.top_blocked_sources
    )
    assert normalise_log(rows).entries[0].source_country is None


def test_missing_or_corrupt_database_disables_the_feature(tmp_path: Path) -> None:
    assert GeoIP("").resolver() is None
    assert GeoIP(str(tmp_path / "absent.mmdb")).resolver() is None
    bad = tmp_path / "bad.mmdb"
    bad.write_bytes(b"not a database")
    assert GeoIP(str(bad)).resolver() is None


def test_reader_is_reopened_when_the_file_is_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "c.mmdb"
    db.write_bytes(b"one")
    opened: list[str] = []

    def fake_open(path: str) -> FakeReader:
        opened.append(path)
        return FakeReader()

    monkeypatch.setattr(maxminddb, "open_database", fake_open)
    g = GeoIP(str(db))
    assert g.resolver() is not None and g.resolver() is not None
    assert len(opened) == 1
    db.write_bytes(b"two-longer")
    assert g.resolver() is not None
    assert len(opened) == 2


async def test_logs_endpoint_reports_geoip_state(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await login_as(app_client, Role.admin)
    fid = await create_fw(app_client)
    await switch(app_client, Role.security_admin, "sec")
    rows = [record(src="8.8.8.8"), record(src="192.168.1.5")]
    with respx.mock() as router:
        router.get(URL).respond(200, json=rows)
        off = (await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")).json()
        monkeypatch.setattr(GeoIP, "resolver", lambda self: lambda a: _country(FakeReader(), a))
        on = (await app_client.get(f"/api/v1/firewalls/{fid}/firewall/logs")).json()
    assert off["geoip_enabled"] is False and off["entries"][0]["source_country"] is None
    assert on["geoip_enabled"] is True
    assert on["entries"][0]["source_country"] == "US" and on["entries"][1]["source_country"] is None
    assert on["summary"]["blocked_by_country"] == [{"label": "US", "count": 1, "country": None}]
