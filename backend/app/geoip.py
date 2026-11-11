"""Offline country lookup for public IP addresses (GeoLite2-Country .mmdb). No network calls.

The database file is mounted into the container and refreshed outside the app, so the
licence key never reaches the backend. A missing or unreadable file disables the feature."""

import ipaddress
import os
import threading
from collections.abc import Callable
from functools import lru_cache
from typing import Any

import maxminddb

from app.core.logging import get_logger

log = get_logger(__name__)

CountryLookup = Callable[[str], str | None]


class GeoIP:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._reader: Any = None
        self._stamp: tuple[int, int] | None = None

    def _current_reader(self) -> Any:
        """Open (or reopen after the file was replaced) the database. None when unavailable."""
        if not self._path:
            return None
        try:
            st = os.stat(self._path)
        except OSError:
            return None
        stamp = (st.st_mtime_ns, st.st_size)
        with self._lock:
            if self._reader is None or stamp != self._stamp:
                try:
                    # The old reader is dropped, not closed: in-flight requests may still use it.
                    self._reader = maxminddb.open_database(self._path)
                    self._stamp = stamp
                except OSError, ValueError, maxminddb.InvalidDatabaseError:
                    log.warning("geoip_database_unreadable")
                    self._reader = None
                    self._stamp = None
            return self._reader

    def resolver(self) -> CountryLookup | None:
        """A lookup function for one request, or None when no database is available."""
        reader = self._current_reader()
        if reader is None:
            return None
        seen: dict[str, str | None] = {}

        def lookup(address: str) -> str | None:
            if address in seen:
                return seen[address]
            seen[address] = value = _country(reader, address)
            return value

        return lookup


def _country(reader: Any, address: str) -> str | None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    # Private, loopback, link-local, reserved and documentation ranges are never looked up.
    if not ip.is_global or ip.is_multicast:
        return None
    try:
        record = reader.get(str(ip))
    except ValueError, maxminddb.InvalidDatabaseError:
        return None
    country = record.get("country") if isinstance(record, dict) else None
    code = country.get("iso_code") if isinstance(country, dict) else None
    if isinstance(code, str) and len(code) == 2 and code.isalpha():
        return code.upper()
    return None


@lru_cache(maxsize=4)
def geoip_for(path: str) -> GeoIP:
    return GeoIP(path)
