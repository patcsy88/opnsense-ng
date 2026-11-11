"""Stable fingerprint of a normalised object, used for stale-revision checks."""

import hashlib
import json
from typing import Any


def fingerprint(snapshot: Any) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
