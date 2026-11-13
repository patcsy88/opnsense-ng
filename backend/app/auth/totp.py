"""TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) with the standard library only (ADR-0012)."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

import segno

DIGITS = 6
STEP_SECONDS = 30
DRIFT_STEPS = 1
SECRET_BYTES = 20  # 160 bits
ISSUER = "OPNsense Manager"


def new_secret() -> str:
    """Random secret as unpadded base32, the form authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time step that ``code`` is valid for (within the drift window), or None. Every
    candidate is compared in constant time so timing does not reveal which step matched."""
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return None
    centre = current_step(now)
    found: int | None = None
    for step in range(centre - DRIFT_STEPS, centre + DRIFT_STEPS + 1):
        if hmac.compare_digest(code_at(secret, step), code):
            found = step
    return found


def otpauth_uri(secret: str, username: str) -> str:
    label = f"{quote(ISSUER, safe='')}:{quote(username, safe='')}"
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )


def qr_matrix(data: str) -> list[list[bool]]:
    """The QR code as rows of dark (True) and light modules, without a quiet zone. The frontend
    draws it as inline SVG, so no image or markup crosses the API."""
    code = segno.make(data, error="m", micro=False)
    return [[bool(module) for module in row] for row in code.matrix]
