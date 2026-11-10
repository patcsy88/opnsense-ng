"""Per-firewall trust: validated PEM CA bundle -> SSL context."""

import re
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

CA_BUNDLE_MAX_BYTES = 64 * 1024
CA_BUNDLE_MAX_CERTS = 20
_PEM_BEGIN = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")


class InvalidCaBundleError(ValueError):
    """The supplied PEM is not an acceptable certificate bundle (message is user-safe)."""


def normalise_ca_bundle(pem: str) -> str:
    """Accept only PEM blocks of public CERTIFICATE type (a private key pasted by mistake is
    rejected, never stored). Returns the re-encoded canonical PEM."""
    if len(pem.encode()) > CA_BUNDLE_MAX_BYTES:
        raise InvalidCaBundleError("CA bundle is too large")
    labels = _PEM_BEGIN.findall(pem)
    if not labels:
        raise InvalidCaBundleError("CA bundle must contain PEM certificates")
    if any(label != "CERTIFICATE" for label in labels):
        raise InvalidCaBundleError("CA bundle may only contain CERTIFICATE blocks")
    try:
        certs = x509.load_pem_x509_certificates(pem.encode())
    except ValueError:
        raise InvalidCaBundleError("CA bundle is not valid PEM certificate data") from None
    if not certs or len(certs) != len(labels):
        raise InvalidCaBundleError("CA bundle contains an unparsable certificate")
    if len(certs) > CA_BUNDLE_MAX_CERTS:
        raise InvalidCaBundleError(
            f"CA bundle may contain at most {CA_BUNDLE_MAX_CERTS} certificates"
        )
    return "".join(c.public_bytes(Encoding.PEM).decode() for c in certs)


def build_ssl_context(*, verify_tls: bool, ca_bundle_pem: str | None) -> ssl.SSLContext:
    """verify_tls=False disables verification entirely (only reachable when the operator set
    ALLOW_INSECURE_TLS). A CA bundle replaces the system trust store for this firewall."""
    if not verify_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_bundle_pem:
        return ssl.create_default_context(cadata=ca_bundle_pem)
    return ssl.create_default_context()
