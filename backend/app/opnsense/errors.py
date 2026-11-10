import enum


class ConnectionStatus(enum.StrEnum):
    ok = "ok"
    timeout = "timeout"
    unreachable = "unreachable"
    tls_error = "tls_error"
    auth_failed = "auth_failed"
    forbidden = "forbidden"
    not_found = "not_found"
    server_error = "server_error"
    bad_response = "bad_response"


class FirewallError(Exception):
    """A failure talking to a firewall. ``status`` is safe to show to users; no secrets inside."""

    def __init__(self, status: ConnectionStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.retry_ok = False
        self.message = message
