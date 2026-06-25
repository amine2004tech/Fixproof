"""
guard.py — Localhost-only URL validator.

Hard safety rules:
- Only allow 127.0.0.1, ::1, and localhost.
- Reject all LAN IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x).
- Reject all public IPs and domains.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class GuardResult(BaseModel):
    """Result of a URL safety check."""
    allowed: bool
    url: str
    reason: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_loopback(ip_str: str) -> bool:
    """Return True only if *ip_str* resolves to a loopback address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_loopback
    except ValueError:
        return False


def _resolve_host(hostname: str) -> list[str]:
    """Resolve a hostname to its IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_url(url: str) -> GuardResult:
    """Validate that *url* targets localhost only.

    Returns a ``GuardResult`` indicating whether the URL is safe to scan.
    """
    parsed = urlparse(url)

    # Must have an HTTP(S) scheme.
    if parsed.scheme not in ("http", "https"):
        return GuardResult(allowed=False, url=url, reason=f"Unsupported scheme: {parsed.scheme!r}")

    hostname = parsed.hostname
    if hostname is None:
        return GuardResult(allowed=False, url=url, reason="No hostname found in URL")

    # Fast-path: hostname is in the explicit allowlist.
    if hostname in _ALLOWED_HOSTS:
        return GuardResult(allowed=True, url=url, reason="Hostname is in localhost allowlist")

    # Check if the hostname is a raw IP address.
    if _is_loopback(hostname):
        return GuardResult(allowed=True, url=url, reason="IP is loopback")

    # Resolve hostname and check all IPs.
    resolved = _resolve_host(hostname)
    if not resolved:
        return GuardResult(allowed=False, url=url, reason=f"Cannot resolve hostname: {hostname!r}")

    for ip in resolved:
        if not _is_loopback(ip):
            return GuardResult(
                allowed=False,
                url=url,
                reason=f"Hostname {hostname!r} resolves to non-loopback IP {ip}",
            )

    return GuardResult(allowed=True, url=url, reason="All resolved IPs are loopback")


def assert_localhost(url: str) -> None:
    """Raise ``ValueError`` if *url* does not target localhost."""
    result = validate_url(url)
    if not result.allowed:
        raise ValueError(f"BLOCKED — {result.reason}: {url}")
