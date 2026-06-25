"""
checks/headers.py — Security header analysis.

Checks for the presence and correctness of security-related HTTP headers.
"""

from __future__ import annotations

import uuid
from typing import Any

import requests

from fixproof.guard import assert_localhost
from fixproof.session_store import TestCase

# ---------------------------------------------------------------------------
# Expected security headers and their recommendations.
# ---------------------------------------------------------------------------

_HEADER_CHECKS: list[dict[str, str]] = [
    {
        "header": "Content-Security-Policy",
        "severity": "high",
        "description": "Content-Security-Policy header is missing.",
        "remediation": "Set a strict CSP that disallows inline scripts and limits sources.",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "medium",
        "expected": "nosniff",
        "description": "X-Content-Type-Options header is missing or incorrect.",
        "remediation": "Set X-Content-Type-Options: nosniff.",
    },
    {
        "header": "X-Frame-Options",
        "severity": "medium",
        "description": "X-Frame-Options header is missing.",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    },
    {
        "header": "Strict-Transport-Security",
        "severity": "medium",
        "description": "Strict-Transport-Security header is missing.",
        "remediation": "Set HSTS with a max-age of at least 31536000.",
    },
    {
        "header": "Referrer-Policy",
        "severity": "low",
        "description": "Referrer-Policy header is missing.",
        "remediation": "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
    },
    {
        "header": "Permissions-Policy",
        "severity": "low",
        "description": "Permissions-Policy header is missing.",
        "remediation": "Set a Permissions-Policy that restricts unnecessary browser features.",
    },
    {
        "header": "X-XSS-Protection",
        "severity": "info",
        "description": "Deprecated header missing; modern protection should rely on output encoding and CSP.",
        "remediation": "Set X-XSS-Protection: 0 (rely on CSP instead).",
    },
]


def check_headers(
    url: str,
    timeout: float = 5.0,
    cookies: dict[str, str] | None = None,
) -> list[TestCase]:
    """Check *url* for missing or misconfigured security headers."""
    assert_localhost(url)

    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return [TestCase(
            id=str(uuid.uuid4()),
            check_type="headers",
            url=url,
            evidence=f"Connection error: {exc}",
            vulnerable=False,
            severity="info",
            description="Could not connect to the target.",
        )]

    results: list[TestCase] = []

    for chk in _HEADER_CHECKS:
        header_name = chk["header"]
        header_val = resp.headers.get(header_name)

        missing = header_val is None
        wrong_value = False

        if not missing and "expected" in chk:
            wrong_value = header_val.lower() != chk["expected"].lower()

        if missing or wrong_value:
            evidence = f"Header {header_name!r} "
            if missing:
                evidence += "is missing from the response."
            else:
                evidence += f"has value {header_val!r} (expected {chk.get('expected', 'present')!r})."

            results.append(TestCase(
                id=str(uuid.uuid4()),
                check_type="headers",
                category="observation",
                url=url,
                method="GET",
                payload={"header": header_name},
                evidence=evidence,
                vulnerable=True,
                severity=chk["severity"],
                description=chk["description"],
                remediation=chk["remediation"],
                retestable=False,
            ))

    return results
