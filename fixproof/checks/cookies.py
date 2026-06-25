"""
checks/cookies.py — Cookie security analysis.

Checks cookies for missing HttpOnly, Secure, and SameSite flags.
"""

from __future__ import annotations

import uuid

import requests

from fixproof.guard import assert_localhost
from fixproof.session_store import TestCase


def check_cookies(
    url: str,
    timeout: float = 5.0,
    extra_cookies: dict[str, str] | None = None,
) -> list[TestCase]:
    """Check cookies set by *url* for insecure flags."""
    assert_localhost(url)

    session = requests.Session()
    if extra_cookies:
        session.cookies.update(extra_cookies)

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return []

    results: list[TestCase] = []

    for cookie in resp.cookies:
        issues: list[str] = []

        if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
            issues.append("HttpOnly flag is missing")

        if not cookie.secure:
            issues.append("Secure flag is missing")

        samesite = cookie._rest.get("SameSite") or cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            issues.append("SameSite attribute is missing")

        if issues:
            results.append(TestCase(
                id=str(uuid.uuid4()),
                check_type="cookies",
                category="observation",
                url=url,
                method="GET",
                payload={"cookie_name": cookie.name},
                evidence=f"Cookie {cookie.name!r}: {'; '.join(issues)}.",
                vulnerable=True,
                severity="medium",
                description=f"Cookie {cookie.name!r} has insecure attributes.",
                remediation=(
                    "Set HttpOnly, Secure, and SameSite=Strict (or Lax) flags "
                    "on all sensitive cookies."
                ),
                retestable=False,
            ))

    return results
