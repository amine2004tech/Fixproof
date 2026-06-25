"""
checks/sqli.py — SQL injection detection.

Three detection strategies:
1. **Error-based** — look for SQL error strings in responses.
2. **Boolean comparison** — compare responses for always-true vs always-false.
3. **Time-delay comparison** — detect timing differences with SLEEP().

No database dumping, no data extraction — detection only.
"""

from __future__ import annotations

import time
import uuid
from typing import Any
from urllib.parse import urljoin

import requests

from fixproof.guard import assert_localhost
from fixproof.session_store import TestCase
from fixproof.surface_mapper import AttackSurface
from fixproof.form_builder import build_submissions

# ---------------------------------------------------------------------------
# Probe payloads
# ---------------------------------------------------------------------------

_ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    '" OR "1"="1',
    "1' AND '1'='1",
    "1; SELECT 1--",
    "' UNION SELECT NULL--",
]

_BOOLEAN_TRUE = "' OR '1'='1'--"
_BOOLEAN_FALSE = "' AND '1'='2'--"

_TIME_PAYLOAD = "' OR SLEEP(2)--"
_TIME_THRESHOLD = 1.5  # seconds

# SQL error fingerprints (lowercase).
_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3.operationalerror",
    "sqlstate",
    "syntax error",
    "sql syntax",
    "microsoft ole db",
    "odbc sql server driver",
    "invalid query",
    "unrecognized token",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_sql_error(text: str) -> str | None:
    """Return the matching error string if found, else None."""
    lower = text.lower()
    for err in _SQL_ERRORS:
        if err in lower:
            return err
    return None


def _boolean_compare(resp_true: str, resp_false: str) -> bool:
    """Return True if responses differ significantly (boolean-based SQLi indicator)."""
    if len(resp_true) == len(resp_false) and resp_true == resp_false:
        return False
    len_diff = abs(len(resp_true) - len(resp_false))
    min_len = max(len(resp_true), len(resp_false), 1)
    return (len_diff / min_len) > 0.05  # >5% size difference


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_sqli(
    surface: AttackSurface,
    base_url: str,
    timeout: float = 5.0,
    cookies: dict[str, str] | None = None,
) -> list[TestCase]:
    """Run SQLi probes against all surfaces."""
    assert_localhost(base_url)

    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    results: list[TestCase] = []

    # --- Test GET parameters ---
    for param_surface in surface.parameters:
        url = param_surface.url
        assert_localhost(url)
        for param_name in param_surface.params:
            results.extend(_test_param_sqli(session, url, param_name, timeout))

    # --- Test POST forms ---
    for form in surface.forms:
        results.extend(_test_form_sqli(session, form, base_url, timeout))

    return results


def _test_param_sqli(
    session: requests.Session,
    url: str,
    param_name: str,
    timeout: float,
) -> list[TestCase]:
    """Test a single GET parameter for SQLi."""
    results: list[TestCase] = []

    # 1. Error-based
    for payload in _ERROR_PAYLOADS:
        try:
            resp = session.get(url, params={param_name: payload}, timeout=timeout)
            err = _has_sql_error(resp.text)
            if err:
                results.append(TestCase(
                    id=str(uuid.uuid4()),
                    check_type="sqli",
                    category="attack",
                    url=url,
                    method="GET",
                    payload={"param": param_name, "value": payload, "technique": "error-based"},
                    evidence=f"SQL error detected: {err!r}. Payload: {payload!r}",
                    vulnerable=True,
                    severity="critical",
                    description=f"Error-based SQL injection via GET parameter {param_name!r}.",
                    remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    retestable=True,
                ))
                return results  # One proof is enough.
        except requests.RequestException:
            continue

    # 2. Boolean comparison
    try:
        resp_true = session.get(url, params={param_name: _BOOLEAN_TRUE}, timeout=timeout)
        resp_false = session.get(url, params={param_name: _BOOLEAN_FALSE}, timeout=timeout)
        if _boolean_compare(resp_true.text, resp_false.text):
            results.append(TestCase(
                id=str(uuid.uuid4()),
                check_type="sqli",
                category="attack",
                url=url,
                method="GET",
                payload={"param": param_name, "value": _BOOLEAN_TRUE, "technique": "boolean-based"},
                evidence=(
                    f"Boolean SQLi: true-payload response length={len(resp_true.text)}, "
                    f"false-payload response length={len(resp_false.text)}."
                ),
                vulnerable=True,
                severity="critical",
                description=f"Boolean-based SQL injection via GET parameter {param_name!r}.",
                remediation="Use parameterized queries / prepared statements.",
                retestable=True,
            ))
            return results
    except requests.RequestException:
        pass

    # 3. Time-delay comparison
    try:
        start = time.monotonic()
        session.get(url, params={param_name: _TIME_PAYLOAD}, timeout=timeout + 3)
        elapsed = time.monotonic() - start
        if elapsed >= _TIME_THRESHOLD:
            results.append(TestCase(
                id=str(uuid.uuid4()),
                check_type="sqli",
                category="attack",
                url=url,
                method="GET",
                payload={"param": param_name, "value": _TIME_PAYLOAD, "technique": "time-based"},
                evidence=f"Time-based SQLi: response took {elapsed:.2f}s (threshold: {_TIME_THRESHOLD}s).",
                vulnerable=True,
                severity="critical",
                description=f"Time-based SQL injection via GET parameter {param_name!r}.",
                remediation="Use parameterized queries / prepared statements.",
                retestable=True,
            ))
    except requests.RequestException:
        pass

    return results


def _test_form_sqli(
    session: requests.Session,
    form: Any,
    base_url: str,
    timeout: float,
) -> list[TestCase]:
    """Test a form's mutable fields for SQLi."""
    results: list[TestCase] = []

    # Error-based probes via form_builder.
    submissions = build_submissions(form, _ERROR_PAYLOADS)
    for sub in submissions:
        try:
            action_url = urljoin(base_url, sub.action)
            assert_localhost(action_url)
            if sub.method == "POST":
                resp = session.post(action_url, data=sub.data, timeout=timeout)
            else:
                resp = session.get(action_url, params=sub.data, timeout=timeout)

            err = _has_sql_error(resp.text)
            if err:
                results.append(TestCase(
                    id=str(uuid.uuid4()),
                    check_type="sqli",
                    category="attack",
                    url=action_url,
                    method=sub.method,
                    payload={
                        "field": sub.mutated_field,
                        "value": sub.payload,
                        "data": sub.data,
                        "technique": "error-based",
                    },
                    evidence=f"SQL error detected: {err!r}. Field: {sub.mutated_field!r}",
                    vulnerable=True,
                    severity="critical",
                    description=f"Error-based SQL injection via form field {sub.mutated_field!r}.",
                    remediation="Use parameterized queries / prepared statements.",
                    retestable=True,
                ))
                return results
        except (requests.RequestException, ValueError):
            continue

    return results
