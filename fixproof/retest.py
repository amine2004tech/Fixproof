"""
retest.py — Replay saved test cases and compare results.
"""

from __future__ import annotations

import time

import requests

from fixproof.guard import assert_localhost
from fixproof.checks.xss import _MARKER, _verify_stability, _confirm_with_playwright
from fixproof.checks.sqli import (
    _has_sql_error, _boolean_compare,
    _BOOLEAN_TRUE, _BOOLEAN_FALSE,
    _TIME_PAYLOAD, _TIME_THRESHOLD,
)
from fixproof.session_store import ScanSession, TestCase, load_session, save_session


def retest_session(
    session_data: ScanSession | None = None,
    timeout: float = 5.0,
) -> ScanSession:
    """Replay all test cases from a saved session."""
    if session_data is None:
        session_data = load_session()
    if session_data is None:
        raise FileNotFoundError("No session found. Run a scan first.")

    http = requests.Session()

    for tc in session_data.test_cases:
        if not tc.vulnerable or not tc.retestable:
            continue
        try:
            assert_localhost(tc.url)
        except ValueError:
            tc.retest_result = "SKIPPED"
            continue
        try:
            still_vuln = _replay(http, tc, timeout)
            if still_vuln:
                tc.retest_result = "STILL_VULNERABLE"
            else:
                tc.retest_result = "NOT_REPRODUCIBLE" if tc.check_type == "xss" else "FIXED"
        except Exception:
            tc.retest_result = "ERROR"

    save_session(session_data)
    return session_data


def _replay(http: requests.Session, tc: TestCase, timeout: float) -> bool:
    if tc.check_type == "headers":
        resp = http.get(tc.url, timeout=timeout)
        return tc.payload.get("header", "") not in resp.headers
    elif tc.check_type == "cookies":
        return True  # Conservative
    elif tc.check_type == "csrf":
        return True
    elif tc.check_type == "xss":
        return _replay_xss(http, tc, timeout)
    elif tc.check_type == "sqli":
        return _replay_sqli(http, tc, timeout)
    return False


def _replay_xss(http: requests.Session, tc: TestCase, timeout: float) -> bool:
    from fixproof.checks.xss import _MARKER, evaluate_xss_response
    p = tc.payload
    try:
        if tc.method == "GET":
            resp = http.get(tc.url, params=p.get("data", {}), timeout=timeout)
        else:
            resp = http.post(tc.url, data=p.get("data", {}), timeout=timeout)
            
        if _MARKER not in resp.text:
            return False
            
        eval_result = evaluate_xss_response(resp.text, p.get("value", ""))
        return eval_result["category"] == "attack"
    except Exception:
        return False


def _replay_sqli(http: requests.Session, tc: TestCase, timeout: float) -> bool:
    p = tc.payload
    technique = p.get("technique", "error-based")
    if tc.method == "GET":
        param = p.get("param", "")
        val = p.get("value", "")
        if technique == "error-based":
            resp = http.get(tc.url, params={param: val}, timeout=timeout)
            return _has_sql_error(resp.text) is not None
        elif technique == "boolean-based":
            rt = http.get(tc.url, params={param: _BOOLEAN_TRUE}, timeout=timeout)
            rf = http.get(tc.url, params={param: _BOOLEAN_FALSE}, timeout=timeout)
            return _boolean_compare(rt.text, rf.text)
        elif technique == "time-based":
            start = time.monotonic()
            http.get(tc.url, params={param: _TIME_PAYLOAD}, timeout=timeout + 3)
            return (time.monotonic() - start) >= _TIME_THRESHOLD
    else:
        resp = http.post(tc.url, data=p.get("data", {}), timeout=timeout)
        return _has_sql_error(resp.text) is not None
    return False
