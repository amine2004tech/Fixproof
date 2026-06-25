"""Tests for fixproof.retest — retest logic."""

import pytest

from fixproof.session_store import ScanSession, TestCase
from fixproof.retest import retest_session


class TestRetestLogic:
    """Test retest without a live server (mocked responses)."""

    def test_skips_non_retestable_or_non_vulnerable(self, monkeypatch):
        """Observations and non-vulnerable cases should not be retested."""

        class FakeSession:
            def get(self, *a, **kw):
                raise AssertionError("Should not be called")

        monkeypatch.setattr("fixproof.retest.requests.Session", FakeSession)

        session = ScanSession(
            target_url="http://localhost:3000",
            test_cases=[
                TestCase(
                    id="safe1",
                    check_type="headers",
                    url="http://localhost:3000",
                    payload={"header": "X-Frame-Options"},
                    vulnerable=True,
                    retestable=False,
                    category="observation",
                    severity="info",
                    description="Observation",
                ),
                TestCase(
                    id="safe2",
                    check_type="xss",
                    url="http://localhost:3000",
                    vulnerable=False,
                    retestable=True,
                    category="attack",
                    severity="high",
                    description="Safe XSS",
                )
            ],
        )

        result = retest_session(session)
        assert result.test_cases[0].retest_result is None
        assert result.test_cases[1].retest_result is None

    def test_retest_xss_fixed(self, monkeypatch):
        """XSS marker not reflected = not_reproducible."""

        class FakeResp:
            headers = {}
            text = "Clean output"
            cookies = []

        class FakeSession:
            def get(self, *a, **kw):
                return FakeResp()
            def post(self, *a, **kw):
                return FakeResp()

        monkeypatch.setattr("fixproof.retest.requests.Session", FakeSession)

        session = ScanSession(
            target_url="http://localhost:3000",
            test_cases=[
                TestCase(
                    id="x1",
                    check_type="xss",
                    url="http://localhost:3000/search",
                    method="GET",
                    payload={"param": "q", "value": "FPXSS<script>alert(1)</script>"},
                    vulnerable=True,
                    retestable=True,
                    category="attack",
                    severity="high",
                    description="Reflected XSS",
                ),
            ],
        )

        result = retest_session(session)
        assert result.test_cases[0].retest_result == "NOT_REPRODUCIBLE"

    def test_retest_sqli_still_vuln(self, monkeypatch):
        """SQL error still present = still_vulnerable."""

        class FakeResp:
            headers = {}
            text = "You have an error in your SQL syntax"
            cookies = []

        class FakeSession:
            def get(self, *a, **kw):
                return FakeResp()
            def post(self, *a, **kw):
                return FakeResp()

        monkeypatch.setattr("fixproof.retest.requests.Session", FakeSession)

        session = ScanSession(
            target_url="http://localhost:3000",
            test_cases=[
                TestCase(
                    id="sq1",
                    check_type="sqli",
                    url="http://localhost:3000/users",
                    method="GET",
                    payload={"param": "id", "value": "'", "technique": "error-based"},
                    vulnerable=True,
                    retestable=True,
                    category="attack",
                    severity="critical",
                    description="Error-based SQLi",
                ),
            ],
        )

        result = retest_session(session)
        assert result.test_cases[0].retest_result == "STILL_VULNERABLE"


