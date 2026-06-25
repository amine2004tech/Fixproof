"""Tests for fixproof.session_store — saving and loading test cases."""

import json
import shutil
from pathlib import Path

import pytest

from fixproof.session_store import (
    ScanSession, TestCase, save_session, load_session, session_exists,
    _SESSION_DIR,
)


@pytest.fixture(autouse=True)
def clean_session_dir(tmp_path, monkeypatch):
    """Redirect session storage to a temp dir for tests."""
    test_dir = tmp_path / ".fixproof"
    monkeypatch.setattr("fixproof.session_store._SESSION_DIR", str(test_dir))
    yield test_dir
    if test_dir.exists():
        shutil.rmtree(test_dir)


class TestSessionStore:
    def test_save_and_load(self, clean_session_dir):
        session = ScanSession(
            target_url="http://localhost:3000",
            test_cases=[
                TestCase(
                    id="test-1",
                    check_type="xss",
                    url="http://localhost:3000/search",
                    method="GET",
                    payload={"param": "q", "value": "<script>"},
                    evidence="Marker reflected",
                    vulnerable=True,
                    severity="high",
                    description="Reflected XSS",
                    remediation="Encode output.",
                ),
            ],
        )
        save_session(session)
        loaded = load_session()

        assert loaded is not None
        assert loaded.target_url == "http://localhost:3000"
        assert len(loaded.test_cases) == 1
        assert loaded.test_cases[0].id == "test-1"
        assert loaded.test_cases[0].vulnerable is True

    def test_load_nonexistent(self, clean_session_dir):
        assert load_session() is None

    def test_session_exists(self, clean_session_dir):
        assert session_exists() is False
        session = ScanSession(target_url="http://localhost:3000")
        save_session(session)
        assert session_exists() is True

    def test_overwrite(self, clean_session_dir):
        s1 = ScanSession(target_url="http://localhost:3000")
        save_session(s1)
        s2 = ScanSession(target_url="http://localhost:5000")
        save_session(s2)
        loaded = load_session()
        assert loaded.target_url == "http://localhost:5000"

    def test_roundtrip_preserves_fields(self, clean_session_dir):
        tc = TestCase(
            id="tc-round",
            check_type="sqli",
            url="http://localhost:8080/api",
            method="POST",
            payload={"field": "name", "value": "' OR 1=1--"},
            headers={"X-Custom": "val"},
            cookies={"session": "abc"},
            evidence="SQL error in response",
            vulnerable=True,
            severity="critical",
            description="SQLi found",
            remediation="Use prepared statements.",
            retest_result="fixed",
        )
        session = ScanSession(
            target_url="http://localhost:8080",
            test_cases=[tc],
            coverage_gaps=["No GET params found"],
        )
        save_session(session)
        loaded = load_session()
        ltc = loaded.test_cases[0]
        assert ltc.method == "POST"
        assert ltc.cookies == {"session": "abc"}
        assert ltc.retest_result == "fixed"
        assert loaded.coverage_gaps == ["No GET params found"]
