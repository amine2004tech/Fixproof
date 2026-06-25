"""
session_store.py — Persist and reload test cases.

All findings and test-case metadata are stored in ``.fixproof/session.json``
so that retest can replay the exact same payloads.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestCase(BaseModel):
    """A single test case that was executed."""
    id: str
    check_type: str  # e.g. "xss", "sqli", "headers", "cookies", "csrf"
    category: str = "observation"  # "attack" or "observation"
    url: str
    method: str = "GET"
    payload: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    evidence: str = ""
    vulnerable: bool = False
    severity: str = "info"  # info, low, medium, high, critical
    description: str = ""
    remediation: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retest_result: Optional[str] = None  # "FIXED", "STILL_VULNERABLE", "NOT_REPRODUCIBLE", "MANUAL_REVIEW", None
    retestable: bool = False
    sources: list[str] = Field(default_factory=list)


class ScanSession(BaseModel):
    """A complete scan session."""
    target_url: str
    scan_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    crawled_urls: list[str] = Field(default_factory=list)
    surfaces: list[dict[str, Any]] = Field(default_factory=list)
    test_cases: list[TestCase] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_SESSION_DIR = ".fixproof"
_SESSION_FILE = "session.json"


def _session_path() -> Path:
    return Path(_SESSION_DIR) / _SESSION_FILE


def save_session(session: ScanSession) -> Path:
    """Save a scan session to disk."""
    path = _session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(session.model_dump(), indent=2, default=str), encoding="utf-8")
    return path


def load_session() -> ScanSession | None:
    """Load a scan session from disk, or return ``None`` if it doesn't exist."""
    path = _session_path()
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return ScanSession.model_validate(data)


def session_exists() -> bool:
    """Return True if a session file exists."""
    return _session_path().exists()
