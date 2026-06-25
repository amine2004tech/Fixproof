"""
checks/csrf.py — CSRF token detection.

Identifies forms that perform state-changing operations without CSRF tokens.
"""

from __future__ import annotations

import uuid

from fixproof.session_store import TestCase
from fixproof.surface_mapper import AttackSurface

_CSRF_FIELD_NAMES = frozenset({
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_token", "token", "authenticity_token", "xsrf",
    "xsrf_token", "_xsrf", "__requestverificationtoken",
})


def check_csrf(surface: AttackSurface) -> list[TestCase]:
    """Check forms in *surface* for missing CSRF tokens.

    Only POST forms are flagged — GET forms are typically safe.
    """
    results: list[TestCase] = []

    for form in surface.forms:
        if form.method != "POST":
            continue

        field_names = {f.name.lower() for f in form.fields if f.name}

        has_csrf = bool(field_names & _CSRF_FIELD_NAMES)

        if not has_csrf:
            results.append(TestCase(
                id=str(uuid.uuid4()),
                check_type="csrf",
                category="observation",
                url=form.page_url,
                method="POST",
                payload={"form_action": form.action, "fields": list(field_names)},
                evidence=(
                    f"POST form at {form.action!r} has no CSRF token field. "
                    f"Fields: {', '.join(sorted(field_names)) or '(none)'}."
                ),
                vulnerable=True,
                severity="medium",
                description="Form is missing CSRF protection.",
                remediation=(
                    "Add a CSRF token (e.g., csrf_token hidden input) to all "
                    "state-changing forms and validate it server-side."
                ),
                retestable=False,
            ))

    return results
