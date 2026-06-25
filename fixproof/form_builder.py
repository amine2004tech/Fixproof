"""
form_builder.py — Build form submissions for injection testing.

Preserves hidden fields and mutates one field at a time so that
form validation and CSRF tokens are maintained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fixproof.surface_mapper import FormField, FormSurface


@dataclass
class FormSubmission:
    """A concrete form submission ready to send."""
    action: str
    method: str
    data: dict[str, str]
    mutated_field: str  # name of the field that was injected
    payload: str  # the payload value injected


def build_submissions(
    form: FormSurface,
    payloads: list[str],
) -> list[FormSubmission]:
    """Generate form submissions by injecting each payload into each mutable field.

    Hidden fields are preserved with their original values.  Only one field
    is mutated per submission.
    """
    mutable_fields = [f for f in form.fields if not f.is_hidden and f.name]
    hidden_base = {f.name: f.value for f in form.fields if f.is_hidden and f.name}
    default_base = {f.name: f.value for f in form.fields if f.name}

    submissions: list[FormSubmission] = []

    for fld in mutable_fields:
        for payload in payloads:
            data = dict(default_base)
            data.update(hidden_base)  # Ensure hidden fields stay.
            data[fld.name] = payload
            submissions.append(FormSubmission(
                action=form.action,
                method=form.method,
                data=data,
                mutated_field=fld.name,
                payload=payload,
            ))

    return submissions
