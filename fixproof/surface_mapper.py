"""
surface_mapper.py — Build an attack-surface map from crawl results.

Extracts GET parameters, POST forms, inputs, hidden fields, cookies,
and API endpoint hints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field as PField


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class FormField(BaseModel):
    """A single form field."""
    tag: str  # input, textarea, select
    input_type: str = "text"
    name: str = ""
    value: str = ""
    is_hidden: bool = False


class FormSurface(BaseModel):
    """Represents a discoverable form."""
    page_url: str
    action: str
    method: str = "GET"
    fields: list[FormField] = PField(default_factory=list)


class ParameterSurface(BaseModel):
    """GET query parameters found in a URL."""
    url: str
    params: dict[str, list[str]]


class CookieSurface(BaseModel):
    """Cookies observed on a page."""
    url: str
    cookies: dict[str, str]


class ApiHint(BaseModel):
    """A possible API endpoint found in page source."""
    url: str
    hint: str  # the matching pattern or URL fragment


class AttackSurface(BaseModel):
    """Complete attack-surface map for a target."""
    forms: list[FormSurface] = PField(default_factory=list)
    parameters: list[ParameterSurface] = PField(default_factory=list)
    cookies: list[CookieSurface] = PField(default_factory=list)
    api_hints: list[ApiHint] = PField(default_factory=list)


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

_API_PATTERNS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/")


def map_surface(
    pages: list[dict],
    response_cookies: dict[str, str] | None = None,
) -> AttackSurface:
    """Build an ``AttackSurface`` from a list of crawl-result dicts.

    Each element in *pages* should have at least ``url`` and ``html`` keys.
    Optionally ``forms`` (pre-parsed) and ``links``.
    """
    surface = AttackSurface()

    all_urls: set[str] = set()

    for page in pages:
        url: str = page.get("url", "")
        html: str = page.get("html", "")
        all_urls.add(url)

        # --- GET parameters ---
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            surface.parameters.append(ParameterSurface(url=url, params=qs))

        # --- Forms ---
        if html:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = (form.get("method") or "GET").upper()
                fields: list[FormField] = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    inp_type = inp.get("type", "text") if inp.name == "input" else inp.name
                    value = inp.get("value", "")
                    is_hidden = inp_type == "hidden"
                    fields.append(FormField(
                        tag=inp.name,
                        input_type=inp_type,
                        name=name,
                        value=value,
                        is_hidden=is_hidden,
                    ))
                surface.forms.append(FormSurface(
                    page_url=url,
                    action=action,
                    method=method,
                    fields=fields,
                ))

        # --- Links that look like API endpoints ---
        links = page.get("links", [])
        for link in links:
            for pattern in _API_PATTERNS:
                if pattern in link.lower():
                    surface.api_hints.append(ApiHint(url=link, hint=pattern))
                    break

        # Also check HTML source for JS fetch/XHR patterns.
        if html:
            for pattern in _API_PATTERNS:
                if pattern in html:
                    surface.api_hints.append(ApiHint(url=url, hint=f"source contains {pattern}"))

    # --- Cookies ---
    if response_cookies:
        surface.cookies.append(CookieSurface(
            url=next(iter(all_urls), ""),
            cookies=response_cookies,
        ))

    return surface
