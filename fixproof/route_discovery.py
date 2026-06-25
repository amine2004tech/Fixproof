"""
route_discovery.py — Discover common routes and endpoints.

Tries a wordlist of common development paths to find additional
pages that the crawler might miss.
"""

from __future__ import annotations

from urllib.parse import urljoin

import requests

from fixproof.guard import assert_localhost

# Common development routes to probe.
_COMMON_ROUTES = [
    "/",
    "/login",
    "/register",
    "/admin",
    "/dashboard",
    "/api",
    "/api/v1",
    "/api/users",
    "/search",
    "/profile",
    "/settings",
    "/logout",
    "/health",
    "/status",
    "/debug",
    "/test",
    "/about",
    "/contact",
    "/docs",
    "/swagger",
    "/graphql",
    "/robots.txt",
    "/sitemap.xml",
]


def discover_routes(
    base_url: str,
    extra_routes: list[str] | None = None,
    timeout: float = 3.0,
    cookies: dict[str, str] | None = None,
) -> list[dict]:
    """Probe *base_url* for common routes.

    Returns a list of dicts with ``url``, ``status_code``, and ``content_type``.
    """
    assert_localhost(base_url)

    routes = list(_COMMON_ROUTES)
    if extra_routes:
        routes.extend(extra_routes)

    found: list[dict] = []
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    for route in routes:
        url = urljoin(base_url, route)
        try:
            assert_localhost(url)
            resp = session.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code < 404:
                found.append({
                    "url": url,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                })
        except (requests.RequestException, ValueError):
            continue

    return found
