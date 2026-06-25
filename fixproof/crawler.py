"""
crawler.py — Requests-based web crawler (no JavaScript rendering).

Follows links within the same localhost origin and collects pages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from fixproof.guard import assert_localhost


@dataclass
class CrawlResult:
    """Result of crawling a single page."""
    url: str
    status_code: int
    content_type: str = ""
    html: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)


def _same_origin(base: str, url: str) -> bool:
    """Check if *url* shares the same origin as *base*."""
    bp = urlparse(base)
    up = urlparse(url)
    return bp.scheme == up.scheme and bp.netloc == up.netloc


def crawl(
    start_url: str,
    max_pages: int = 50,
    timeout: float = 5.0,
    cookies: dict[str, str] | None = None,
) -> list[CrawlResult]:
    """Crawl *start_url* and follow same-origin links.

    Returns a list of ``CrawlResult`` objects for visited pages.
    """
    assert_localhost(start_url)

    visited: set[str] = set()
    queue: list[str] = [start_url]
    results: list[CrawlResult] = []
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        normalized = urlparse(url)._replace(fragment="").geturl()

        if normalized in visited:
            continue
        visited.add(normalized)

        # Guard every outgoing request.
        assert_localhost(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue

        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct and "application/xhtml" not in ct:
            results.append(CrawlResult(url=url, status_code=resp.status_code, content_type=ct))
            continue

        soup = BeautifulSoup(resp.text, "lxml")

        # Extract links.
        links: list[str] = []
        for a in soup.find_all("a", href=True):
            href = urljoin(url, a["href"])
            if _same_origin(start_url, href):
                links.append(href)
                if href not in visited:
                    queue.append(href)

        # Extract basic form info.
        forms: list[dict] = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", ""))
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "tag": inp.name,
                    "type": inp.get("type", "text"),
                    "name": inp.get("name", ""),
                    "value": inp.get("value", ""),
                })
            forms.append({"action": action, "method": method, "inputs": inputs})

        results.append(CrawlResult(
            url=url,
            status_code=resp.status_code,
            content_type=ct,
            html=resp.text,
            links=links,
            forms=forms,
        ))

    return results
