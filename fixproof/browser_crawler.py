"""
browser_crawler.py — Playwright-based crawler for JS-rendered pages.

Falls back gracefully if Playwright browsers are not installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from fixproof.guard import assert_localhost

logger = logging.getLogger(__name__)


@dataclass
class BrowserPage:
    """A page rendered by a real browser."""
    url: str
    html: str
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)


def _same_origin(base: str, url: str) -> bool:
    bp = urlparse(base)
    up = urlparse(url)
    return bp.scheme == up.scheme and bp.netloc == up.netloc


def browser_crawl(
    start_url: str,
    max_pages: int = 20,
    cookies: dict[str, str] | None = None,
) -> list[BrowserPage]:
    """Crawl *start_url* using Playwright's Chromium.

    Returns an empty list if Playwright is not set up.
    """
    assert_localhost(start_url)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning("Playwright not installed; skipping browser crawl.")
        return []

    results: list[BrowserPage] = []
    visited: set[str] = set()
    queue: list[str] = [start_url]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()

            if cookies:
                parsed = urlparse(start_url)
                cookie_list = [
                    {
                        "name": k,
                        "value": v,
                        "domain": parsed.hostname or "localhost",
                        "path": "/",
                    }
                    for k, v in cookies.items()
                ]
                context.add_cookies(cookie_list)

            page = context.new_page()

            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                norm = urlparse(url)._replace(fragment="").geturl()
                if norm in visited:
                    continue
                visited.add(norm)
                assert_localhost(url)

                try:
                    page.goto(url, wait_until="networkidle", timeout=10000)
                except Exception:
                    continue

                html = page.content()

                # Collect links.
                links = []
                for a in page.query_selector_all("a[href]"):
                    href = a.get_attribute("href")
                    if href:
                        full = urljoin(url, href)
                        if _same_origin(start_url, full):
                            links.append(full)
                            if full not in visited:
                                queue.append(full)

                # Collect forms.
                forms = []
                for form in page.query_selector_all("form"):
                    action = form.get_attribute("action") or ""
                    method = (form.get_attribute("method") or "GET").upper()
                    inputs = []
                    for inp in form.query_selector_all("input, textarea, select"):
                        inputs.append({
                            "tag": inp.evaluate("el => el.tagName.toLowerCase()"),
                            "type": inp.get_attribute("type") or "text",
                            "name": inp.get_attribute("name") or "",
                            "value": inp.get_attribute("value") or "",
                        })
                    forms.append({
                        "action": urljoin(url, action),
                        "method": method,
                        "inputs": inputs,
                    })

                # Collect cookies.
                browser_cookies = context.cookies()

                results.append(BrowserPage(
                    url=url,
                    html=html,
                    links=links,
                    forms=forms,
                    cookies=browser_cookies,
                ))

            browser.close()
    except Exception as exc:
        logger.warning("Browser crawl failed: %s", exc)

    return results
