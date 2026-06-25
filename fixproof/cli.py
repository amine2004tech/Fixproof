"""
cli.py — Typer CLI for FixProof Local v1.

Commands:
  fixproof discover           — Find HTTP services on localhost.
  fixproof scan --url URL     — Passive scan (headers, cookies, CSRF).
  fixproof scan --url URL --active  — Active scan (+ XSS, SQLi).
  fixproof scan --url URL --active --cookie "session=..."
  fixproof retest             — Replay saved test cases.
  fixproof report             — Generate HTML + JSON reports.
"""

from __future__ import annotations

from typing import Optional
from pathlib import Path
import webbrowser

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from fixproof import __version__
from fixproof.guard import validate_url
from fixproof.session_store import (
    ScanSession, save_session, load_session, session_exists,
)

app = typer.Typer(
    name="fixproof",
    help="FixProof Local v1 — localhost-only vulnerability scanner & retest tool.",
    add_completion=False,
)
console = Console()


# -----------------------------------------------------------------------
# preflight
# -----------------------------------------------------------------------

@app.command()
def preflight(
    url: str = typer.Option(..., "--url", help="Target URL (must be localhost)."),
    app_root: Optional[Path] = typer.Option(None, "--app-root", help="Path to local application root."),
):
    """Check if the target application is running in an insecure development mode."""
    guard = validate_url(url)
    if not guard.allowed:
        rprint(f"[bold red]BLOCKED:[/] {guard.reason}")
        raise typer.Exit(code=1)
        
    rprint(f"[bold cyan]✈️ Running preflight checks against {url}…[/]")
    from fixproof.preflight import run_preflight_checks
    
    warnings = run_preflight_checks(url, app_root)
    if warnings:
        for w in warnings:
            rprint(f"[bold yellow]⚠ WARNING:[/] {w}")
        rprint("\n[yellow]It is recommended to run the app in production mode before a serious scan.[/]")
    else:
        rprint("[bold green]✅ Preflight passed. No obvious development mode indicators found.[/]")


# -----------------------------------------------------------------------
# discover
# -----------------------------------------------------------------------

@app.command()
def discover():
    """Discover HTTP services running on localhost."""
    from fixproof.discover import discover_services

    rprint("[bold cyan]🔍 Discovering localhost services…[/]")
    services = discover_services()

    if not services:
        rprint("[yellow]No HTTP services found on common ports.[/]")
        raise typer.Exit()

    table = Table(title="Localhost Services")
    table.add_column("Port", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Title")
    table.add_column("Server")

    for svc in services:
        table.add_row(str(svc.port), svc.url, svc.title, svc.server)

    console.print(table)


# -----------------------------------------------------------------------
# scan
# -----------------------------------------------------------------------

@app.command()
def scan(
    url: str = typer.Option(..., "--url", help="Target URL (must be localhost)."),
    active: bool = typer.Option(False, "--active", help="Enable active testing (XSS, SQLi)."),
    cookie: Optional[str] = typer.Option(None, "--cookie", help='Cookies as "k=v; k2=v2".'),
    app_root: Optional[Path] = typer.Option(None, "--app-root", help="Path to local application root."),
):
    """Scan a localhost application for vulnerabilities."""
    guard = validate_url(url)
    if not guard.allowed:
        rprint(f"[bold red]BLOCKED:[/] {guard.reason}")
        raise typer.Exit(code=1)

    cookies = _parse_cookies(cookie)

    rprint(f"[bold cyan]🎯 Target:[/] {url}")
    rprint(f"[bold cyan]   Mode:[/] {'Active (XSS + SQLi)' if active else 'Passive'}")
    
    from fixproof.preflight import run_preflight_checks
    warnings = run_preflight_checks(url, app_root)
    if warnings:
        for w in warnings:
            rprint(f"[bold yellow]⚠ Preflight Warning:[/] {w}")

    # --- Crawl ---
    rprint("\n[bold]Phase 1: Crawling…[/]")
    from fixproof.crawler import crawl
    crawl_results = crawl(url, cookies=cookies)
    rprint(f"  Crawled [green]{len(crawl_results)}[/] pages.")

    pages = [{"url": r.url, "html": r.html, "links": r.links} for r in crawl_results]

    # --- Route discovery ---
    rprint("[bold]Phase 2: Route discovery…[/]")
    from fixproof.route_discovery import discover_routes
    routes = discover_routes(url, cookies=cookies)
    rprint(f"  Found [green]{len(routes)}[/] routes.")

    # --- Surface mapping ---
    rprint("[bold]Phase 3: Mapping attack surface…[/]")
    from fixproof.surface_mapper import map_surface
    resp_cookies = {}
    for cr in crawl_results:
        pass  # Cookies captured from session are enough.
    surface = map_surface(pages, resp_cookies)
    rprint(f"  Forms: [green]{len(surface.forms)}[/]")
    rprint(f"  GET params: [green]{len(surface.parameters)}[/]")
    rprint(f"  API hints: [green]{len(surface.api_hints)}[/]")

    # --- Passive checks ---
    rprint("\n[bold]Phase 4: Passive checks…[/]")
    all_cases = []

    from fixproof.checks.headers import check_headers
    hdr_cases = check_headers(url, cookies=cookies)
    all_cases.extend(hdr_cases)
    rprint(f"  Headers: [yellow]{sum(1 for c in hdr_cases if c.vulnerable)}[/] issues")

    from fixproof.checks.cookies import check_cookies
    cook_cases = check_cookies(url, extra_cookies=cookies)
    all_cases.extend(cook_cases)
    rprint(f"  Cookies: [yellow]{sum(1 for c in cook_cases if c.vulnerable)}[/] issues")

    from fixproof.checks.csrf import check_csrf
    csrf_cases = check_csrf(surface)
    all_cases.extend(csrf_cases)
    rprint(f"  CSRF:    [yellow]{sum(1 for c in csrf_cases if c.vulnerable)}[/] issues")

    # --- Active checks ---
    if active:
        rprint("\n[bold]Phase 5: Active checks…[/]")

        from fixproof.checks.xss import check_xss
        xss_cases = check_xss(surface, url, cookies=cookies)
        all_cases.extend(xss_cases)
        rprint(f"  XSS:  [red]{sum(1 for c in xss_cases if c.vulnerable)}[/] findings")

        from fixproof.checks.sqli import check_sqli
        sqli_cases = check_sqli(surface, url, cookies=cookies)
        all_cases.extend(sqli_cases)
        rprint(f"  SQLi: [red]{sum(1 for c in sqli_cases if c.vulnerable)}[/] findings")

    # --- Coverage gaps ---
    gaps = []
    if not surface.forms:
        gaps.append("No forms discovered — form-based tests skipped.")
    if not surface.parameters:
        gaps.append("No GET parameters discovered — parameter-based tests skipped.")
    if not active:
        gaps.append("Active testing was not enabled — XSS and SQLi tests skipped.")

    # --- Save session ---
    session = ScanSession(
        target_url=url,
        crawled_urls=[r.url for r in crawl_results],
        surfaces=[s.model_dump() for s in [surface]],
        test_cases=all_cases,
        coverage_gaps=gaps,
    )
    path = save_session(session)
    attacks = sum(1 for c in all_cases if c.category == "attack")
    observations = sum(1 for c in all_cases if c.category == "observation")
    retestable = sum(1 for c in all_cases if c.retestable)
    rprint(f"\n[bold green]✅ Scan complete.[/]")
    rprint(f"  Attack findings: {attacks}")
    rprint(f"  Observations: {observations}")
    rprint(f"  Saved retestable cases: {retestable}")
    rprint(f"   Session saved to [cyan]{path}[/]")


# -----------------------------------------------------------------------
# retest
# -----------------------------------------------------------------------

@app.command()
def retest():
    """Retest previously found vulnerabilities after manual fixes."""
    if not session_exists():
        rprint("[bold red]No session found.[/] Run 'fixproof scan' first.")
        raise typer.Exit(code=1)

    rprint("[bold cyan]🔄 Retesting saved test cases…[/]")
    from fixproof.retest import retest_session
    session = retest_session()

    fixed = sum(1 for t in session.test_cases if t.retest_result == "FIXED")
    still = sum(1 for t in session.test_cases if t.retest_result == "STILL_VULNERABLE")

    table = Table(title="Retest Results")
    table.add_column("Type", style="cyan")
    table.add_column("URL")
    table.add_column("Result")
    for tc in session.test_cases:
        if tc.retest_result is None:
            continue
        if tc.retest_result == "FIXED":
            result = "[green]✓ Fixed[/]"
        elif tc.retest_result == "STILL_VULNERABLE":
            result = "[red]✗ Still vulnerable[/]"
        elif tc.retest_result == "NOT_REPRODUCIBLE":
            result = "[yellow]? Not Reproducible[/]"
        elif tc.retest_result == "MANUAL_REVIEW":
            result = "[magenta]Manual Review[/]"
        else:
            result = f"[yellow]{tc.retest_result}[/]"
        table.add_row(tc.check_type, tc.url, result)

    console.print(table)
    rprint(f"\n[green]{fixed}[/] fixed · [red]{still}[/] still vulnerable")


# -----------------------------------------------------------------------
# report
# -----------------------------------------------------------------------

@app.command()
def report(
    open_report: bool = typer.Option(False, "--open", help="Open the HTML report in the default browser.")
):
    """Generate HTML and JSON reports from the last scan."""
    if not session_exists():
        rprint("[bold red]No session found.[/] Run 'fixproof scan' first.")
        raise typer.Exit(code=1)

    session = load_session()
    from fixproof.reporter import generate_report
    paths = generate_report(session)

    rprint("[bold green]📄 Reports generated:[/]")
    html_path = paths['html'].absolute()
    rprint(f"  HTML: [cyan]{html_path}[/]")
    rprint(f"  JSON: [cyan]{paths['json'].absolute()}[/]")
    
    if open_report:
        webbrowser.open(html_path.as_uri())


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _parse_cookies(raw: str | None) -> dict[str, str] | None:
    if not raw:
        return None
    cookies = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


if __name__ == "__main__":
    app()
