"""
discover.py — Discover HTTP services running on localhost.

Scans a range of TCP ports on 127.0.0.1 looking for HTTP listeners.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

import requests
from rich.progress import Progress, SpinnerColumn, TextColumn


@dataclass
class LocalService:
    """Represents a discovered local HTTP service."""
    port: int
    url: str
    title: str = ""
    server: str = ""


def _check_port(port: int, timeout: float = 0.3) -> bool:
    """Quick TCP connect check."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _probe_http(port: int, timeout: float = 2.0) -> LocalService | None:
    """Try an HTTP GET on the port and extract basic info."""
    for scheme in ("http",):
        url = f"{scheme}://127.0.0.1:{port}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            title = ""
            if "<title>" in resp.text.lower():
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "lxml")
                tag = soup.find("title")
                if tag:
                    title = tag.get_text(strip=True)
            server = resp.headers.get("Server", "")
            return LocalService(port=port, url=url, title=title, server=server)
        except (requests.ConnectionError, requests.Timeout, requests.RequestException):
            continue
    return None


def discover_services(
    port_start: int = 1024,
    port_end: int = 65535,
    common_only: bool = True,
) -> list[LocalService]:
    """Discover HTTP services on localhost.

    If *common_only* is True (default), only scans common development ports.
    """
    if common_only:
        ports = [
            80, 443, 3000, 3001, 4200, 5000, 5173, 5500, 7000,
            8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
        ]
    else:
        ports = list(range(port_start, port_end + 1))

    services: list[LocalService] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning localhost ports…", total=len(ports))

        for port in ports:
            progress.update(task, description=f"Checking port {port}…")
            if _check_port(port):
                svc = _probe_http(port)
                if svc:
                    services.append(svc)
            progress.advance(task)

    return services
