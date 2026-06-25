"""
preflight.py — Preflight checks for target application environments.

Analyzes the target URL and optional application root directory to determine
if the app is running in a development mode (e.g., NODE_ENV=development).
"""

from __future__ import annotations

import json
from pathlib import Path

import requests

from fixproof.guard import assert_localhost


def run_preflight_checks(url: str, app_root: Path | None = None) -> list[str]:
    """Run preflight checks against the target.

    Returns a list of warning messages. If the list is empty, no obvious
    development mode indicators were found.
    """
    assert_localhost(url)
    warnings: list[str] = []

    # 1. Check HTTP response headers for development mode indicators
    try:
        resp = requests.get(url, timeout=3)
        server_header = resp.headers.get("Server", "").lower()
        x_powered_by = resp.headers.get("X-Powered-By", "").lower()

        if "development" in server_header or "development" in x_powered_by:
            warnings.append("HTTP Headers indicate the server is running in development mode.")
        if "werkzeug" in server_header:
            warnings.append("Werkzeug development server detected. Do not use this in production.")
            
    except requests.RequestException:
        warnings.append(f"Could not connect to {url} during preflight check.")

    # 2. Check local application files if app_root is provided
    if app_root:
        if not app_root.exists() or not app_root.is_dir():
            warnings.append(f"App root directory {app_root} not found or is not a directory.")
        else:
            warnings.extend(_check_node_env(app_root))

    return warnings


def _check_node_env(app_root: Path) -> list[str]:
    """Check a Node.js project for development mode indicators."""
    warnings: list[str] = []
    
    # Check package.json
    package_json_path = app_root / "package.json"
    if package_json_path.exists():
        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            # Heuristic: If there are devDependencies and we can't confirm production, warn.
            if "devDependencies" in data:
                warnings.append(
                    "Found 'devDependencies' in package.json. Ensure you run the app "
                    "with NODE_ENV=production before a serious security scan, as dev "
                    "mode often includes intentionally insecure debug endpoints or "
                    "weaker security configurations."
                )
        except (json.JSONDecodeError, OSError):
            pass

    return warnings
