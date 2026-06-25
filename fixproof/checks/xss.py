"""
checks/xss.py — Reflected XSS detection.

Uses controlled, unique markers to detect when user input is reflected
back in the response body. Context-aware: checks whether the marker
appears inside HTML tags, attributes, script blocks, etc.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any
from urllib.parse import urljoin, urlencode, urlparse

import requests

from fixproof.guard import assert_localhost
from fixproof.session_store import TestCase
from fixproof.surface_mapper import AttackSurface
from fixproof.form_builder import build_submissions

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_MARKER = "FPXSS"

_XSS_PAYLOADS = [
    f'{_MARKER}<script>alert(1)</script>',
    f'{_MARKER}"><img src=x onerror=alert(1)>',
    f'{_MARKER}\'><svg onload=alert(1)>',
    f'{_MARKER}" onfocus=alert(1) autofocus="',
    f'{_MARKER}"><iframe src="javascript:alert(1)">',
    f"{_MARKER}{{{{7*7}}}}",  # Template injection probe
]


# ---------------------------------------------------------------------------
# Context analysis
# ---------------------------------------------------------------------------

def _analyse_context(html: str, marker: str, payload: str) -> list[str]:
    """Return a list of contexts where *marker* appears in *html*.
    
    Contexts: html_body, html_attribute, script_context, json_context,
              input_value, escaped_html.
    """
    contexts = set()
    lower_html = html.lower()
    lower_marker = marker.lower()
    
    if lower_marker not in lower_html:
        return []

    # If the exact payload is not in the HTML, it was likely escaped or transformed
    if payload not in html:
        contexts.add("escaped_html")
        
    idx = 0
    while True:
        pos = lower_html.find(lower_marker, idx)
        if pos == -1:
            break
            
        before = lower_html[:pos]
        
        # 1. JSON context (crude check if inside { } or [ ])
        last_brace_open = max(before.rfind("{"), before.rfind("["))
        last_brace_close = max(before.rfind("}"), before.rfind("]"))
        if last_brace_open > last_brace_close:
            contexts.add("json_context")
            
        # 2. HTML context
        last_tag_open = before.rfind("<")
        last_tag_close = before.rfind(">")
        
        if last_tag_open > last_tag_close:
            tag_content = before[last_tag_open:]
            if tag_content.startswith("<!--"):
                contexts.add("comment")
            elif tag_content.startswith("<input") and "value=" in tag_content:
                contexts.add("input_value")
            else:
                contexts.add("html_attribute")
        else:
            if "<script" in before and "</script>" not in before[before.rfind("<script"):]:
                contexts.add("script_context")
            elif "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
                contexts.add("comment")
            else:
                contexts.add("html_body")
                
        idx = pos + 1
        
    return list(contexts)


# ---------------------------------------------------------------------------
# Playwright verification
# ---------------------------------------------------------------------------

def _confirm_with_playwright(url: str, method: str, data: dict, timeout: float) -> bool:
    """Use Playwright to confirm if the payload actually executes JS."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
        
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            
            alert_fired = [False]
            def handle_dialog(dialog):
                if dialog.message == "1" or _MARKER in dialog.message:
                    alert_fired[0] = True
                dialog.accept()
                
            page.on("dialog", handle_dialog)
            
            pw_timeout = int(timeout * 1000)
            if method == "GET":
                qs = urlencode(data)
                target = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"
                page.goto(target, wait_until="networkidle", timeout=pw_timeout)
            else:
                html = f'<form id="f" method="POST" action="{url}">'
                for k, v in data.items():
                    html += f'<input type="hidden" name="{k}" value="{v.replace('"', '&quot;')}">'
                html += '</form><script>document.getElementById("f").submit();</script>'
                page.set_content(html)
                page.wait_for_load_state("networkidle", timeout=pw_timeout)
                
            browser.close()
            return alert_fired[0]
    except Exception:
        return False


def _verify_stability(session: requests.Session, url: str, method: str, data: dict, payload: str, timeout: float) -> bool:
    """Repeat the test 2 times to ensure the reflection is stable."""
    for _ in range(2):
        time.sleep(0.5)
        try:
            if method == "GET":
                resp = session.get(url, params=data, timeout=timeout)
            else:
                resp = session.post(url, data=data, timeout=timeout)
            if _MARKER not in resp.text:
                return False
        except requests.RequestException:
            return False
    return True


def evaluate_xss_response(resp_text: str, payload: str) -> dict:
    """Evaluate response text to determine XSS classification and state."""
    contexts = _analyse_context(resp_text, _MARKER, payload)
    
    is_escaped = "escaped_html" in contexts
    is_input_only = "input_value" in contexts and not any(c in ("html_body", "script_context", "html_attribute") for c in contexts if c != "input_value")
    
    if is_escaped:
        state = "reflected_input_observed"
        severity = "info"
        desc = "Input reflected but encoded"
        category = "observation"
        retestable = False
        check_type = "xss_observation"
    elif is_input_only:
        state = "reflected_input_observed"
        severity = "info"
        desc = "Input reflection observed; manual review recommended."
        category = "observation"
        retestable = False
        check_type = "xss_observation"
    else:
        state = "dangerous_unescaped_reflection"
        severity = "high"
        desc = "Potential reflected XSS; unescaped HTML-sensitive marker detected."
        category = "attack"
        retestable = True
        check_type = "xss"

    return {
        "state": state,
        "severity": severity,
        "desc": desc,
        "category": category,
        "retestable": retestable,
        "check_type": check_type,
        "contexts": contexts,
    }

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_xss(
    surface: AttackSurface,
    base_url: str,
    timeout: float = 5.0,
    cookies: dict[str, str] | None = None,
) -> list[TestCase]:
    """Run XSS probes against all surfaces."""
    assert_localhost(base_url)

    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    results: list[TestCase] = []
    findings_dict: dict[tuple, dict] = {}

    def _process_finding(url: str, method: str, data: dict, payload: str, field_name: str, resp_text: str, source: str):
        eval_result = evaluate_xss_response(resp_text, payload)
        state = eval_result["state"]
        severity = eval_result["severity"]
        desc = eval_result["desc"]
        category = eval_result["category"]
        retestable = eval_result["retestable"]
        check_type = eval_result["check_type"]
        contexts = eval_result["contexts"]

        if state == "dangerous_unescaped_reflection":
            # 1. Verify stability
            if not _verify_stability(session, url, method, data, payload, timeout):
                return  # Skip unstable reflection entirely

            # 2. Try Playwright confirmation
            if _confirm_with_playwright(url, method, data, timeout):
                state = "confirmed_executable_xss"
                severity = "high"
                desc = "Confirmed reflected XSS."

        # Deduplication key
        path = urlparse(url).path
        key = (method, path, field_name)
        
        # Upgrade logic
        if key in findings_dict:
            existing = findings_dict[key]
            # Add source if new
            if source not in existing["sources"]:
                existing["sources"].append(source)
            # Upgrade observation to attack
            if state in ("dangerous_unescaped_reflection", "confirmed_executable_xss") and existing["category"] == "observation":
                existing["state"] = state
                existing["severity"] = severity
                existing["desc"] = desc
                existing["category"] = category
                existing["retestable"] = retestable
                existing["payload"] = payload
                existing["data"] = data
                existing["contexts"] = contexts
            # Upgrade unconfirmed attack to confirmed
            elif state == "confirmed_executable_xss" and existing["state"] != "confirmed_executable_xss":
                existing["state"] = state
                existing["desc"] = desc
        else:
            findings_dict[key] = {
                "url": url,
                "method": method,
                "field_name": field_name,
                "payload": payload,
                "data": data,
                "state": state,
                "severity": severity,
                "desc": desc,
                "category": category,
                "retestable": retestable,
                "check_type": check_type,
                "contexts": contexts,
                "sources": [source],
            }

    # --- Test GET parameters ---
    for param_surface in surface.parameters:
        url = param_surface.url
        assert_localhost(url)
        for param_name in param_surface.params:
            for payload in _XSS_PAYLOADS:
                data = {param_name: payload}
                try:
                    resp = session.get(url, params=data, timeout=timeout)
                    if _MARKER in resp.text:
                        _process_finding(url, "GET", data, payload, param_name, resp.text, "url_param")
                        break  # One proof is enough per param.
                except requests.RequestException:
                    continue

    # --- Test POST forms ---
    for form in surface.forms:
        submissions = build_submissions(form, _XSS_PAYLOADS)
        for sub in submissions:
            try:
                action_url = urljoin(base_url, sub.action)
                assert_localhost(action_url)
                if sub.method == "POST":
                    resp = session.post(action_url, data=sub.data, timeout=timeout)
                else:
                    resp = session.get(action_url, params=sub.data, timeout=timeout)

                if _MARKER in resp.text:
                    _process_finding(action_url, sub.method, sub.data, sub.payload, sub.mutated_field, resp.text, "html_form")
                    break  # One proof per field.
            except (requests.RequestException, ValueError):
                continue

    for f in findings_dict.values():
        results.append(TestCase(
            id=str(uuid.uuid4()),
            check_type=f["check_type"],
            category=f["category"],
            url=f["url"],
            method=f["method"],
            payload={"field": f["field_name"], "value": f["payload"], "data": f["data"], "state": f["state"]},
            evidence=(
                f"State: {f['state']}. "
                f"Contexts: {', '.join(f['contexts'])}. "
                f"Field: {f['field_name']!r}. "
                f"Payload: {f['payload']!r}"
            ),
            vulnerable=True,
            severity=f["severity"],
            description=f["desc"],
            remediation=(
                "HTML-encode all user input before reflecting it in the page. "
                "Use a Content-Security-Policy that blocks inline scripts."
            ),
            retestable=f["retestable"],
            sources=f["sources"],
        ))

    return results
