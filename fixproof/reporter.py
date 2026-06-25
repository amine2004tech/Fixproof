"""
reporter.py — Generate HTML and JSON reports.

Uses Jinja2 for HTML templating. Reports include findings,
evidence, remediation, retest status, and coverage gaps.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, select_autoescape

from fixproof.session_store import ScanSession

# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FixProof Report — {{ session.target_url }}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
.container{max-width:960px;margin:auto}
h1{font-size:1.8rem;margin-bottom:.5rem;color:#38bdf8}
h2{font-size:1.3rem;margin:1.5rem 0 .75rem;color:#7dd3fc}
.meta{color:#94a3b8;margin-bottom:1.5rem;font-size:.9rem}
table{width:100%;border-collapse:collapse;margin-bottom:1.5rem}
th,td{padding:.6rem .8rem;text-align:left;border-bottom:1px solid #1e293b}
th{background:#1e293b;color:#7dd3fc;font-weight:600}
tr:hover{background:#1e293b}
.sev-critical{color:#ef4444;font-weight:700}
.sev-high{color:#f97316;font-weight:700}
.sev-medium{color:#eab308}
.sev-low{color:#22d3ee}
.sev-info{color:#94a3b8}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:600}
.badge-fixed{background:#166534;color:#4ade80}
.badge-vuln{background:#7f1d1d;color:#fca5a5}
.badge-na{background:#334155;color:#94a3b8}
.badge-notreproducible{background:#475569;color:#cbd5e1}
.evidence{background:#1e293b;padding:.5rem;border-radius:4px;font-size:.85rem;margin-top:.3rem;white-space:pre-wrap;word-break:break-all}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1.5rem}
.summary-card{background:#1e293b;padding:1rem;border-radius:8px;text-align:center}
.summary-card .num{font-size:2rem;font-weight:700;color:#38bdf8}
.summary-card .label{font-size:.8rem;color:#94a3b8;margin-top:.25rem}
.gap{background:#1e293b;padding:.5rem .8rem;border-radius:4px;margin-bottom:.3rem}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ FixProof Report</h1>
<p class="meta">Target: {{ session.target_url }} · Scanned: {{ session.scan_time }}</p>

<div class="summary-grid">
  <div class="summary-card">
    <div class="num">{{ total }}</div>
    <div class="label">Total Checks</div>
  </div>
  <div class="summary-card">
    <div class="num">{{ vuln_count }}</div>
    <div class="label">Vulnerabilities</div>
  </div>
  <div class="summary-card">
    <div class="num">{{ fixed_count }}</div>
    <div class="label">Fixed</div>
  </div>
  <div class="summary-card">
    <div class="num">{{ still_vuln }}</div>
    <div class="label">Still Vulnerable</div>
  </div>
</div>

<h2>Attack Findings</h2>
{% if active_attacks %}
<table>
<thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Description</th></tr></thead>
<tbody>
{% for tc in active_attacks %}
<tr>
  <td>{{ tc.check_type }}</td>
  <td class="sev-{{ tc.severity }}">{{ tc.severity | upper }}</td>
  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ tc.url }}</td>
  <td>{{ tc.description }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% for tc in active_attacks %}
<details style="margin-bottom:.75rem">
  <summary style="cursor:pointer;color:#7dd3fc">{{ tc.check_type | upper }} — {{ tc.description }}</summary>
  <div class="evidence">{{ tc.evidence }}</div>
  <p style="margin-top:.4rem;font-size:.85rem"><strong>Remediation:</strong> {{ tc.remediation }}</p>
</details>
{% endfor %}
{% else %}
<p class="meta">No active attack findings.</p>
{% endif %}

<h2>Security Observations</h2>
{% if observations %}
<table>
<thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Description</th></tr></thead>
<tbody>
{% for tc in observations %}
<tr>
  <td>{{ tc.check_type }}</td>
  <td class="sev-{{ tc.severity }}">{{ tc.severity | upper }}</td>
  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ tc.url }}</td>
  <td>{{ tc.description }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% for tc in observations %}
<details style="margin-bottom:.75rem">
  <summary style="cursor:pointer;color:#7dd3fc">{{ tc.check_type | upper }} — {{ tc.description }}</summary>
  <div class="evidence">{{ tc.evidence }}</div>
  {% if tc.remediation %}
  <p style="margin-top:.4rem;font-size:.85rem"><strong>Remediation:</strong> {{ tc.remediation }}</p>
  {% endif %}
</details>
{% endfor %}
{% else %}
<p class="meta">No security observations.</p>
{% endif %}

<h2>Retest Results</h2>
{% if retested_cases %}
<table>
<thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Description</th><th>Retest</th></tr></thead>
<tbody>
{% for tc in retested_cases %}
<tr>
  <td>{{ tc.check_type }}</td>
  <td class="sev-{{ tc.severity }}">{{ tc.severity | upper }}</td>
  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ tc.url }}</td>
  <td>{{ tc.description }}</td>
  <td>
    {% if tc.retest_result == "FIXED" %}
      <span class="badge badge-fixed">✓ Fixed</span>
    {% elif tc.retest_result == "STILL_VULNERABLE" %}
      <span class="badge badge-vuln">✗ Vulnerable</span>
    {% elif tc.retest_result == "NOT_REPRODUCIBLE" %}
      <span class="badge badge-notreproducible">? Not Reproducible</span>
    {% elif tc.retest_result == "MANUAL_REVIEW" %}
      <span class="badge badge-na">Manual Review</span>
    {% else %}
      <span class="badge badge-na">{{ tc.retest_result }}</span>
    {% endif %}
  </td>
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p class="meta">No retest data available.</p>
{% endif %}

{% if session.coverage_gaps %}
<h2>Coverage Gaps</h2>
{% for gap in session.coverage_gaps %}
<div class="gap">⚠ {{ gap }}</div>
{% endfor %}
{% endif %}

<p class="meta" style="margin-top:2rem">Generated by FixProof Local v1</p>
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    session: ScanSession,
    output_dir: str = "fixproof-report",
) -> dict[str, Path]:
    """Generate HTML and JSON reports. Returns paths to generated files."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    total = len(session.test_cases)
    vuln_count = sum(1 for t in session.test_cases if t.vulnerable)
    fixed_count = sum(1 for t in session.test_cases if t.retest_result == "FIXED")
    still_vuln = sum(1 for t in session.test_cases if t.retest_result == "STILL_VULNERABLE")

    active_attacks = [t for t in session.test_cases if t.category == "attack" and t.retest_result not in ("FIXED", "NOT_REPRODUCIBLE")]
    observations = [t for t in session.test_cases if t.category == "observation"]
    retested_cases = [t for t in session.test_cases if t.retest_result is not None]

    # HTML
    env = Environment(autoescape=select_autoescape(default_for_string=True, default=True))
    template = env.from_string(_HTML_TEMPLATE)
    html = template.render(
        session=session,
        total=total,
        vuln_count=vuln_count,
        fixed_count=fixed_count,
        still_vuln=still_vuln,
        active_attacks=active_attacks,
        observations=observations,
        retested_cases=retested_cases,
    )
    html_path = out / "report.html"
    html_path.write_text(html, encoding="utf-8")

    # JSON
    json_data = session.model_dump()
    json_data["summary"] = {
        "total_checks": total,
        "vulnerabilities": vuln_count,
        "fixed": fixed_count,
        "still_vulnerable": still_vuln,
    }
    json_path = out / "report.json"
    json_path.write_text(
        json.dumps(json_data, indent=2, default=str),
        encoding="utf-8",
    )

    return {"html": html_path, "json": json_path}
