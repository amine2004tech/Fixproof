# FixProof Local v1 🛡️

**A modern, localhost-only offensive validation and retest toolkit for developers.**

FixProof is designed to help developers identify, validate, and definitively fix security vulnerabilities in their local web applications. While capable of scanning any local HTTP server, **FixProof's preflight and analysis engines are specifically optimized for Node.js and Express.js applications** (e.g., automatically analyzing `package.json`, `.env` files, and `NODE_ENV` settings).

Unlike traditional DAST tools that blindly spray payloads, FixProof meticulously maps the attack surface, intelligently detects vulnerabilities with context-aware analysis, and allows you to **replay the exact same payloads** after you've written a fix to prove the issue is resolved.

---

## 🚫 Safety First: The Localhost Guard

FixProof is strictly for **local development environments**. It enforces rigorous safety checks before a single packet is sent.
**FixProof will NEVER:**
- Scan public domains (e.g., `google.com`).
- Scan LAN IPs (e.g., `192.168.x.x`, `10.x.x.x`, `172.16.x.x`).
- Execute destructive operations (no DB dumping, no file reading, no login brute-forcing).
- Run third-party tools (no sqlmap, nmap, ZAP, or nuclei).

It explicitly allows only `localhost`, `127.0.0.1`, and `::1`.

---

## 🏗️ Architecture & Pipeline

FixProof operates on a deterministic pipeline to ensure precision and lack of false positives:

1. **Preflight**: Analyzes the application context (like `.env` files or framework signatures) to warn you if you are scanning a development build that might yield false positive security warnings.
2. **Discover**: Scans local ports to find running HTTP services.
3. **Crawl & Map**: Uses a headless Chromium browser (Playwright) to navigate the app, execute JavaScript, and discover dynamic routes, forms, inputs, cookies, and API endpoints.
4. **Passive Scan**: Analyzes headers, cookies, and CSRF token presence without sending malicious payloads. These are categorized as **Security Observations**.
5. **Active Scan**: Intelligently probes inputs with harmless but precise markers to identify XSS and SQL injection. 
6. **Stateful Retest**: Saves the exact test cases and payloads locally (`.fixproof/session.json`). After you patch the vulnerability in your code, the `retest` engine replays the exact payload to verify if it is `FIXED`, `STILL_VULNERABLE`, or `NOT_REPRODUCIBLE`.
7. **Report**: Generates beautiful, human-readable HTML reports (`fixproof-report/report.html`) strictly separating active **Attack Findings** from passive **Security Observations**.

### 🧠 Smart XSS Engine
The XSS detection engine uses a **3-State Logic Model**:
- **Observation (`INFO`)**: The payload was reflected, but it was safely HTML-encoded or safely contained within an inert attribute.
- **Dangerous Reflection (`HIGH`)**: The raw payload escaped safely and hit a dangerous executable context (like an HTML body or inline script).
- **Confirmed Execution (`HIGH`)**: The dangerous reflection was verified by spinning up an invisible Playwright browser and successfully capturing a JavaScript execution pop-up.

---

## 💻 Technologies Used

- **Python 3.11+**: The core language.
- **Typer**: For building a clean, intuitive CLI interface.
- **Rich**: For gorgeous terminal output, colors, and structured tables.
- **Playwright**: For modern SPA/JavaScript-heavy application crawling and XSS execution confirmation.
- **Requests**: For fast, underlying HTTP probes and retest replays.
- **BeautifulSoup4 / lxml**: For deep DOM parsing and context-aware XSS reflection analysis.
- **Pydantic**: For rigid data validation and test case modeling.
- **Jinja2**: For rendering the beautiful HTML vulnerability reports.

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/amine2004tech/Fixproof.git
cd Fixproof
pip install -e ".[dev]"
playwright install chromium
```

### 2. Start the Vulnerable Example App
FixProof comes with a dummy vulnerable application so you can test its capabilities safely.

```bash
cd examples/vulnerable_express_app
npm install
npm start
# The vulnerable app is now running at http://127.0.0.1:3000
```

### 3. Discover Local Services
Find what's running on your machine:
```bash
fixproof discover
```

### 4. Run Preflight Checks
Warns if the target app is running in development mode (which often disables standard security protections):
```bash
fixproof preflight --url http://localhost:3000 --app-root ../vulnerable_express_app
```

### 5. Active Scan
Run the full suite (Passive + Active) against the target.
```bash
fixproof scan --url http://localhost:3000 --active
```

*(Optional) You can also supply session cookies to scan authenticated areas:*
```bash
fixproof scan --url http://localhost:3000 --active --cookie "session=abc123"
```

### 6. Patch & Retest
Once you've run the scan, FixProof saves your session. Leave the app running, go to the `examples/vulnerable_express_app/` source code, and fix one of the vulnerabilities (e.g., escape the output).

Then, run the retest engine to prove it's fixed:
```bash
fixproof retest
```

### 7. Generate Reports
Generate the final HTML and JSON reports:
```bash
fixproof report --open
```

---

## 🛠️ CLI Commands Reference

| Command | Description |
|---------|-------------|
| `fixproof discover` | Find HTTP services running on localhost |
| `fixproof preflight --url <URL>` | Check if target is running in insecure dev mode |
| `fixproof scan --url <URL>` | Passive scan (missing headers, insecure cookies, CSRF) |
| `fixproof scan --url <URL> --active` | Active scan (injects XSS and SQLi probes) |
| `fixproof scan --url <URL> --active --cookie "k=v"` | Active scan with an authenticated session cookie |
| `fixproof retest` | Replays saved test cases to verify if vulnerabilities are patched |
| `fixproof report --open` | Generates safe, escaped HTML + JSON reports and opens in browser |

---

## 🛡️ Vulnerabilities Covered

- **Cross-Site Scripting (XSS)**: Context-aware reflection analysis (HTML body, attributes, scripts, comments, inputs). Detects properly encoded data to minimize false positives.
- **SQL Injection (SQLi)**: Detects Error-based, Boolean-based, and Time-delay injection flaws.
- **Cross-Site Request Forgery (CSRF)**: Flags state-changing POST forms lacking protective tokens.
- **Security Headers**: Identifies missing or misconfigured headers (CSP, HSTS, X-Frame-Options, etc.).
- **Insecure Cookies**: Checks for missing `HttpOnly`, `Secure`, and `SameSite` flags.

---

## 📄 License
MIT License
