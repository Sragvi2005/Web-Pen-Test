# 🔐 SecScan — Automated Web Security & API Threat Intelligence Scanner

A command-line penetration testing tool that performs automated vulnerability assessments against web applications and APIs, then generates professional HTML and PDF executive reports. Built with a modular Python architecture.

---

## 📋 Table of Contents

- [Features](#-features)
- [Project Architecture](#-project-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Reports](#-output-reports)
- [What Gets Scanned](#-what-gets-scanned)
- [Examples](#-examples)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#-disclaimer)

---

## ✨ Features

- ✅ **SSL/TLS Certificate Inspection** — Detects expired, expiring, or weak protocol versions
- ✅ **HTTP Security Header Audit** — Checks for OWASP-recommended headers
- ✅ **CORS Misconfiguration Detection** — Tests for arbitrary origin reflection and credential leaks
- ✅ **Sensitive Endpoint Discovery** — Concurrent multi-threaded scan for exposed files/paths
- ✅ **Reflected XSS Detection** — Tests for unsanitized input parameter reflection
- ✅ **Executive Reports** — Generates JSON, HTML, and PDF reports with CVSS v3.1 scores and remediation guidance
- ✅ **Modular Architecture** — Clean separation of scanner engines, reporting modules, logger, and CLI entry points

---

## 🏗️ Project Architecture

```text
Web-Pen-Test/
├── secscan/                  # Core Security Scanner Package
│   ├── __init__.py           # Package exports (VulnerabilityScanner)
│   ├── core.py               # Core VulnerabilityScanner class orchestrator
│   ├── logger.py             # Cross-platform terminal logging with Colorama
│   ├── scanners.py           # Vulnerability detection & security audit functions
│   └── report.py             # HTML, PDF (WeasyPrint), and JSON report generators
├── scanner.py                # Backward-compatible CLI entry point
├── main.py                   # Modular CLI entry point
├── README.md                 # Project documentation
└── .gitignore                # Git exclusion rules
```

---

## 🧰 Requirements

| Requirement        | Version     |
|--------------------|-------------|
| Python             | 3.10+       |
| requests           | ≥ 2.28      |
| colorama           | ≥ 0.4       |
| weasyprint         | ≥ 69.0 *(optional, for PDF)* |
| pango *(macOS)*    | via Homebrew *(optional, for PDF)* |

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Sragvi2005/Web-Pen-Test.git
cd Web-Pen-Test
```

### 2. Create and Activate a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# OR
venv\Scripts\activate           # Windows
```

### 3. Install Python Dependencies

```bash
pip install requests colorama weasyprint
```

### 4. Install System Libraries for PDF Generation (macOS only)

WeasyPrint requires native system libraries for PDF rendering:

```bash
brew install pango
```

> **Note:** PDF generation is optional. If system libraries are missing, the scanner will still run and produce JSON and HTML reports.

---

## 📖 Usage

Run using `main.py` or `scanner.py`:

```bash
python main.py -t <TARGET_URL> [OPTIONS]
# OR
python scanner.py -t <TARGET_URL> [OPTIONS]
```

### Arguments

| Flag | Long Form | Description | Default |
|------|-----------|-------------|---------|
| `-t` | `--target` | Target URL to scan (**required**) | — |
| `-w` | `--workers` | Number of concurrent threads | `10` |
| `-o` | `--output-prefix` | Output filename prefix | `security_report` |

---

## 📄 Output Reports

Each scan produces three output files:

| File | Format | Contents |
|------|--------|----------|
| `<prefix>.json` | JSON | Raw structured findings with CVSS scores |
| `<prefix>.html` | HTML | Styled executive report, viewable in any browser |
| `<prefix>.pdf`  | PDF  | Print-ready executive report *(requires WeasyPrint + pango)* |

---

## 🔍 What Gets Scanned

### 1. SSL/TLS Certificate
- Protocol version in use (TLS 1.0/1.1 flagged as vulnerable)
- Certificate expiry — alerts if expired or expiring within 15 days
- Active cipher suite

### 2. HTTP Security Headers
Checks for the presence of these OWASP-recommended headers:

| Header | Risk if Missing |
|--------|----------------|
| `Content-Security-Policy` | XSS / data injection |
| `Strict-Transport-Security` | Downgrade attacks |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing |
| `Referrer-Policy` | Information disclosure |

### 3. CORS Misconfiguration
- Sends a spoofed `Origin: https://evil-attacker-domain.com` header
- Flags if the server reflects the attacker origin
- Critical alert if `Access-Control-Allow-Credentials: true` is also returned

### 4. Sensitive Endpoint Discovery
Concurrently probes common sensitive paths:

```text
/.env           /.git/HEAD       /config.json    /admin
/api/v1/health  /swagger.json    /robots.txt     /server-status
/.aws/credentials                /backup.sql
```

### 5. Reflected XSS
- Sends `<SecTest123>` as a query parameter
- Flags if the raw string is reflected unescaped in the response body

---

## 💡 Examples

**Basic scan:**
```bash
python main.py -t https://example.com
```

**Scan with custom output name and thread count:**
```bash
python main.py -t https://target-app.com -w 20 -o target_audit_report
```

**Scan without PDF (if missing system libraries):**
```bash
python main.py -t https://example.com -o report
```
> PDF will be skipped automatically; JSON and HTML reports will still be generated.

---

## 🛠 Troubleshooting

### `OSError: cannot load library 'libgobject-2.0-0'`
WeasyPrint cannot find the required system library on macOS. Fix:
```bash
brew install pango
```
Then run with:
```bash
DYLD_LIBRARY_PATH=/opt/homebrew/lib python main.py ...
```

### `command not found: python`
On macOS/Linux, Python 3 is often invoked as `python3`:
```bash
python3 main.py ...
```

---

## ⚠️ Disclaimer

> This tool is intended for **authorized security testing only**.
> Only scan systems you own or have **explicit written permission** to test.
> Unauthorized use against systems you do not own is **illegal** and unethical.
> The author assumes no liability for misuse of this tool.
