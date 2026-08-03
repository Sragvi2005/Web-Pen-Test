# SecScan — Automated Security & Web Penetration Testing Engine

SecScan is a high-precision, automated penetration testing engine and web interface designed to audit web applications and APIs. It analyzes attack surfaces across 5 key vulnerability vectors with CVSS v3.1 scoring, real-time terminal output, and actionable remediation guidance.

![SecScan Engine](https://img.shields.io/badge/SecScan-v3.5_Enterprise-blue?style=flat-square)
![Docker Supported](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)
![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)

---

## ⚡ Quick Start with Docker (Recommended)

Run SecScan instantly in a containerized environment with zero local setup:

```bash
# 1. Clone the repository
git clone https://github.com/Sragvi2005/Web-Pen-Test.git
cd Web-Pen-Test

# 2. Build and launch the container
docker compose up -d --build
```

👉 **Access the Web UI at:** `http://localhost:5000`

### Useful Docker Commands
```bash
docker compose logs -f    # View real-time container logs
docker compose ps         # Check container status
docker compose down       # Stop and remove container
```

---

## 🐍 Local Python Setup (Without Docker)

If you prefer running SecScan natively on your machine:

```bash
# 1. Clone the repository
git clone https://github.com/Sragvi2005/Web-Pen-Test.git
cd Web-Pen-Test

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the Web & API Server
python server.py
```

👉 **Access the Web UI at:** `http://localhost:5000`

---

## 🎯 Attack Surface Coverage

SecScan audits five core attack vectors sequentially or concurrently:

| Module | What It Tests | Risk / Impact |
| :--- | :--- | :--- |
| **SSL/TLS Inspection** | Protocol versions (TLS 1.0/1.1/1.2/1.3), cipher suites, and certificate expiration. | Prevents MITM, downgrade attacks, and expired cert warnings. |
| **HTTP Security Headers** | Checks for OWASP headers: `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. | Mitigates XSS, Clickjacking, MIME-sniffing, and data leakage. |
| **CORS Policy Probe** | Origin reflection & `Access-Control-Allow-Credentials` flag auditing. | Prevents unauthorized cross-origin data and credential theft. |
| **Endpoint Discovery** | Concurrent multithreaded directory dictionary attack (`/.env`, `/.git/HEAD`, `/swagger.json`, etc.). | Identifies sensitive file disclosures and secret key exposures. |
| **Reflected XSS Probe** | Safely tests input parameters for unsanitized reflection in HTTP responses. | Detects potential script injection vectors. |

---

## 🖥️ Command Line Interface (CLI)

You can also run scans directly from your terminal using `main.py`:

```bash
# Basic scan against a target
python main.py -t https://target.example.com

# Multithreaded scan with custom output file prefix
python main.py -t https://target.example.com -w 20 -o my_audit_report
```

---

## 📄 Output Reports

SecScan supports three report export formats:

1. **Structured JSON (`.json`)**: Raw machine-readable data for SIEM, Jira, or custom pipeline integration.
2. **Executive HTML (`.html`)**: Rich visual report with risk meters, vulnerability tables, and remediation instructions.
3. **Printable PDF (`.pdf`)**: A4-formatted executive deliverable (requires `weasyprint`).

---

## ⚠️ Legal Disclaimer

SecScan is developed for **authorized security audits, educational purposes, and defensive testing only**. Scanning targets without prior explicit authorization from the system owner is illegal and unethical. Use responsibly.
