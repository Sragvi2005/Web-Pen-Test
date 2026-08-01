import requests
import urllib.parse
import json
import argparse
import socket
import ssl
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colorama fallback for clean cross-platform terminal formatting
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        CYAN = "\033[36m"
        GREEN = "\033[32m"
        RED = "\033[31m"
        MAGENTA = "\033[35m"
        RESET = "\033[0m"
    class Style:
        RESET_ALL = "\033[0m"
    def init(autoreset=True):
        pass

# WeasyPrint check for PDF generation
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    # ImportError = not installed; OSError = missing system libs (e.g. libgobject-2.0 on macOS)
    WEASYPRINT_AVAILABLE = False


class VulnerabilityScanner:
    def __init__(self, target_url, max_threads=10):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urllib.parse.urlparse(self.target_url)
        self.domain = self.parsed_url.netloc or self.parsed_url.path
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]
            
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecScan-Enterprise-Engine/3.5'})
        self.findings = []
        self.start_time = datetime.now()

    def log(self, level, message):
        if level == "INFO":
            print(f"{Fore.CYAN}[*] {message}{Fore.RESET}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}[+] {message}{Fore.RESET}")
        elif level == "VULN":
            print(f"{Fore.RED}[!] VULNERABILITY FOUND: {message}{Fore.RESET}")

    def inspect_ssl_certificate(self):
        """Inspect TLS protocol versions and certificate expiration details."""
        if self.parsed_url.scheme != "https":
            self.log("INFO", "Target is not using HTTPS. Skipping SSL/TLS inspection.")
            return

        self.log("INFO", f"Inspecting SSL/TLS Certificate for {self.domain}...")
        context = ssl.create_default_context()

        try:
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher, version, _ = ssock.cipher()

                    self.log("SUCCESS", f"TLS Version in Use: {version} | Cipher: {cipher}")

                    if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        msg = f"Deprecated or insecure TLS protocol version enabled: {version}."
                        remediation = "Disable TLS 1.0/1.1 and legacy SSL protocols on web server configurations; enforce TLS 1.2 or TLS 1.3 only."
                        self.log("VULN", msg)
                        self.findings.append({
                            "title": "Weak TLS Protocol Enabled",
                            "type": "Transport Layer Security",
                            "severity": "High",
                            "cvss": "7.5",
                            "detail": msg,
                            "remediation": remediation
                        })

                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        expires_on = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_remaining = (expires_on - datetime.utcnow()).days

                        if days_remaining < 0:
                            msg = f"SSL/TLS Certificate expired on {expires_on.strftime('%Y-%m-%d')}."
                            remediation = "Renew and bind a valid, trusted X.509 SSL certificate immediately."
                            self.log("VULN", msg)
                            self.findings.append({
                                "title": "Expired SSL/TLS Certificate",
                                "type": "Transport Layer Security",
                                "severity": "High",
                                "cvss": "7.4",
                                "detail": msg,
                                "remediation": remediation
                            })
                        elif days_remaining < 15:
                            msg = f"SSL/TLS Certificate is nearing expiration (expires in {days_remaining} days)."
                            remediation = "Schedule certificate renewal with certificate authority prior to expiration date."
                            self.log("VULN", msg)
                            self.findings.append({
                                "title": "Expiring SSL/TLS Certificate",
                                "type": "Transport Layer Security",
                                "severity": "Medium",
                                "cvss": "5.3",
                                "detail": msg,
                                "remediation": remediation
                            })
                        else:
                            self.log("SUCCESS", f"SSL Certificate is valid for {days_remaining} more days.")

        except Exception as e:
            self.log("VULN", f"SSL/TLS Inspection Failed: {e}")

    def audit_security_headers(self):
        """Check for recommended OWASP security headers."""
        self.log("INFO", "Auditing HTTP Security Headers...")
        recommended_headers = {
            "Content-Security-Policy": ("Mitigates Cross-Site Scripting (XSS) and data injection attacks.", "High", "6.5", "Implement a robust Content-Security-Policy header restricting script execution sources."),
            "Strict-Transport-Security": ("Enforces secure HTTPS connections.", "Medium", "5.3", "Configure HSTS header: 'max-age=31536000; includeSubDomains; preload'."),
            "X-Frame-Options": ("Protects application against Clickjacking attacks.", "Medium", "4.3", "Set X-Frame-Options header to 'DENY' or 'SAMEORIGIN'."),
            "X-Content-Type-Options": ("Prevents browser MIME-sniffing vulnerabilities.", "Low", "3.4", "Configure 'X-Content-Type-Options: nosniff'."),
            "Referrer-Policy": ("Controls referrer information disclosure in request headers.", "Low", "3.1", "Set 'Referrer-Policy: strict-origin-when-cross-origin'.")
        }
        
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            
            for header, (description, severity, cvss, remediation) in recommended_headers.items():
                if header not in headers:
                    msg = f"Missing HTTP Security Header: '{header}'. {description}"
                    self.log("VULN", msg)
                    self.findings.append({
                        "title": f"Missing Header: {header}",
                        "type": "HTTP Security Header",
                        "severity": severity,
                        "cvss": cvss,
                        "detail": msg,
                        "remediation": remediation
                    })
                else:
                    self.log("SUCCESS", f"Found Header: {header}")
        except requests.RequestException as e:
            self.log("VULN", f"Failed to connect to target: {e}")

    def check_cors_misconfiguration(self):
        """Audit for arbitrary origin reflection and credential exposure in CORS."""
        self.log("INFO", "Auditing CORS Configuration...")
        attacker_origin = "https://evil-attacker-domain.com"
        headers = {"Origin": attacker_origin}

        try:
            res = self.session.get(self.target_url, headers=headers, timeout=5)
            cors_origin = res.headers.get("Access-Control-Allow-Origin")
            cors_credentials = res.headers.get("Access-Control-Allow-Credentials")

            if cors_origin == attacker_origin or cors_origin == "*":
                if cors_credentials == "true":
                    msg = f"Critical CORS Misconfiguration! Origin reflected ('{cors_origin}') with Access-Control-Allow-Credentials set to true."
                    remediation = "Avoid reflecting request Origin headers dynamically with credentials enabled; whitelist trusted origins explicitly."
                    self.log("VULN", msg)
                    self.findings.append({
                        "title": "Exploitable CORS Misconfiguration",
                        "type": "Cross-Origin Access",
                        "severity": "Critical",
                        "cvss": "8.8",
                        "detail": msg,
                        "remediation": remediation
                    })
                elif cors_origin == attacker_origin:
                    msg = f"Arbitrary Origin Reflection detected: Access-Control-Allow-Origin reflects arbitrary origin '{cors_origin}'."
                    remediation = "Restrict Access-Control-Allow-Origin to static, strictly validated domain lists."
                    self.log("VULN", msg)
                    self.findings.append({
                        "title": "Arbitrary CORS Origin Reflection",
                        "type": "Cross-Origin Access",
                        "severity": "Medium",
                        "cvss": "5.3",
                        "detail": msg,
                        "remediation": remediation
                    })
            else:
                self.log("SUCCESS", "CORS policy appears properly restricted.")

        except requests.RequestException as e:
            self.log("VULN", f"CORS Audit Request Failed: {e}")

    def _check_single_endpoint(self, path):
        """Helper function executed by individual worker threads."""
        url = f"{self.target_url}{path}"
        try:
            res = self.session.get(url, timeout=3, allow_redirects=False)
            if res.status_code == 200:
                msg = f"Exposed Sensitive Endpoint: {path} returned HTTP 200 OK."
                remediation = f"Restrict public access to path '{path}' using web server access controls or authenticated route guards."
                self.log("VULN", msg)
                return {
                    "title": f"Exposed Sensitive File/Directory: {path}",
                    "type": "Information Disclosure",
                    "severity": "High" if path in ["/.env", "/.git/HEAD", "/.aws/credentials", "/backup.sql"] else "Medium",
                    "cvss": "7.5" if path in ["/.env", "/.git/HEAD", "/.aws/credentials", "/backup.sql"] else "5.3",
                    "detail": msg,
                    "remediation": remediation
                }
        except requests.RequestException:
            pass
        return None

    def scan_sensitive_endpoints_concurrently(self):
        """Concurrent dictionary-based endpoint discovery using ThreadPoolExecutor."""
        self.log("INFO", f"Scanning sensitive endpoints with {self.max_threads} worker threads...")
        common_paths = [
            "/.env", "/.git/HEAD", "/config.json", "/admin", 
            "/api/v1/health", "/swagger.json", "/robots.txt",
            "/server-status", "/.aws/credentials", "/backup.sql"
        ]

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {
                executor.submit(self._check_single_endpoint, path): path 
                for path in common_paths
            }
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    self.findings.append(result)

    def test_reflected_xss(self):
        """Safely test for Reflected XSS parameter reflection."""
        self.log("INFO", "Testing for Reflected XSS indicators...")
        payload = "<SecTest123>"
        test_url = f"{self.target_url}/?q={urllib.parse.quote(payload)}"
        
        try:
            res = self.session.get(test_url, timeout=5)
            if payload in res.text:
                msg = f"Unsanitized reflected input detected at query parameter 'q' in target URL."
                remediation = "Implement contextual HTML/JavaScript output encoding and validate input parameters against strict allow-lists."
                self.log("VULN", msg)
                self.findings.append({
                    "title": "Reflected Input Parameter (XSS Indicator)",
                    "type": "Input Injection",
                    "severity": "High",
                    "cvss": "7.2",
                    "detail": msg,
                    "remediation": remediation
                })
            else:
                self.log("INFO", "No simple reflected input found in standard parameters.")
        except requests.RequestException:
             self.log("INFO", "XSS test request failed.")

    def generate_html_report(self, filename="security_report.html"):
        """Generates an executive-ready HTML vulnerability assessment report."""
        end_time = datetime.now()
        duration = round((end_time - self.start_time).total_seconds(), 2)

        critical_count = sum(1 for f in self.findings if f['severity'] == 'Critical')
        high_count = sum(1 for f in self.findings if f['severity'] == 'High')
        med_count = sum(1 for f in self.findings if f['severity'] == 'Medium')
        low_count = sum(1 for f in self.findings if f['severity'] == 'Low')

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability & API Security Assessment Report</title>
<style>
@page {{
    size: A4;
    margin: 15mm 12mm;
    background-color: #f8fafc;
}}

*, *::before, *::after {{
    box-sizing: border-box;
}}

body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #334155;
    background-color: #f8fafc;
    margin: 0;
    padding: 0;
    font-size: 10pt;
    line-height: 1.5;
}}

.header-banner {{
    background-color: #0f172a;
    color: #ffffff;
    margin: -15mm -12mm 20px -12mm;
    padding: 24px 15mm;
    border-bottom: 4px solid #2563eb;
}}

.header-banner h1 {{
    margin: 0 0 6px 0;
    font-size: 18pt;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #ffffff;
}}

.header-banner .subtitle {{
    color: #94a3b8;
    font-size: 10pt;
    margin: 0;
}}

.meta-grid {{
    width: 100%;
    margin-bottom: 20px;
    border-collapse: collapse;
}}

.meta-grid td {{
    padding: 8px 12px;
    background: #ffffff;
    border: 1px solid #e2e8f0;
    font-size: 9.5pt;
}}

.meta-label {{
    font-weight: 600;
    color: #475569;
    width: 18%;
    background-color: #f1f5f9 !important;
}}

.meta-val {{
    color: #0f172a;
    width: 32%;
}}

.section-title {{
    font-size: 13pt;
    font-weight: 700;
    color: #0f172a;
    margin: 20px 0 10px 0;
    padding-left: 10px;
    border-left: 4px solid #2563eb;
    page-break-after: avoid;
}}

.summary-cards {{
    width: 100%;
    margin-bottom: 22px;
    border-collapse: separate;
    border-spacing: 8px;
}}

.summary-card {{
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 10px;
    text-align: center;
}}

.card-num {{
    font-size: 18pt;
    font-weight: 800;
    line-height: 1.1;
}}

.card-label {{
    font-size: 8pt;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.5px;
    margin-top: 4px;
}}

.bg-critical {{ color: #dc2626; }}
.bg-high {{ color: #ea580c; }}
.bg-medium {{ color: #d97706; }}
.bg-low {{ color: #2563eb; }}

.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 8pt;
    font-weight: 700;
    text-transform: uppercase;
    color: #ffffff;
}}

.badge-critical {{ background-color: #dc2626; }}
.badge-high {{ background-color: #ea580c; }}
.badge-medium {{ background-color: #d97706; }}
.badge-low {{ background-color: #2563eb; }}

.table-findings {{
    width: 100%;
    border-collapse: collapse;
    background: #ffffff;
    margin-bottom: 20px;
}}

.table-findings th {{
    background-color: #1e293b;
    color: #ffffff;
    text-align: left;
    padding: 8px 10px;
    font-size: 9pt;
    font-weight: 600;
}}

.table-findings td {{
    padding: 8px 10px;
    border-bottom: 1px solid #e2e8f0;
    font-size: 9pt;
}}

.finding-box {{
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    padding: 12px 14px;
    margin-bottom: 12px;
    page-break-inside: avoid;
}}

.finding-header {{
    width: 100%;
    margin-bottom: 8px;
}}

.finding-title {{
    font-size: 11pt;
    font-weight: 700;
    color: #0f172a;
}}

.detail-label {{
    font-weight: 600;
    color: #475569;
    margin-top: 6px;
    font-size: 8.5pt;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}}

.detail-text {{
    color: #334155;
    background: #f8fafc;
    padding: 8px;
    border-left: 3px solid #cbd5e1;
    font-size: 9pt;
    margin-top: 4px;
}}

.remediation-text {{
    color: #065f46;
    background: #ecfdf5;
    padding: 8px;
    border-left: 3px solid #10b981;
    font-size: 9pt;
    margin-top: 4px;
}}

.footer {{
    margin-top: 30px;
    padding-top: 10px;
    border-top: 1px solid #cbd5e1;
    font-size: 8pt;
    color: #64748b;
    text-align: center;
}}
</style>
</head>
<body>

<div class="header-banner">
    <h1>Security Assessment & Vulnerability Report</h1>
    <div class="subtitle">Automated Web Security & API Threat Intelligence Audit</div>
</div>

<table class="meta-grid">
    <tr>
        <td class="meta-label">Target URL</td>
        <td class="meta-val"><code>{self.target_url}</code></td>
        <td class="meta-label">Scan Date</td>
        <td class="meta-val">{self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
    </tr>
    <tr>
        <td class="meta-label">Domain Name</td>
        <td class="meta-val">{self.domain}</td>
        <td class="meta-label">Scan Duration</td>
        <td class="meta-val">{duration} seconds</td>
    </tr>
    <tr>
        <td class="meta-label">Audit Engine</td>
        <td class="meta-val">SecScan Enterprise v3.5</td>
        <td class="meta-label">Worker Threads</td>
        <td class="meta-val">{self.max_threads} Concurrent Threads</td>
    </tr>
</table>

<div class="section-title">Executive Risk Summary</div>

<table class="summary-cards">
    <tr>
        <td class="summary-card" style="width: 20%;">
            <div class="card-num">{len(self.findings)}</div>
            <div class="card-label" style="color: #475569;">Total Risks</div>
        </td>
        <td class="summary-card" style="width: 20%;">
            <div class="card-num bg-critical">{critical_count}</div>
            <div class="card-label bg-critical">Critical</div>
        </td>
        <td class="summary-card" style="width: 20%;">
            <div class="card-num bg-high">{high_count}</div>
            <div class="card-label bg-high">High</div>
        </td>
        <td class="summary-card" style="width: 20%;">
            <div class="card-num bg-medium">{med_count}</div>
            <div class="card-label bg-medium">Medium</div>
        </td>
        <td class="summary-card" style="width: 20%;">
            <div class="card-num bg-low">{low_count}</div>
            <div class="card-label bg-low">Low / Info</div>
        </td>
    </tr>
</table>

<div class="section-title">Vulnerability Overview</div>
"""

        if not self.findings:
            html_content += """
            <div style="background: #ecfdf5; border: 1px solid #a7f3d0; padding: 15px; color: #065f46; border-radius: 4px; font-weight: 600;">
                [+] No security vulnerabilities were identified during this assessment sweep.
            </div>
            """
        else:
            html_content += """
            <table class="table-findings">
                <thead>
                    <tr>
                        <th style="width: 15%;">Severity</th>
                        <th style="width: 10%;">CVSS</th>
                        <th style="width: 45%;">Vulnerability Title</th>
                        <th style="width: 30%;">Category</th>
                    </tr>
                </thead>
                <tbody>
            """
            for f in self.findings:
                sev_lower = f['severity'].lower()
                html_content += f"""
                <tr>
                    <td><span class="badge badge-{sev_lower}">{f['severity']}</span></td>
                    <td><strong>{f['cvss']}</strong></td>
                    <td>{f['title']}</td>
                    <td>{f['type']}</td>
                </tr>
                """
            html_content += "</tbody></table>"

            html_content += '<div class="section-title">Detailed Vulnerability Findings & Remediation</div>'
            for idx, f in enumerate(self.findings, 1):
                sev_lower = f['severity'].lower()
                html_content += f"""
                <div class="finding-box">
                    <div class="finding-header">
                        <span class="badge badge-{sev_lower}">{f['severity']}</span>
                        <span style="font-size: 9pt; color: #64748b; margin-left: 8px;">CVSS v3.1: {f['cvss']}</span>
                        <div class="finding-title" style="margin-top: 4px;">#{idx}. {f['title']}</div>
                    </div>
                    
                    <div class="detail-label">Technical Observation</div>
                    <div class="detail-text">{f['detail']}</div>
                    
                    <div class="detail-label">Recommended Remediation Action</div>
                    <div class="remediation-text">{f['remediation']}</div>
                </div>
                """

        html_content += """
<div class="footer">
    Confidential Security Assessment Document &bull; Generated automatically by SecScan Threat Intelligence Engine
</div>

</body>
</html>
"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        self.log("SUCCESS", f"HTML Analysis Report successfully generated: {filename}")
        return filename

    def generate_pdf_report(self, html_filename="security_report.html", pdf_filename="security_report.pdf"):
        """Converts generated HTML report to a publishable, multi-page PDF document using WeasyPrint."""
        if not WEASYPRINT_AVAILABLE:
            self.log("VULN", "WeasyPrint package is not installed. PDF generation skipped. (Run: pip install weasyprint)")
            return None

        try:
            HTML(filename=html_filename).write_pdf(pdf_filename)
            self.log("SUCCESS", f"Executive PDF Report generated: {pdf_filename}")
            return pdf_filename
        except Exception as e:
            self.log("VULN", f"Failed to render PDF report: {e}")
            return None

    def export_json_report(self, filename="scan_report.json"):
        """Export findings to structured JSON format."""
        report_data = {
            "target": self.target_url,
            "scan_timestamp": self.start_time.isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        with open(filename, "w") as f:
            json.dump(report_data, f, indent=4)
        self.log("SUCCESS", f"JSON data output saved to {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Security & API Scanner with Professional Executive Reporting")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent worker threads (Default: 10)")
    parser.add_argument("-o", "--output-prefix", default="security_report", help="Output report base filename")
    
    args = parser.parse_args()
    
    print("======================================================")
    print("     Automated Security & API Threat Intelligence     ")
    print("======================================================\n")
    
    scanner = VulnerabilityScanner(args.target, max_threads=args.workers)
    scanner.inspect_ssl_certificate()
    scanner.audit_security_headers()
    scanner.check_cors_misconfiguration()
    scanner.scan_sensitive_endpoints_concurrently()
    scanner.test_reflected_xss()
    
    json_file = f"{args.output_prefix}.json"
    html_file = f"{args.output_prefix}.html"
    pdf_file = f"{args.output_prefix}.pdf"
    
    scanner.export_json_report(json_file)
    scanner.generate_html_report(html_file)
    scanner.generate_pdf_report(html_file, pdf_file)