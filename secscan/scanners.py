import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .logger import log


def inspect_ssl_certificate(scanner):
    """Inspect TLS protocol versions and certificate expiration details."""
    if scanner.parsed_url.scheme != "https":
        log("INFO", "Target is not using HTTPS. Skipping SSL/TLS inspection.")
        return

    log("INFO", f"Inspecting SSL/TLS Certificate for {scanner.domain}...")
    context = ssl.create_default_context()

    try:
        with socket.create_connection((scanner.domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=scanner.domain) as ssock:
                cert = ssock.getpeercert()
                cipher, version, _ = ssock.cipher()

                log("SUCCESS", f"TLS Version in Use: {version} | Cipher: {cipher}")

                if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    msg = f"Deprecated or insecure TLS protocol version enabled: {version}."
                    remediation = "Disable TLS 1.0/1.1 and legacy SSL protocols on web server configurations; enforce TLS 1.2 or TLS 1.3 only."
                    log("VULN", msg)
                    scanner.findings.append({
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
                    days_remaining = (expires_on - datetime.now(timezone.utc).replace(tzinfo=None)).days

                    if days_remaining < 0:
                        msg = f"SSL/TLS Certificate expired on {expires_on.strftime('%Y-%m-%d')}."
                        remediation = "Renew and bind a valid, trusted X.509 SSL certificate immediately."
                        log("VULN", msg)
                        scanner.findings.append({
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
                        log("VULN", msg)
                        scanner.findings.append({
                            "title": "Expiring SSL/TLS Certificate",
                            "type": "Transport Layer Security",
                            "severity": "Medium",
                            "cvss": "5.3",
                            "detail": msg,
                            "remediation": remediation
                        })
                    else:
                        log("SUCCESS", f"SSL Certificate is valid for {days_remaining} more days.")

    except Exception as e:
        log("VULN", f"SSL/TLS Inspection Failed: {e}")


def audit_security_headers(scanner):
    """Check for recommended OWASP security headers."""
    log("INFO", "Auditing HTTP Security Headers...")
    recommended_headers = {
        "Content-Security-Policy": ("Mitigates Cross-Site Scripting (XSS) and data injection attacks.", "High", "6.5", "Implement a robust Content-Security-Policy header restricting script execution sources."),
        "Strict-Transport-Security": ("Enforces secure HTTPS connections.", "Medium", "5.3", "Configure HSTS header: 'max-age=31536000; includeSubDomains; preload'."),
        "X-Frame-Options": ("Protects application against Clickjacking attacks.", "Medium", "4.3", "Set X-Frame-Options header to 'DENY' or 'SAMEORIGIN'."),
        "X-Content-Type-Options": ("Prevents browser MIME-sniffing vulnerabilities.", "Low", "3.4", "Configure 'X-Content-Type-Options: nosniff'."),
        "Referrer-Policy": ("Controls referrer information disclosure in request headers.", "Low", "3.1", "Set 'Referrer-Policy: strict-origin-when-cross-origin'.")
    }
    
    try:
        response = scanner.session.get(scanner.target_url, timeout=5)
        headers = response.headers
        
        for header, (description, severity, cvss, remediation) in recommended_headers.items():
            if header not in headers:
                msg = f"Missing HTTP Security Header: '{header}'. {description}"
                log("VULN", msg)
                scanner.findings.append({
                    "title": f"Missing Header: {header}",
                    "type": "HTTP Security Header",
                    "severity": severity,
                    "cvss": cvss,
                    "detail": msg,
                    "remediation": remediation
                })
            else:
                log("SUCCESS", f"Found Header: {header}")
    except requests.RequestException as e:
        log("VULN", f"Failed to connect to target: {e}")


def check_cors_misconfiguration(scanner):
    """Audit for arbitrary origin reflection and credential exposure in CORS."""
    log("INFO", "Auditing CORS Configuration...")
    attacker_origin = "https://evil-attacker-domain.com"
    headers = {"Origin": attacker_origin}

    try:
        res = scanner.session.get(scanner.target_url, headers=headers, timeout=5)
        cors_origin = res.headers.get("Access-Control-Allow-Origin")
        cors_credentials = res.headers.get("Access-Control-Allow-Credentials")

        if cors_origin == attacker_origin or cors_origin == "*":
            if cors_credentials == "true":
                msg = f"Critical CORS Misconfiguration! Origin reflected ('{cors_origin}') with Access-Control-Allow-Credentials set to true."
                remediation = "Avoid reflecting request Origin headers dynamically with credentials enabled; whitelist trusted origins explicitly."
                log("VULN", msg)
                scanner.findings.append({
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
                log("VULN", msg)
                scanner.findings.append({
                    "title": "Arbitrary CORS Origin Reflection",
                    "type": "Cross-Origin Access",
                    "severity": "Medium",
                    "cvss": "5.3",
                    "detail": msg,
                    "remediation": remediation
                })
        else:
            log("SUCCESS", "CORS policy appears properly restricted.")

    except requests.RequestException as e:
        log("VULN", f"CORS Audit Request Failed: {e}")


def _check_single_endpoint(scanner, path):
    """Helper function executed by individual worker threads."""
    url = f"{scanner.target_url}{path}"
    try:
        res = scanner.session.get(url, timeout=3, allow_redirects=False)
        if res.status_code == 200:
            msg = f"Exposed Sensitive Endpoint: {path} returned HTTP 200 OK."
            remediation = f"Restrict public access to path '{path}' using web server access controls or authenticated route guards."
            log("VULN", msg)
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


def scan_sensitive_endpoints_concurrently(scanner):
    """Concurrent dictionary-based endpoint discovery using ThreadPoolExecutor."""
    log("INFO", f"Scanning sensitive endpoints with {scanner.max_threads} worker threads...")
    common_paths = [
        "/.env", "/.git/HEAD", "/config.json", "/admin", 
        "/api/v1/health", "/swagger.json", "/robots.txt",
        "/server-status", "/.aws/credentials", "/backup.sql"
    ]

    with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        future_to_path = {
            executor.submit(_check_single_endpoint, scanner, path): path 
            for path in common_paths
        }
        
        for future in as_completed(future_to_path):
            result = future.result()
            if result:
                scanner.findings.append(result)


def test_reflected_xss(scanner):
    """Safely test for Reflected XSS parameter reflection."""
    log("INFO", "Testing for Reflected XSS indicators...")
    payload = "<SecTest123>"
    test_url = f"{scanner.target_url}/?q={urllib.parse.quote(payload)}"
    
    try:
        res = scanner.session.get(test_url, timeout=5)
        if payload in res.text:
            msg = f"Unsanitized reflected input detected at query parameter 'q' in target URL."
            remediation = "Implement contextual HTML/JavaScript output encoding and validate input parameters against strict allow-lists."
            log("VULN", msg)
            scanner.findings.append({
                "title": "Reflected Input Parameter (XSS Indicator)",
                "type": "Input Injection",
                "severity": "High",
                "cvss": "7.2",
                "detail": msg,
                "remediation": remediation
            })
        else:
            log("INFO", "No simple reflected input found in standard parameters.")
    except requests.RequestException:
         log("INFO", "XSS test request failed.")
