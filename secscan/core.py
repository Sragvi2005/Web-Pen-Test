import urllib.parse
from datetime import datetime

import requests

from .logger import log
from . import scanners as _scanners
from . import report as _report


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
        log(level, message)

    # --- Scanning methods (delegate to scanners module) ---

    def inspect_ssl_certificate(self):
        _scanners.inspect_ssl_certificate(self)

    def audit_security_headers(self):
        _scanners.audit_security_headers(self)

    def check_cors_misconfiguration(self):
        _scanners.check_cors_misconfiguration(self)

    def scan_sensitive_endpoints_concurrently(self):
        _scanners.scan_sensitive_endpoints_concurrently(self)

    def test_reflected_xss(self):
        _scanners.test_reflected_xss(self)

    # --- Reporting methods (delegate to report module) ---

    def generate_html_report(self, filename="security_report.html"):
        return _report.generate_html_report(self, filename)

    def generate_pdf_report(self, html_filename="security_report.html", pdf_filename="security_report.pdf"):
        return _report.generate_pdf_report(self, html_filename, pdf_filename)

    def export_json_report(self, filename="scan_report.json"):
        _report.export_json_report(self, filename)
