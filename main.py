import argparse
from secscan import VulnerabilityScanner


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
