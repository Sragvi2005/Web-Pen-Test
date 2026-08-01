import json
from datetime import datetime

from .logger import log

# WeasyPrint check for PDF generation
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    # ImportError = not installed; OSError = missing system libs (e.g. libgobject-2.0 on macOS)
    WEASYPRINT_AVAILABLE = False


def generate_html_report(scanner, filename="security_report.html"):
    """Generates an executive-ready HTML vulnerability assessment report."""
    end_time = datetime.now()
    duration = round((end_time - scanner.start_time).total_seconds(), 2)

    critical_count = sum(1 for f in scanner.findings if f['severity'] == 'Critical')
    high_count = sum(1 for f in scanner.findings if f['severity'] == 'High')
    med_count = sum(1 for f in scanner.findings if f['severity'] == 'Medium')
    low_count = sum(1 for f in scanner.findings if f['severity'] == 'Low')

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
        <td class="meta-val"><code>{scanner.target_url}</code></td>
        <td class="meta-label">Scan Date</td>
        <td class="meta-val">{scanner.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
    </tr>
    <tr>
        <td class="meta-label">Domain Name</td>
        <td class="meta-val">{scanner.domain}</td>
        <td class="meta-label">Scan Duration</td>
        <td class="meta-val">{duration} seconds</td>
    </tr>
    <tr>
        <td class="meta-label">Audit Engine</td>
        <td class="meta-val">SecScan Enterprise v3.5</td>
        <td class="meta-label">Worker Threads</td>
        <td class="meta-val">{scanner.max_threads} Concurrent Threads</td>
    </tr>
</table>

<div class="section-title">Executive Risk Summary</div>

<table class="summary-cards">
    <tr>
        <td class="summary-card" style="width: 20%;">
            <div class="card-num">{len(scanner.findings)}</div>
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

    if not scanner.findings:
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
        for f in scanner.findings:
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
        for idx, f in enumerate(scanner.findings, 1):
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
    
    log("SUCCESS", f"HTML Analysis Report successfully generated: {filename}")
    return filename


def generate_pdf_report(scanner, html_filename="security_report.html", pdf_filename="security_report.pdf"):
    """Converts generated HTML report to a publishable, multi-page PDF document using WeasyPrint."""
    if not WEASYPRINT_AVAILABLE:
        log("VULN", "WeasyPrint package is not installed. PDF generation skipped. (Run: pip install weasyprint)")
        return None

    try:
        HTML(filename=html_filename).write_pdf(pdf_filename)
        log("SUCCESS", f"Executive PDF Report generated: {pdf_filename}")
        return pdf_filename
    except Exception as e:
        log("VULN", f"Failed to render PDF report: {e}")
        return None


def export_json_report(scanner, filename="scan_report.json"):
    """Export findings to structured JSON format."""
    report_data = {
        "target": scanner.target_url,
        "scan_timestamp": scanner.start_time.isoformat(),
        "total_findings": len(scanner.findings),
        "findings": scanner.findings
    }
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
    log("SUCCESS", f"JSON data output saved to {filename}")
