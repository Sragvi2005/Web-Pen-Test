"""
SecScan Flask API Server & Static Frontend Host
===============================================
Wraps the existing secscan VulnerabilityScanner behind a REST API and serves
the frontend web application on localhost.

Usage:
    python server.py              # starts on http://127.0.0.1:5000
    python server.py --port 8080  # custom port
"""

import argparse
import os
import time

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from secscan import VulnerabilityScanner
from secscan.logger import start_log_collector, stop_log_collector

frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
app = Flask(__name__, static_folder=frontend_dir)
CORS(app)  # Allow cross-origin requests if frontend is served separately


@app.route("/")
def serve_frontend():
    """Serve index.html at root."""
    return send_from_directory(frontend_dir, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    """Serve JS, CSS, and other static assets from the frontend directory."""
    if os.path.exists(os.path.join(frontend_dir, path)):
        return send_from_directory(frontend_dir, path)
    return send_from_directory(frontend_dir, "index.html")


@app.route("/api/scan", methods=["POST"])
def run_scan():
    """
    Run a security scan against the provided target.
    """
    data = request.get_json(force=True, silent=True)
    if not data or "target" not in data:
        return jsonify({"status": "error", "message": "Missing 'target' in request body."}), 400

    target = data["target"].strip()
    if not target:
        return jsonify({"status": "error", "message": "Target URL cannot be empty."}), 400

    modules = data.get("modules", {
        "ssl": True,
        "headers": True,
        "cors": True,
        "endpoints": True,
        "xss": True,
    })
    workers = int(data.get("workers", 10))

    # Start capturing log output for this request
    start_log_collector()
    start_time = time.time()

    try:
        scanner = VulnerabilityScanner(target, max_threads=workers)

        if modules.get("ssl", False):
            scanner.inspect_ssl_certificate()

        if modules.get("headers", False):
            scanner.audit_security_headers()

        if modules.get("cors", False):
            scanner.check_cors_misconfiguration()

        if modules.get("endpoints", False):
            scanner.scan_sensitive_endpoints_concurrently()

        if modules.get("xss", False):
            scanner.test_reflected_xss()

        elapsed = round(time.time() - start_time, 2)
        logs = stop_log_collector()

        return jsonify({
            "status": "complete",
            "target": target,
            "scan_duration": elapsed,
            "findings": scanner.findings,
            "logs": logs,
        })

    except Exception as exc:
        elapsed = round(time.time() - start_time, 2)
        logs = stop_log_collector()

        return jsonify({
            "status": "error",
            "target": target,
            "scan_duration": elapsed,
            "message": str(exc),
            "findings": [],
            "logs": logs,
        }), 500


@app.route("/api/health", methods=["GET"])
def health():
    """Simple health-check endpoint."""
    return jsonify({"status": "ok", "engine": "SecScan Enterprise v3.5"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecScan API & Web Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    args = parser.parse_args()

    print("======================================================")
    print("     SecScan API Server — Enterprise Engine v3.5      ")
    print("======================================================")
    print(f"  Web Application: http://{args.host}:{args.port}/")
    print(f"  Scan API:         POST http://{args.host}:{args.port}/api/scan")
    print(f"  Health Check:     GET  http://{args.host}:{args.port}/api/health")
    print("======================================================\n")

    app.run(host=args.host, port=args.port, debug=False)
