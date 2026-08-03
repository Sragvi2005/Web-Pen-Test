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

import threading

# Thread-local storage for capturing log messages during API-driven scans.
# When a scan runs via the Flask API, we start a collector on the current
# thread so every log() call also appends to a list we can return as JSON.
_local = threading.local()


def start_log_collector():
    """Begin capturing log messages on the current thread."""
    _local.log_lines = []


def stop_log_collector():
    """Stop capturing and return the collected log lines."""
    lines = getattr(_local, "log_lines", [])
    _local.log_lines = None
    return lines


def log(level, message):
    """Print a colour-coded log line to the terminal and optionally capture it."""
    # Terminal output (always)
    if level == "INFO":
        print(f"{Fore.CYAN}[*] {message}{Fore.RESET}")
    elif level == "SUCCESS":
        print(f"{Fore.GREEN}[+] {message}{Fore.RESET}")
    elif level == "VULN":
        print(f"{Fore.RED}[!] VULNERABILITY FOUND: {message}{Fore.RESET}")

    # Capture for API responses if a collector is active
    collector = getattr(_local, "log_lines", None)
    if collector is not None:
        # Map levels to the CSS classes the frontend terminal uses
        css_map = {"INFO": "tw-muted", "SUCCESS": "tw-ok", "VULN": "tw-line-vuln"}
        prefix_map = {"INFO": "[*]", "SUCCESS": "[✓]", "VULN": "[VULN]"}
        collector.append({
            "text": f"{prefix_map.get(level, '[*]')} {message}",
            "cls": css_map.get(level, ""),
        })
