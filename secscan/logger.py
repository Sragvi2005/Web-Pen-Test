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


def log(level, message):
    """Print a colour-coded log line to the terminal."""
    if level == "INFO":
        print(f"{Fore.CYAN}[*] {message}{Fore.RESET}")
    elif level == "SUCCESS":
        print(f"{Fore.GREEN}[+] {message}{Fore.RESET}")
    elif level == "VULN":
        print(f"{Fore.RED}[!] VULNERABILITY FOUND: {message}{Fore.RESET}")
