import sys
import ctypes
import shutil
import logging

from .console import console

log = logging.getLogger("throttwin")

REQUIRED_PYTHON = (3, 9)


def check_os():
    """Verify we're running on Windows."""
    if sys.platform != "win32":
        console.print(" [error]Throttwin only supports Windows.[/error]")
        console.print(" [error]For Linux, use Throttnux Plus instead.[/error]")
        sys.exit(1)


def check_admin():
    """Check for Administrator/elevated privileges required by Npcap."""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False

    if not is_admin:
        console.print(" [error]Throttwin must be run as Administrator.[/error]")
        console.print(" [error]Right-click your terminal and select 'Run as administrator', then re-run.[/error]")
        sys.exit(1)


def check_npcap():
    """Verify Npcap (or WinPcap) is installed and accessible via Scapy."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        if not ifaces:
            raise RuntimeError("No Npcap interfaces found.")
    except Exception as e:
        console.print(" [error]Npcap not detected or Scapy cannot access it.[/error]")
        console.print(f" [error]Details: {e}[/error]")
        console.print(" [error]Please install Npcap from https://npcap.com and restart.[/error]")
        sys.exit(1)


def check_python_version():
    """Ensure a recent enough Python version."""
    if sys.version_info < REQUIRED_PYTHON:
        console.print(f" [error]Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+ is required.[/error]")
        console.print(f" [error]Current version: {sys.version}[/error]")
        sys.exit(1)


def check_dependencies():
    """Check that required Python packages are importable."""
    missing = []
    required = ["scapy", "rich", "questionary", "pyfiglet", "flask", "psutil"]
    for pkg in required:
        if shutil.which(pkg) is None:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(pkg)

    if missing:
        console.print(f" [error]Missing required packages: {', '.join(missing)}[/error]")
        console.print(f" [error]Run: pip install {' '.join(missing)}[/error]")
        sys.exit(1)


def check_all():
    """Run all startup checks."""
    check_os()
    check_python_version()
    check_npcap()
    check_dependencies()
