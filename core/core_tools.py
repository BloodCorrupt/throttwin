"""
core_tools.py — Management & execution for native compiled binaries (arp-scan.exe).

Provides:
- Automatic detection of local and bundled arp-scan binaries
- 1-Click downloading from https://github.com/QbsuranAlang/arp-scan-windows-
- Subprocess execution and output parsing for ultra-fast native C ARP sweeps
"""

import os
import sys
import platform
import subprocess
import urllib.request
import re
import logging
import threading

log = logging.getLogger("throttwin.core_tools")

# GitHub raw repository URLs for compiled Release binaries
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/QbsuranAlang/arp-scan-windows-/main/arp-scan"
URL_X64 = f"{GITHUB_RAW_BASE}/Release(x64)/arp-scan.exe"
URL_X86 = f"{GITHUB_RAW_BASE}/Release(x86)/arp-scan.exe"

_DOWNLOAD_LOCK = threading.Lock()
_IS_DOWNLOADING = False


def get_bin_dir():
    """Return the absolute path to the project's bin directory."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bin_dir = os.path.join(project_root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    return bin_dir


def get_arp_scan_path():
    """Locate arp-scan.exe in project bin/ or system PATH."""
    bin_dir = get_bin_dir()
    local_exe = os.path.join(bin_dir, "arp-scan.exe")
    if os.path.isfile(local_exe) and os.access(local_exe, os.X_OK | os.R_OK):
        return local_exe

    # Check system PATH
    import shutil
    path_exe = shutil.which("arp-scan.exe") or shutil.which("arp-scan")
    if path_exe:
        return path_exe

    return local_exe


def is_arp_scan_installed():
    """Return True if arp-scan.exe is installed and runnable."""
    exe_path = get_arp_scan_path()
    if not os.path.isfile(exe_path):
        return False
    try:
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0

        res = subprocess.run([exe_path, "-h"], capture_output=True, text=True, timeout=2, startupinfo=startupinfo)
        return "Usage:" in res.stderr or "Usage:" in res.stdout or res.returncode in (0, 1)
    except Exception as e:
        log.debug(f"arp-scan verification failed: {e}")
        return False


def get_core_status():
    """Return status dictionary of all core native binaries."""
    installed = is_arp_scan_installed()
    exe_path = get_arp_scan_path()
    size_bytes = 0
    if os.path.isfile(exe_path):
        try:
            size_bytes = os.path.getsize(exe_path)
        except Exception:
            pass

    is_64bit = sys.maxsize > 2**32
    arch_str = "x64" if is_64bit else "x86"

    return {
        "arp_scan": {
            "installed": installed,
            "path": exe_path if installed else "",
            "size_bytes": size_bytes,
            "arch": arch_str,
            "downloading": _IS_DOWNLOADING,
            "source_repo": "https://github.com/QbsuranAlang/arp-scan-windows-",
            "description": "High-Speed Native C Multi-Threaded ARP Sweep Engine for Windows"
        }
    }


def download_arp_scan(arch=None):
    """
    Download pre-compiled arp-scan.exe from QbsuranAlang/arp-scan-windows- repository.
    Returns (success: bool, message: str)
    """
    global _IS_DOWNLOADING
    with _DOWNLOAD_LOCK:
        if _IS_DOWNLOADING:
            return False, "Download already in progress."
        _IS_DOWNLOADING = True

    try:
        if arch is None:
            is_64bit = sys.maxsize > 2**32
            arch = "x64" if is_64bit else "x86"

        download_url = URL_X64 if arch == "x64" else URL_X86
        log.info(f"Downloading arp-scan.exe ({arch}) from {download_url}...")

        req = urllib.request.Request(
            download_url,
            headers={
                "User-Agent": "Throttwin-Core-Downloader/2.1 (Windows NT 10.0; Win64; x64)"
            }
        )

        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200:
                return False, f"HTTP Error {response.status} while downloading."
            content = response.read()

        if len(content) < 10000:
            return False, f"Downloaded binary is corrupted or too small ({len(content)} bytes)."

        bin_dir = get_bin_dir()
        target_path = os.path.join(bin_dir, "arp-scan.exe")
        
        # Write to temporary file then replace to avoid partial file states
        temp_path = target_path + ".tmp"
        with open(temp_path, "wb") as f:
            f.write(content)

        if os.path.exists(target_path):
            try:
                os.remove(target_path)
            except Exception:
                pass
        os.rename(temp_path, target_path)

        # Verify executable
        if is_arp_scan_installed():
            log.info(f"arp-scan.exe successfully installed to {target_path} ({len(content)} bytes).")
            return True, f"arp-scan.exe ({arch}) installed successfully ({len(content) // 1024} KB)!"
        else:
            return False, "Binary was downloaded but failed verification."

    except Exception as e:
        log.error(f"Failed to download arp-scan.exe: {e}")
        return False, f"Download failed: {str(e)}"
    finally:
        with _DOWNLOAD_LOCK:
            _IS_DOWNLOADING = False


def run_arp_scan_native(target_cidr, timeout=6.0):
    """
    Execute native arp-scan.exe tool against target_cidr (e.g. '192.168.1.1/24' or '192.168.1.100').
    Returns a list of dicts: [{'ip': '192.168.1.50', 'mac': 'aa:bb:cc:dd:ee:ff'}]
    """
    exe_path = get_arp_scan_path()
    if not os.path.isfile(exe_path):
        return []

    # Prepare CIDR argument (arp-scan.exe accepts -t IP/slash)
    target = str(target_cidr).strip()
    cmd = [exe_path, "-t", target]

    devices = []
    try:
        # Use STARTUPINFO to hide the console window popup on Windows
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            startupinfo=startupinfo
        )

        output = proc.stdout or ""
        # Match lines like: Reply that 40:74:E0:5E:E8:AE is 192.168.110.131 in 0.145200
        pattern = re.compile(
            r"Reply\s+that\s+([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})\s+is\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE
        )
        for match in pattern.finditer(output):
            mac = match.group(1).lower().replace("-", ":")
            ip = match.group(2)
            if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and not ip.endswith(".255"):
                devices.append({"ip": ip, "mac": mac})

    except subprocess.TimeoutExpired:
        log.debug(f"arp-scan.exe timed out after {timeout}s on {target_cidr}")
    except Exception as e:
        log.warning(f"arp-scan.exe native sweep failed: {e}")

    return devices
