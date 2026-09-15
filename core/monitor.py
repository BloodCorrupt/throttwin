import time
import logging
import threading
import subprocess

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from .console import console
from .scanner import arp_scan, merge_devices, device_sort_key

log = logging.getLogger("throttwin")


def format_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    return f"{b / 1024 ** 3:.2f} GB"


def format_duration(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def check_online_windows(ip):
    """Check if a device is online via ping on Windows."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "800", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def verify_spoofing(interface, target_ip, shapers, stop_event, timeout=8):
    """
    Verify that ARP spoofing is working by checking if bytes
    are flowing through the target's shaper.
    Returns True if traffic is detected within `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    shaper = shapers.get(target_ip)
    if not shaper:
        return True  # No shaper = whitelist mode, assume OK

    initial = shaper.total_bytes
    while time.monotonic() < deadline:
        if stop_event.is_set():
            return False
        if shaper.total_bytes > initial + 512:
            return True
        time.sleep(0.5)
    return False


def live_monitor(interface, targets, shapers, limit_mbps, stop_event,
                 router_ip=None, whitelist_devices=None, on_new_device=None,
                 session_start_time=None):
    """
    Rich Live terminal monitor showing per-target bandwidth, totals, and uptime.
    Optionally runs a background ARP watcher for whitelist mode.
    """
    start_time = session_start_time or time.monotonic()

    # Background whitelist watcher
    if on_new_device and router_ip:
        watcher_thread = threading.Thread(
            target=_whitelist_watcher,
            args=(interface, router_ip, targets, whitelist_devices, on_new_device, stop_event),
            daemon=True
        )
        watcher_thread.start()

    def _build_table():
        now     = time.monotonic()
        uptime  = now - start_time
        up_str  = format_duration(uptime)

        total_mbps  = sum(s.get_speed_mbps() for s in shapers.values())
        total_bytes = sum(s.total_bytes for s in shapers.values())

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            expand=True,
            border_style="dim"
        )
        table.add_column("IP Address",   style="bold white",  min_width=15)
        table.add_column("Device",       style="dim",         min_width=20)
        table.add_column("Speed",        style="cyan",        min_width=12, justify="right")
        table.add_column("Limit",        style="dim",         min_width=10, justify="right")
        table.add_column("Total",        style="dim",         min_width=10, justify="right")
        table.add_column("Status",       style="",            min_width=10)

        for tgt in list(targets):
            ip     = tgt.get("ip") if isinstance(tgt, dict) else tgt
            vendor = tgt.get("vendor", "Unknown") if isinstance(tgt, dict) else "Unknown"
            host   = tgt.get("hostname", "") if isinstance(tgt, dict) else ""
            name   = f"{host} ({vendor})" if host else vendor
            if len(name) > 24:
                name = name[:24] + "…"

            shaper    = shapers.get(ip)
            speed_mbps = shaper.get_speed_mbps() if shaper else 0.0
            total_b    = shaper.total_bytes if shaper else 0

            # Status indicator
            bar_pct  = min(speed_mbps / limit_mbps, 1.0) if limit_mbps > 0 else 0
            if bar_pct > 0.75:
                status_str = "[red]● HEAVY[/red]"
            elif bar_pct > 0.1:
                status_str = "[yellow]● ACTIVE[/yellow]"
            else:
                status_str = "[dim]○ Idle[/dim]"

            table.add_row(
                ip or "-",
                name,
                f"{speed_mbps:.2f} Mbps",
                f"{limit_mbps:.1f} Mbps",
                format_bytes(total_b),
                status_str
            )

        # Footer panel
        footer = (
            f"[bold cyan]Total:[/bold cyan] {total_mbps:.2f} Mbps  "
            f"[dim]|[/dim]  "
            f"[bold cyan]Transferred:[/bold cyan] {format_bytes(total_bytes)}  "
            f"[dim]|[/dim]  "
            f"[bold cyan]Uptime:[/bold cyan] {up_str}  "
            f"[dim]|[/dim]  "
            f"[dim]Ctrl+C to stop[/dim]"
        )

        return Panel(table, title="[bold white]Throttwin — Live Monitor[/bold white]",
                     subtitle=footer, border_style="bright_blue")

    with Live(_build_table(), refresh_per_second=2, console=console) as live:
        while not stop_event.is_set():
            try:
                live.update(_build_table())
                stop_event.wait(0.5)
            except Exception:
                break

    console.print("\n [error]Session terminated.[/error]")
    console.print(" [success]Network restored and traffic shaping cleared.[/success]")


def _whitelist_watcher(interface, router_ip, targets, whitelist_devices,
                       on_new_device, stop_event):
    """
    Background thread that continuously scans for new devices.
    In whitelist mode, newly discovered devices not in the safe list
    are automatically throttled via the on_new_device callback.
    """
    known_ips = {tgt.get("ip") if isinstance(tgt, dict) else tgt for tgt in targets}
    from .config import get_predefined_whitelist
    global_wl = set(get_predefined_whitelist().keys())
    if whitelist_devices:
        safe_macs = {d.get("mac", "").lower() for d in whitelist_devices if isinstance(d, dict) and d.get("mac")}
        safe_ips  = {d.get("ip") for d in whitelist_devices if isinstance(d, dict) and d.get("ip")}
    else:
        safe_macs = set()
        safe_ips  = set()

    for pmac in global_wl:
        safe_macs.add(pmac.lower())

    while not stop_event.is_set():
        stop_event.wait(12)
        if stop_event.is_set():
            break
        try:
            fresh = arp_scan(interface, router_ip)
            for dev in fresh:
                ip  = dev.get("ip")
                mac = dev.get("mac", "").lower()
                if not ip or ip in known_ips:
                    continue
                if mac in safe_macs or ip in safe_ips:
                    continue
                # New unwhitelisted device — throttle it
                log.info(f"Whitelist watcher: new device detected {ip} ({mac})")
                on_new_device(dev)
                known_ips.add(ip)
        except Exception as e:
            log.warning(f"Whitelist watcher error: {e}")
