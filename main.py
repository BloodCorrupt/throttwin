#!/usr/bin/env python3
"""
Throttwin — All-in-One Windows Bandwidth Limiter
Per-device bandwidth limiting via ARP spoofing and Scapy/Npcap.

Usage:
    python main.py             # Interactive CLI
    python main.py --web       # Web UI dashboard
    python main.py -w -p 8080  # Web UI on custom port
"""

import sys
import signal
import logging
import threading
import time

from core.console import console, Table, box, Panel
from pyfiglet import figlet_format

from core import (
    check_os, check_admin, check_npcap, check_dependencies,
    pick_interface, pick_interfaces, pick_router,
    scan_devices, display_devices, pick_limit,
    enable_ip_forwarding, disable_ip_forwarding,
    setup_traffic_shaping, cleanup_traffic_shaping, add_target_shaping,
    arp_spoof_loop, get_router_mac, get_my_mac,
    verify_spoofing, live_monitor, multi_live_monitor,
    save_config, load_config, clear_saved_config,
    ask_user_action, prompt_operational_mode,
    prompt_blacklist_selection, prompt_whitelist_selection,
    prompt_session_review, match_saved_config, match_saved_whitelist,
    prompt_manage_rules, prompt_manual_device,
    device_sort_key, get_predefined_whitelist,
    ThrottwinEngine,
)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("throttwin")

stop_event = threading.Event()


def banner():
    print()
    print(figlet_format("Throttwin", font="standard").rstrip())
    console.print("  [dim]Per-device bandwidth limiter via ARP spoofing[/dim]")
    from core.core_tools import is_arp_scan_installed
    if is_arp_scan_installed():
        console.print("  [dim]Windows Edition — [bold cyan]Double-Powered by arp-scan (x64 C-Engine)[/bold cyan][/dim]")
    else:
        console.print("  [dim]Windows Edition — powered by Scapy + Npcap[/dim]")
    print()


def signal_handler(sig, frame):
    stop_event.set()


def configure_session_for_interface(iface_info, session_index=1, total_sessions=1):
    """Interactive wizard to configure session parameters for ONE network adapter."""
    interface = iface_info["name"]
    router_ip = iface_info.get("gateway") or pick_router(interface)

    if total_sessions > 1:
        console.rule(f"[bold cyan]Configuring Session {session_index}/{total_sessions}: {interface} ({iface_info['ip']} → {router_ip})[/bold cyan]")

    config = load_config(interface)
    devices = scan_devices(interface, router_ip)

    has_saved = bool(config and config.get("interface") == interface and config.get("router_ip") == router_ip)
    saved_mode = config.get("operational_mode", "blacklist") if has_saved else None

    if has_saved and saved_mode == "whitelist":
        matched_whitelisted = match_saved_whitelist(config, devices)
        matched_dev         = match_saved_config(config, devices)
        last_ips = [d["ip"] for d in (matched_whitelisted or [])]
    elif has_saved:
        matched_whitelisted = None
        matched_dev         = match_saved_config(config, devices)
        last_ips = [d["ip"] for d in (matched_dev or [])]
    else:
        matched_whitelisted = None
        matched_dev         = None
        last_ips            = []
        console.print(f" [dim]No previous session found on {interface}.[/dim]\n")

    display_devices(
        config if has_saved else None,
        matched_whitelisted if saved_mode == "whitelist" else matched_dev,
        devices,
        last_ips=last_ips
    )

    while True:
        action = ask_user_action(has_saved=has_saved)

        if action == "add_device":
            dev = prompt_manual_device(interface)
            if dev:
                mac = dev.get("mac", "").lower()
                existing_idx = None
                for idx, d in enumerate(devices):
                    if (mac and mac != "unknown" and d.get("mac", "").lower() == mac) \
                            or (dev.get("ip") and d.get("ip") == dev["ip"]):
                        existing_idx = idx
                        break
                if existing_idx is not None:
                    devices[existing_idx] = dev
                else:
                    devices.append(dev)
                devices.sort(key=device_sort_key)
            console.clear()
            console.print()
            display_devices(config if has_saved else None,
                            matched_whitelisted if saved_mode == "whitelist" else matched_dev,
                            devices, last_ips=last_ips)
            continue

        elif action == "manage_rules":
            prompt_manage_rules(devices, interface=interface)
            console.clear()
            console.print()
            display_devices(config if has_saved else None,
                            matched_whitelisted if saved_mode == "whitelist" else matched_dev,
                            devices, last_ips=last_ips)
            continue

        elif action == "clear_cache":
            clear_saved_config(interface)
            config = None
            has_saved = False
            matched_dev = None
            matched_whitelisted = None
            last_ips = []
            console.clear()
            console.print(f" [success]Saved session and cache cleared for {interface}.[/success]\n")
            devices = scan_devices(interface, router_ip)
            display_devices(None, None, devices, last_ips=[])
            continue

        elif action == "rescan":
            console.clear()
            console.print()
            devices = scan_devices(interface, router_ip, existing_devices=devices,
                                   status_msg=f"Rescanning {interface}, please wait...")
            if has_saved:
                if saved_mode == "whitelist":
                    matched_whitelisted = match_saved_whitelist(config, devices)
                    matched_dev         = match_saved_config(config, devices)
                    last_ips = [d["ip"] for d in (matched_whitelisted or [])]
                else:
                    matched_whitelisted = None
                    matched_dev = match_saved_config(config, devices)
                    last_ips = [d["ip"] for d in (matched_dev or [])]
            else:
                matched_dev = matched_whitelisted = None
                last_ips = []
            display_devices(config if has_saved else None,
                            matched_whitelisted if saved_mode == "whitelist" else matched_dev,
                            devices, last_ips=last_ips)
            continue

        else:
            break

    # ── Mode & target selection ───────────────────────────────
    used_saved = False
    if action == "use_saved":
        limit_mbps       = config["limit_mbps"]
        operational_mode = config.get("operational_mode", "blacklist")
        if operational_mode == "whitelist":
            saved_wl    = config.get("whitelisted", [])
            safe_devices = match_saved_whitelist(config, devices) or [d for d in saved_wl if isinstance(d, dict)]
            safe_macs    = {d["mac"].lower() for d in safe_devices if isinstance(d, dict) and d.get("mac")}
            safe_ips     = {d["ip"] if isinstance(d, dict) else d for d in safe_devices}
            targets_to_throttle = [
                d for d in devices
                if not ((d.get("mac") and d["mac"].lower() in safe_macs) or d.get("ip") in safe_ips)
            ]
        else:
            safe_devices = []
            targets_to_throttle = matched_dev or []
        used_saved = True

    elif action == "new_scan":
        operational_mode = prompt_operational_mode()

    if not used_saved:
        if operational_mode in ("blacklist", None):
            safe_devices = []
            targets_to_throttle = prompt_blacklist_selection(devices, matched_dev, interface=interface)
        elif operational_mode == "whitelist":
            safe_devices = prompt_whitelist_selection(devices, matched_whitelisted, interface=interface)
            safe_macs    = {d["mac"].lower() for d in safe_devices if isinstance(d, dict) and d.get("mac")}
            safe_ips     = {d["ip"] if isinstance(d, dict) else d for d in safe_devices}
            targets_to_throttle = [
                d for d in devices
                if not ((d.get("mac") and d["mac"].lower() in safe_macs) or d.get("ip") in safe_ips)
            ]
            if not targets_to_throttle:
                console.print(f" [info]All current devices on {interface} whitelisted. New devices will be throttled automatically.[/info]")

        limit_mbps = pick_limit()

    if total_sessions == 1 and not used_saved:
        prompt_session_review(interface, router_ip, operational_mode, limit_mbps, targets_to_throttle)

    return {
        "interface": interface,
        "router_ip": router_ip,
        "operational_mode": operational_mode,
        "targets": targets_to_throttle,
        "safe_devices": safe_devices,
        "limit_mbps": limit_mbps,
        "devices": devices,
        "used_saved": used_saved,
    }


def main():
    check_os()
    check_admin()
    check_npcap()
    check_dependencies()

    banner()

    # Multi-interface picker
    selected_interfaces = pick_interfaces()
    total_sessions = len(selected_interfaces)

    configured_sessions = []
    for idx, iface_info in enumerate(selected_interfaces, 1):
        sess_cfg = configure_session_for_interface(iface_info, session_index=idx, total_sessions=total_sessions)
        configured_sessions.append(sess_cfg)

    # Multi-session review table when multiple interfaces selected
    if total_sessions > 1:
        console.print()
        table = Table(box=box.ROUNDED, title="[bold white]Multi-Interface Session Review[/bold white]")
        table.add_column("Interface", style="bold cyan")
        table.add_column("Gateway", style="white")
        table.add_column("Mode", style="yellow")
        table.add_column("Targets / Safe", style="green")
        table.add_column("Limit", style="bold magenta")
        for cs in configured_sessions:
            if cs["operational_mode"] == "blacklist":
                tgt_str = f"{len(cs['targets'])} target(s)"
            else:
                tgt_str = f"{len(cs['safe_devices'])} safe (auto-trap)"
            table.add_row(
                cs["interface"],
                cs["router_ip"],
                cs["operational_mode"].title(),
                tgt_str,
                f"{cs['limit_mbps']:.1f} Mbps"
            )
        console.print(table)
        console.print()
        try:
            yn = input("  Proceed to launch all sessions? (y/n): ").strip().lower()
            if yn != "y":
                console.print(" [error]Cancelled by user.[/error]")
                sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)

    # Launch sessions via ThrottwinEngine
    engine = ThrottwinEngine()
    active_sessions = []

    with console.status("Starting session(s)...", spinner="dots"):
        for cs in configured_sessions:
            session, _ = engine.create_session(cs["interface"], cs["router_ip"])
            ok, msg = session.start_session(
                mode=cs["operational_mode"],
                targets=cs["targets"],
                limit_mbps=cs["limit_mbps"],
                whitelisted=cs["safe_devices"] if cs["operational_mode"] == "whitelist" else None
            )
            if ok:
                active_sessions.append(session)
            else:
                console.print(f" [error]Failed to start session on {cs['interface']}: {msg}[/error]")

    if not active_sessions:
        console.print(" [error]No sessions could be started.[/error]")
        sys.exit(1)

    console.print(f" [success]Started {len(active_sessions)} session(s) successfully![/success]")
    time.sleep(1)

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        multi_live_monitor(active_sessions, stop_event, session_start_time=time.monotonic())
    finally:
        with console.status("Stopping all sessions and restoring network...", spinner="dots"):
            for s in active_sessions:
                s.stop_session()
        console.print("\n [error]Session(s) terminated.[/error]")
        console.print(" [success]Network restored and traffic shaping cleared.[/success]")


def run_web_ui(host="0.0.0.0", port=5000):
    """Launch the Flask-backed Web UI dashboard."""
    from web.app import app, engine

    banner()
    console.print(f"  [bold green]●[/bold green] [bold white]Throttwin Web Dashboard[/bold white]")
    console.print(f"  [dim]• Local URL   :[/dim] [bold cyan]http://127.0.0.1:{port}[/bold cyan]")

    # Display all auto-detected sessions
    for sid, session in engine.sessions.items():
        console.print(f"  [dim]• Session     :[/dim] [white]{sid}[/white] → [cyan]{session.router_ip}[/cyan]")

    if not engine.sessions:
        console.print(f"  [dim]• Interface   :[/dim] [white]No active interfaces detected[/white]")

    console.print(f"\n  [dim]Press Ctrl+C to stop the web server.[/dim]\n")

    # Pre-scan all sessions in background
    for session in engine.sessions.values():
        threading.Thread(target=session.scan, daemon=True).start()

    # Suppress werkzeug noise
    class WerkzeugFilter(logging.Filter):
        def filter(self, record):
            msg = record.getMessage()
            return not any(x in msg for x in ["Bad request", "code 400"])

    wz = logging.getLogger("werkzeug")
    wz.addFilter(WerkzeugFilter())
    wz.setLevel(logging.ERROR)

    try:
        app.run(host=host, port=port, debug=False)
    except KeyboardInterrupt:
        console.print("\n [error]Web server stopped.[/error]")
    finally:
        # Stop all running sessions
        for session in engine.sessions.values():
            if session.status == "RUNNING":
                session.stop_session()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Throttwin — Per-device bandwidth limiter via ARP spoofing (Windows)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-w", "--web",  action="store_true", help="Launch Web UI dashboard")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Web UI port (default: 5000)")
    parser.add_argument("-H", "--host", type=str, default="0.0.0.0", help="Web UI bind host (default: 0.0.0.0)")
    parser.add_argument("--no-admin-check", action="store_true", help="Skip Administrator privilege check")

    args = parser.parse_args()

    if args.web:
        check_os()
        if not args.no_admin_check:
            check_admin()
        check_npcap()
        check_dependencies()
        run_web_ui(host=args.host, port=args.port)
    else:
        main()
