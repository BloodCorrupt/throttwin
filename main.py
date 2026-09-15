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

from core.console import console
from pyfiglet import figlet_format

from core import (
    check_os, check_admin, check_npcap, check_dependencies,
    pick_interface, pick_router,
    scan_devices, display_devices, pick_limit,
    enable_ip_forwarding, disable_ip_forwarding,
    setup_traffic_shaping, cleanup_traffic_shaping, add_target_shaping,
    arp_spoof_loop, get_router_mac, get_my_mac,
    verify_spoofing, live_monitor,
    save_config, load_config, clear_saved_config,
    ask_user_action, prompt_operational_mode,
    prompt_blacklist_selection, prompt_whitelist_selection,
    prompt_session_review, match_saved_config, match_saved_whitelist,
    prompt_manage_rules, prompt_manual_device,
    device_sort_key, get_predefined_whitelist,
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
    console.print("  [dim]Windows Edition — powered by Scapy + Npcap[/dim]")
    print()


def signal_handler(sig, frame):
    stop_event.set()


def main():
    check_os()
    check_admin()
    check_npcap()
    check_dependencies()

    banner()

    interface       = None
    router_ip       = None
    limit_mbps      = None
    used_saved      = False
    targets_to_throttle = []
    safe_devices    = []
    safe_ips        = set()
    safe_macs       = set()
    operational_mode = "blacklist"

    interface = pick_interface()
    router_ip = pick_router(interface)

    config  = load_config()
    devices = scan_devices(interface, router_ip)

    has_saved  = bool(config and config.get("interface") == interface and config.get("router_ip") == router_ip)
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
        console.print(" [dim]No previous session found on this network.[/dim]\n")

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
                    if (mac and mac != "unknown" and d.get("mac","").lower() == mac) \
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
            clear_saved_config()
            config = None
            has_saved = False
            matched_dev = None
            matched_whitelisted = None
            last_ips = []
            console.clear()
            console.print(" [success]Saved session and cache cleared.[/success]\n")
            devices = scan_devices(interface, router_ip)
            display_devices(None, None, devices, last_ips=[])
            continue

        elif action == "rescan":
            console.clear()
            console.print()
            devices = scan_devices(interface, router_ip, existing_devices=devices,
                                   status_msg="Rescanning network, please wait...")
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
            targets_to_throttle = matched_dev or []
        used_saved = True

    elif action == "new_scan":
        operational_mode = prompt_operational_mode()

    if not used_saved:
        if operational_mode in ("blacklist", None):
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
                console.print(" [info]All current devices whitelisted. New devices will be throttled automatically.[/info]")

        limit_mbps = pick_limit()

    if not used_saved:
        prompt_session_review(interface, router_ip, operational_mode, limit_mbps, targets_to_throttle)

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ── Resolve MACs ──────────────────────────────────────────
    with console.status("Resolving router MAC and local MAC...", spinner="dots"):
        router_mac = get_router_mac(router_ip, interface)
        my_mac     = get_my_mac(interface)

    if not router_mac:
        console.print(f" [error]Could not resolve router MAC for {router_ip}. Check your interface and gateway.[/error]")
        sys.exit(1)
    if not my_mac:
        console.print(" [error]Could not determine local MAC address.[/error]")
        sys.exit(1)

    spoof_threads = []
    shapers       = {}

    def on_new_device(dev):
        """Called by whitelist watcher when a new unwhitelisted device appears."""
        dev_mac = dev.get("mac", "").lower()
        dev_ip  = dev.get("ip")
        predefined_wl = set(get_predefined_whitelist().keys())
        if operational_mode == "whitelist":
            if (dev_mac and (dev_mac in safe_macs or dev_mac in predefined_wl)) or \
               (dev_ip and dev_ip in safe_ips):
                return None

        shaper = add_target_shaping(
            interface, dev_ip, dev_mac, router_ip, router_mac,
            my_mac, limit_mbps, stop_event
        )
        shapers[dev_ip] = shaper

        t = threading.Thread(
            target=arp_spoof_loop,
            args=(interface, dev_ip, dev_mac, router_ip, router_mac, my_mac, stop_event),
            daemon=True
        )
        t.start()
        spoof_threads.append(t)
        targets_to_throttle.append(dev)
        return dev_ip

    try:
        with console.status("Starting session...", spinner="dots"):
            save_config(interface, router_ip, operational_mode, targets_to_throttle, limit_mbps,
                        whitelisted=safe_devices if operational_mode == "whitelist" else None)

            enable_ip_forwarding()

            shapers = setup_traffic_shaping(
                interface, targets_to_throttle, limit_mbps,
                router_ip, router_mac, my_mac, stop_event
            )

            for tgt in targets_to_throttle:
                tgt_ip  = tgt.get("ip")  if isinstance(tgt, dict) else tgt
                tgt_mac = tgt.get("mac") if isinstance(tgt, dict) else ""
                if tgt_ip and tgt_ip != "-":
                    t = threading.Thread(
                        target=arp_spoof_loop,
                        args=(interface, tgt_ip, tgt_mac, router_ip, router_mac, my_mac, stop_event),
                        daemon=True
                    )
                    t.start()
                    spoof_threads.append(t)

            # Verify spoofing if we have targets
            if targets_to_throttle:
                first_ip = targets_to_throttle[0].get("ip") if isinstance(targets_to_throttle[0], dict) \
                           else targets_to_throttle[0]
                success = verify_spoofing(interface, first_ip, shapers, stop_event)
            else:
                success = True

        if success:
            if targets_to_throttle:
                console.print(" [success]ARP spoofing active — launching live monitor...[/success]")
            else:
                console.print(" [success]Whitelist mode active — monitoring for new devices...[/success]")
            time.sleep(1)

            monitor_thread = threading.Thread(
                target=live_monitor,
                args=(interface, targets_to_throttle, shapers, limit_mbps, stop_event),
                kwargs={
                    "router_ip":         router_ip,
                    "whitelist_devices": safe_devices if operational_mode == "whitelist" else None,
                    "on_new_device":     on_new_device if operational_mode == "whitelist" else None,
                    "session_start_time": time.monotonic(),
                },
                daemon=True
            )
            monitor_thread.start()
        else:
            console.print(" [warning]Target device not seen yet — may not be active on the network.[/warning]")
            console.print(" [dim]Running anyway. Press Ctrl+C to stop.[/dim]")

            monitor_thread = threading.Thread(
                target=live_monitor,
                args=(interface, targets_to_throttle, shapers, limit_mbps, stop_event),
                kwargs={"session_start_time": time.monotonic()},
                daemon=True
            )
            monitor_thread.start()

        try:
            while not stop_event.is_set():
                stop_event.wait(0.2)
        except KeyboardInterrupt:
            stop_event.set()

        if "monitor_thread" in dir():
            monitor_thread.join(timeout=2)

    finally:
        with console.status("Stopping session and restoring network...", spinner="dots"):
            for t in spoof_threads:
                t.join(timeout=4)
            cleanup_traffic_shaping(shapers)
            disable_ip_forwarding()

        console.print("\n [error]Session terminated.[/error]")
        console.print(" [success]Network restored and traffic rules cleared.[/success]")


def run_web_ui(host="0.0.0.0", port=5000):
    """Launch the Flask-backed Web UI dashboard."""
    from web.app import app, engine

    banner()
    console.print(f"  [bold green]●[/bold green] [bold white]Throttwin Web Dashboard[/bold white]")
    console.print(f"  [dim]• Local URL   :[/dim] [bold cyan]http://127.0.0.1:{port}[/bold cyan]")
    if host == "0.0.0.0":
        console.print(f"  [dim]• Network URL :[/dim] [bold cyan]http://{engine.current_router_ip}:{port}[/bold cyan]")
    console.print(f"  [dim]• Interface   :[/dim] [white]{engine.current_interface or 'Auto-detecting'}[/white]")
    console.print(f"  [dim]• Gateway     :[/dim] [white]{engine.current_router_ip or 'Auto-detecting'}[/white]\n")
    console.print("  [dim]Press Ctrl+C to stop the web server.[/dim]\n")

    # Pre-scan in background
    threading.Thread(target=engine.scan, daemon=True).start()

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
        engine.stop_session()


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
