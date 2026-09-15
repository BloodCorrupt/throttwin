import re
import sys
import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import psutil

from .console import console, questionary, qselect

log = logging.getLogger("throttwin")


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def get_active_interfaces():
    """
    Return list of active network interfaces with real IPv4 and MAC addresses.
    Filters out loopback, virtual/VPN adapters, and link-local-only interfaces.
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    # Prefixes/keywords to skip
    SKIP_NAMES = [
        "loopback", "pseudo", "wan miniport", "bluetooth",
        "tailscale", "openvpn", "wiresock", "tap-windows",
        "virtual", "direct virtual", "mobile broadband"
    ]

    for iface_name, stat in stats.items():
        if not stat.isup or iface_name not in addrs:
            continue

        lower_name = iface_name.lower()
        if any(skip in lower_name for skip in SKIP_NAMES):
            continue

        ipv4 = [
            a.address for a in addrs[iface_name]
            if a.family.name == "AF_INET"
            and not a.address.startswith("169.254")   # Skip link-local
            and a.address != "127.0.0.1"
        ]

        import psutil as _psutil
        AF_LINK = None
        for family in _psutil.net_if_addrs().get(iface_name, []):
            if family.family.name in ("AF_LINK", "AF_PACKET"):
                AF_LINK = family.address
                break

        if not ipv4 or not AF_LINK:
            continue

        # Clean up Windows MAC format (xx-xx-xx -> xx:xx:xx)
        mac_clean = AF_LINK.lower().replace("-", ":")

        interfaces.append({
            "name": iface_name,
            "ip":   ipv4[0],
            "mac":  mac_clean,
        })

    return interfaces


def get_scapy_interface(friendly_name):
    """
    Map a friendly interface name (e.g. 'Wi-Fi') to a Scapy NPF network_name.
    """
    try:
        from scapy.all import get_working_ifaces
        for iface in get_working_ifaces():
            if iface.name == friendly_name or iface.description == friendly_name:
                return iface.network_name
    except Exception:
        pass
    return friendly_name


def get_default_gateway(interface=None):
    """
    Detect the default gateway IP using Windows routing table via Scapy.
    Falls back to parsing `route print` output.
    """
    try:
        from scapy.all import conf
        # conf.route.route('0.0.0.0') returns (iface, src_ip, gw_ip)
        route = conf.route.route("0.0.0.0")
        if route and route[2] and route[2] != "0.0.0.0":
            return route[2]
    except Exception:
        pass

    # Fallback: parse `route print` output
    try:
        result = run("route print 0.0.0.0")
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass

    return None


def get_gateways():
    """
    Return list of {ip, interface} dicts for each detected default gateway.
    """
    gateways = []
    try:
        result = run("route print 0.0.0.0")
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw_ip = parts[2]
                if gw_ip and gw_ip != "0.0.0.0":
                    gateways.append({"ip": gw_ip})
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for g in gateways:
        if g["ip"] not in seen:
            seen.add(g["ip"])
            unique.append(g)
    return unique


def resolve_mac_from_arp_cache(ip):
    """
    Resolve MAC address for an IP from Windows ARP table.
    Returns MAC string or '' if not found.
    """
    try:
        result = run(f"arp -a {ip}")
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == ip:
                mac = parts[1].replace("-", ":").lower()
                if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                    return mac
    except Exception:
        pass
    return ""


def resolve_hostname(ip, timeout=0.4):
    """Lightweight reverse DNS hostname resolution."""
    if not ip or ip == "-":
        return ""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(old)
        if host and host != ip:
            return host.split(".")[0]
    except Exception:
        pass
    return ""


def get_interfaces():
    """Return list of friendly interface name strings."""
    return [i["name"] for i in get_active_interfaces()]


def pick_interface():
    """Interactive interface picker. Auto-selects if only one found."""
    interfaces = get_active_interfaces()

    if not interfaces:
        console.print(" [error]No active network interfaces found.[/error]")
        sys.exit(1)

    console.print(f" [success]Found {len(interfaces)} active interface(s)[/success]")

    if len(interfaces) == 1:
        iface = interfaces[0]
        console.print(f" [text]Auto-selected interface: {iface['name']} ({iface['ip']})[/text]")
        return iface["name"]

    choices = []
    for iface in interfaces:
        display = f"{iface['name']:<22} {iface['ip']:<16} {iface['mac']}"
        choices.append(questionary.Choice(title=display, value=iface["name"]))

    selected = qselect("Select network interface:", choices=choices)
    if selected is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)

    selected_iface = next(i for i in interfaces if i["name"] == selected)
    console.print(f" [text]Selected interface: {selected_iface['name']} ({selected_iface['ip']})[/text]")
    return selected


def pick_router(interface):
    """Interactive gateway picker. Auto-selects if only one found."""
    gateways = get_gateways()

    if not gateways:
        console.print(" [error]No gateway detected. Make sure you're connected to a network.[/error]")
        sys.exit(1)

    if len(gateways) == 1:
        gw = gateways[0]["ip"]
        console.print(f" [text]Auto-selected gateway: {gw}[/text]")
        return gw

    choices = []
    for gw in gateways:
        choices.append(questionary.Choice(title=gw["ip"], value=gw["ip"]))

    selected = qselect("Select gateway router:", choices=choices)
    if selected is None:
        console.print(" [error]Cancelled by user.[/error]")
        sys.exit(0)

    console.print(f" [text]Selected gateway: {selected}[/text]")
    return selected
