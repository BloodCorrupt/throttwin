import re
import sys
import ctypes
import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import psutil

from .console import console, questionary, qselect

log = logging.getLogger("throttwin")

# Win32 SendARP API binding
_send_arp_fn = None
try:
    _send_arp_fn = ctypes.windll.iphlpapi.SendARP
except Exception:
    _send_arp_fn = None


def win_send_arp(ip):
    """
    Direct Windows kernel-level ARP query via iphlpapi.dll -> SendARP.
    Returns lowercase MAC string (e.g. 'aa:bb:cc:dd:ee:ff') or None if unreachable.
    Fast, reliable, works with or without Npcap, and bypasses driver/firewall issues.
    """
    if not _send_arp_fn or not ip or ip in ("-", "Unknown", "0.0.0.0"):
        return None
    try:
        dst = socket.inet_aton(ip)
        dst_ulong = ctypes.c_ulong(int.from_bytes(dst, byteorder="little"))
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = _send_arp_fn(dst_ulong, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0:
            mac_str = ":".join(f"{b:02x}" for b in mac_buf)
            if mac_str not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                return mac_str
    except Exception:
        pass
    return None


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def get_interface_ip_and_mac(iface_name):
    """
    Get IPv4 and MAC for a given interface name.
    """
    addrs = psutil.net_if_addrs().get(iface_name, [])
    ip = None
    mac = None
    for a in addrs:
        if a.family.name == "AF_INET" and not a.address.startswith("169.254") and a.address != "127.0.0.1":
            ip = a.address
        elif a.family.name in ("AF_LINK", "AF_PACKET") and a.address:
            mac = a.address.lower().replace("-", ":")
    return ip, mac


def get_active_interfaces():
    """
    Return list of active network interfaces with real IPv4 and MAC addresses.
    Filters out loopback, virtual/VPN adapters, and link-local-only interfaces.
    Prioritizes the interface that has the active default gateway route.
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    # Get descriptions from Scapy working ifaces if available
    desc_map = {}
    try:
        from scapy.all import get_working_ifaces
        for w in get_working_ifaces():
            desc_map[w.name] = (w.description or "").lower()
    except Exception:
        pass

    # Prefixes/keywords to skip
    SKIP_KEYWORDS = [
        "loopback", "pseudo", "wan miniport", "bluetooth",
        "tailscale", "openvpn", "wiresock", "tap-windows",
        "virtualbox", "vmware", "hyper-v", "wsl", "vnic",
        "direct virtual", "mobile broadband"
    ]

    gw_ip = get_default_gateway()

    for iface_name, stat in stats.items():
        if not stat.isup or iface_name not in addrs:
            continue

        lower_name = iface_name.lower()
        desc = desc_map.get(iface_name, "")
        combined = f"{lower_name} {desc}"

        if any(skip in combined for skip in SKIP_KEYWORDS):
            continue

        ipv4 = [
            a.address for a in addrs[iface_name]
            if a.family.name == "AF_INET"
            and not a.address.startswith("169.254")   # Skip link-local
            and a.address != "127.0.0.1"
        ]

        AF_LINK = None
        for family in addrs[iface_name]:
            if family.family.name in ("AF_LINK", "AF_PACKET") and family.address:
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

    # Sort so that the interface matching the default gateway subnet comes first
    def _iface_priority(item):
        iface_ip = item["ip"]
        if gw_ip:
            # Check if gateway IP starts with same /24 prefix
            gw_prefix = ".".join(gw_ip.split(".")[:3])
            if iface_ip.startswith(gw_prefix):
                return 0
        return 1

    interfaces.sort(key=_iface_priority)
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
        route = conf.route.route("0.0.0.0")
        if route and route[2] and route[2] != "0.0.0.0":
            return route[2]
    except Exception:
        pass

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


def resolve_hostname(ip, timeout=0.25):
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
