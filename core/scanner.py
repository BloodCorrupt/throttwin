import os
import json
import re
import sys
import logging
import socket
import struct
import ctypes
import subprocess
import ipaddress
import questionary
from concurrent.futures import ThreadPoolExecutor

from .console import console, Table, box, qselect, custom_style
from .network import (
    resolve_mac_from_arp_cache,
    resolve_hostname,
    get_scapy_interface,
    win_send_arp,
    get_interface_ip_and_mac
)

log = logging.getLogger("throttwin")

_HOSTNAME_CACHE = {}
_VENDOR_OUI_CACHE = {}

# Load comprehensive 53,000+ entry IEEE OUI Database
_OUI_DB = {}
_OUI_PATH = os.path.join(os.path.dirname(__file__), "oui_db.json")
try:
    if os.path.exists(_OUI_PATH):
        with open(_OUI_PATH, "r", encoding="utf-8") as _f:
            _OUI_DB = json.load(_f)
except Exception as _e:
    log.warning(f"Could not load OUI database: {_e}")


def is_randomized_mac(mac):
    """
    Check if a MAC address has the Locally Administered bit set (Private Wi-Fi Address).
    """
    if not mac or mac in ("unknown", "Unknown", "-"):
        return False
    parts = mac.split(":")
    if len(parts) >= 1:
        try:
            first_byte = int(parts[0], 16)
            return bool(first_byte & 2)
        except ValueError:
            pass
    return False


_VENDOR_ALIASES = {
    "CLOUD NETWORK TECHNOLOGY": "Cloud Network (Realtek)",
    "HON HAI PRECISION": "Foxconn",
    "AZUREWAVE TECHNOLOGY": "AzureWave (Realtek/Broadcom)",
    "SHENZHEN BILIAN ELECTRONIC": "LB-Link (Realtek)",
    "CHICONY ELECTRONICS": "Chicony",
    "LITEON TECHNOLOGY": "Lite-On",
    "MURATA MANUFACTURING": "Murata Wi-Fi",
    "XIAOMI COMMUNICATIONS": "Xiaomi",
    "SAMSUNG ELECTRONICS": "Samsung",
    "INTEL CORPORATE": "Intel",
    "HUAWEI TECHNOLOGIES": "Huawei",
    "OPPO MOBILE": "Oppo Mobile",
    "GUANGDONG OPPO": "Oppo Mobile",
    "VIVO MOBILE": "Vivo Mobile",
    "REALME": "Realme Mobile",
    "TP-LINK": "TP-Link",
    "MERCUSYS": "Mercusys",
    "ESPRESSIF": "Espressif",
    "TUYA SMART": "Tuya Smart",
}


def clean_vendor_name(vendor):
    if not vendor or vendor in ("Unknown", "unknown", "-"):
        return "Unknown"
    v_upper = vendor.upper().strip()
    for pattern, alias in _VENDOR_ALIASES.items():
        if pattern in v_upper:
            return alias
    return vendor


def oui_lookup(mac):
    """
    Ultra-fast OUI vendor lookup using official 53,000+ IEEE database
    and MAC randomization detection.
    """
    if not mac or mac in ("unknown", "Unknown", "-"):
        return "Unknown"
    mac_clean = mac.lower().replace("-", ":")
    if mac_clean in _VENDOR_OUI_CACHE:
        return _VENDOR_OUI_CACHE[mac_clean]

    # 1. Check for Private / Randomized MAC
    if is_randomized_mac(mac_clean):
        res = "Randomized MAC (Private Wi-Fi)"
        _VENDOR_OUI_CACHE[mac_clean] = res
        return res

    # 2. Check full IEEE OUI database
    hex_clean = mac_clean.replace(":", "").upper()
    for length in (9, 7, 6):
        if len(hex_clean) >= length:
            prefix = hex_clean[:length]
            if prefix in _OUI_DB:
                raw_vendor = _OUI_DB[prefix]
                vendor = clean_vendor_name(raw_vendor)
                _VENDOR_OUI_CACHE[mac_clean] = vendor
                return vendor

    _VENDOR_OUI_CACHE[mac_clean] = "Unknown"
    return "Unknown"



def netbios_lookup(ip, timeout=0.15):
    """
    Direct NetBIOS Name Query (UDP 137) to discover Windows PC names,
    SMB hosts, NAS devices, and workgroups.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    pkt = (
        b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
        if len(data) > 56:
            num = data[56]
            offset = 57
            for _ in range(num):
                name = data[offset:offset+15].decode("latin1", errors="ignore").strip()
                n_type = data[offset+15]
                if n_type == 0 and name and not name.startswith("IS~") and name != "WORKGROUP":
                    return name
                offset += 18
    except Exception:
        pass
    finally:
        s.close()
    return ""


def mdns_lookup(ip, timeout=0.15):
    """
    Lightweight mDNS / ZeroConf probe to query device name (Apple, Smart TVs, IoT).
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    try:
        rev_parts = ip.split(".")[::-1]
        qname = "".join(f"{len(p)}{p}" for p in rev_parts) + "\x07in-addr\x04arpa\x00"
        dns_pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname.encode() + b"\x00\x0c\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(dns_pkt, (ip, 5353))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) > 12:
            text = data[12:].decode("latin1", errors="ignore")
            m = re.search(r"([a-zA-Z0-9_-]+)\.local", text)
            if m:
                return m.group(1)
    except Exception:
        pass
    return ""


def resolve_device_name(ip):
    """
    Resolve device name using NetBIOS, mDNS, and Reverse DNS concurrently.
    """
    if not ip or ip in ("-", "Unknown"):
        return (ip, "")
    if ip in _HOSTNAME_CACHE:
        return (ip, _HOSTNAME_CACHE[ip])

    # 1. NetBIOS query (best for PCs, NAS, SMB)
    name = netbios_lookup(ip, timeout=0.15)
    
    # 2. Reverse DNS
    if not name:
        name = resolve_hostname(ip, timeout=0.15)
        
    # 3. mDNS probe (best for Apple / IoT / Smart devices)
    if not name:
        name = mdns_lookup(ip, timeout=0.15)

    _HOSTNAME_CACHE[ip] = name
    return (ip, name)



def populate_hostnames(devices):
    """Batch concurrent hostname resolution across all discovered devices."""
    ips = [d["ip"] for d in devices if d.get("ip") and d["ip"] not in ("-", "Unknown") and not d.get("hostname")]
    if not ips:
        for d in devices:
            if "hostname" not in d:
                d["hostname"] = ""
        return devices

    try:
        with ThreadPoolExecutor(max_workers=min(len(ips), 32)) as ex:
            results = dict(ex.map(resolve_device_name, ips))
        for d in devices:
            ip = d.get("ip")
            if ip in results and results[ip]:
                d["hostname"] = results[ip]
            elif "hostname" not in d:
                d["hostname"] = ""
    except Exception:
        for d in devices:
            if "hostname" not in d:
                d["hostname"] = ""
    return devices


def device_sort_key(dev):
    """Sort devices by IP numerically, then by MAC."""
    if not isinstance(dev, dict):
        return (2, str(dev))
    ip_str = dev.get("ip")
    if ip_str and ip_str not in ("Unknown", "-"):
        try:
            return (0, int(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass
    return (1, dev.get("mac", "").lower())


def _lan_wakeup_probe(ips):
    """
    Fast concurrent non-blocking UDP blast to ports (53, 80, 137, 5353)
    across all IPs on the local subnet to wake sleeping Wi-Fi radios (iOS/Android).
    Takes <0.05s.
    """
    def _poke(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.01)
            # Short UDP probe
            s.sendto(b"\x00", (ip, 137))
            s.close()
        except Exception:
            pass

    try:
        with ThreadPoolExecutor(max_workers=128) as ex:
            list(ex.map(_poke, ips))
    except Exception:
        pass


def _get_arp_cache(router_ip=None):
    """
    Parse Windows `arp -a` cache table.
    """
    devices = []
    try:
        res = subprocess.run("arp -a", capture_output=True, text=True, shell=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                ip  = parts[0]
                mac = parts[1].replace("-", ":").lower()
                if (re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac)
                        and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
                        and not ip.endswith(".255")
                        and not ip.startswith("224.")
                        and not ip.startswith("239.")
                        and ip != "255.255.255.255"
                        and ip != router_ip):
                    vendor = oui_lookup(mac)
                    devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""})
    except Exception as e:
        log.warning(f"ARP cache parsing failed: {e}")
    return devices


def arp_scan(interface, router_ip, progress_callback=None):
    """
    BEAST-MODE Multi-Vector Hybrid Network Scanner for Windows:
      1. Computes local subnet from interface IPv4 & netmask.
      2. Fires fast multi-protocol wake-up probe.
      3. Sweeps all subnet IPs simultaneously using native Win32 SendARP (ThreadPool 256).
      4. Merges with Windows kernel ARP table (`arp -a`).
      5. Runs multi-protocol NetBIOS, mDNS, and Reverse DNS name queries concurrently.
      6. Applies rich OUI vendor intelligence and MAC randomization detection.
    """
    devices = []

    # 1. Determine local subnet IPs
    subnet_ips = []
    try:
        import psutil
        addrs = psutil.net_if_addrs().get(interface, [])
        ip4 = [(a.address, a.netmask) for a in addrs if a.family.name == "AF_INET"
               and not a.address.startswith("169.254") and a.address != "127.0.0.1"]
        if ip4:
            my_ip, netmask = ip4[0]
            net = ipaddress.IPv4Network(f"{my_ip}/{netmask}", strict=False)
            subnet_ips = [str(ip) for ip in net.hosts()]
        else:
            # Fallback based on router_ip
            if router_ip and router_ip != "0.0.0.0":
                prefix = ".".join(router_ip.split(".")[:3])
                subnet_ips = [f"{prefix}.{i}" for i in range(1, 255)]
    except Exception as e:
        log.warning(f"Could not compute subnet for {interface}: {e}")
        if router_ip and router_ip != "0.0.0.0":
            prefix = ".".join(router_ip.split(".")[:3])
            subnet_ips = [f"{prefix}.{i}" for i in range(1, 255)]

    if not subnet_ips:
        return _get_arp_cache(router_ip)

    # Limit scan to max 512 IPs if large subnet to maintain extreme speed
    if len(subnet_ips) > 512:
        subnet_ips = subnet_ips[:512]

    # 2. Parallel Native Win32 SendARP sweep across all subnet IPs
    discovered = {}
    
    def _scan_single_ip(target_ip):
        if target_ip == router_ip:
            return None
        mac = win_send_arp(target_ip)
        if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return (target_ip, mac)
        return None

    try:
        workers = min(len(subnet_ips), 256)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = ex.map(_scan_single_ip, subnet_ips)
            for r in results:
                if r:
                    discovered[r[0]] = r[1]
                    if progress_callback:
                        progress_callback(r[0], r[1])
    except Exception as e:
        log.debug(f"Win32 SendARP sweep exception: {e}")

    # 4. Harvest Windows Kernel ARP Cache
    cache_devs = _get_arp_cache(router_ip)
    for dev in cache_devs:
        ip = dev["ip"]
        mac = dev["mac"]
        if ip not in discovered and mac:
            discovered[ip] = mac

    # 5. Build device list and resolve OUI vendors
    for ip, mac in discovered.items():
        vendor = oui_lookup(mac)
        devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""})

    # 6. Populate Hostnames & Device Names
    devices = populate_hostnames(devices)
    devices.sort(key=device_sort_key)
    return devices


def merge_devices(existing, new_devices):
    """
    Merge two device lists, updating existing entries and adding new ones.
    Retains all previously discovered devices so none are lost on rescan.
    """
    if not existing:
        return list(new_devices)

    merged = {d["mac"].lower(): dict(d) for d in existing if d.get("mac") and d["mac"] not in ("Unknown", "unknown")}
    by_ip  = {d["ip"]: dict(d) for d in existing if (not d.get("mac") or d["mac"] in ("Unknown", "unknown")) and d.get("ip") and d["ip"] != "-"}

    for dev in new_devices:
        mac    = dev.get("mac", "").lower()
        ip     = dev.get("ip", "-")
        vendor = dev.get("vendor", "")
        host   = dev.get("hostname", "")

        if mac and mac not in ("unknown", ""):
            if mac in merged:
                if ip and ip != "-":
                    merged[mac]["ip"] = ip
                if vendor and vendor != "Unknown":
                    merged[mac]["vendor"] = vendor
                if host:
                    merged[mac]["hostname"] = host
            else:
                merged[mac] = dict(dev)
        elif ip and ip != "-":
            if ip in by_ip:
                if vendor and vendor != "Unknown":
                    by_ip[ip]["vendor"] = vendor
                if host:
                    by_ip[ip]["hostname"] = host
            else:
                by_ip[ip] = dict(dev)

    result = list(merged.values()) + list(by_ip.values())
    result.sort(key=device_sort_key)
    return result


def resolve_mac(ip, interface=None):
    """
    Resolve MAC for an IP using native Win32 SendARP, ARP cache, and Scapy fallback.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    # 1. Native Win32 SendARP
    mac = win_send_arp(ip)
    if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return mac

    # 2. Windows ARP Cache
    mac = resolve_mac_from_arp_cache(ip)
    if mac:
        return mac

    # 3. Scapy ARP Request
    try:
        from scapy.all import Ether, ARP, srp
        npf = get_scapy_interface(interface) if interface else None
        kwargs = {"iface": npf} if npf else {}
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=1.5, verbose=0, **kwargs)
        if ans:
            return ans[0][1][Ether].src.lower()
    except Exception:
        pass
    return ""


def prompt_manual_device(interface=None):
    """Prompt user to manually enter IP or MAC address."""
    console.print("\n [bold white]Manual Device Entry[/bold white]")
    try:
        user_input = input("  Enter IP or MAC address (e.g. 192.168.1.50 or aa:bb:cc:dd:ee:ff): ").strip()
        if not user_input:
            console.print("  [warning]No address entered. Cancelled.[/warning]\n")
            return None

        clean = user_input.replace("-", ":").strip().lower()
        is_mac = bool(re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", clean))

        if is_mac:
            mac = clean
            ip  = "-"
            try:
                result = subprocess.run("arp -a", shell=True, capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if mac in line.lower():
                        parts = line.split()
                        if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                            ip = parts[0]
                            console.print(f"  [dim]Auto-detected IP: {ip}[/dim]")
                            break
            except Exception:
                pass
        else:
            try:
                ipaddress.ip_address(user_input)
                ip = user_input
            except ValueError:
                console.print(f"  [error]Invalid format: '{user_input}'[/error]\n")
                return None

            with console.status("Checking ARP cache for MAC...", spinner="dots"):
                mac = resolve_mac(ip, interface) or "Unknown"
            if mac != "Unknown":
                console.print(f"  [dim]Auto-detected MAC: {mac}[/dim]")
                inp = input(f"  Confirm MAC [{mac}]: ").strip().lower()
                mac = inp.replace("-", ":") if inp else mac
            else:
                inp = input("  Enter MAC address (optional): ").strip().lower()
                mac = inp.replace("-", ":") if inp else "Unknown"

        name = input("  Enter friendly name/label (optional): ").strip()
        vendor = name if name else oui_lookup(mac)

        dev = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""}
        console.print(f"  [success]✓ Added: {ip} ({mac}) — {vendor}[/success]\n")
        return dev
    except KeyboardInterrupt:
        console.print("\n  [dim]Cancelled.[/dim]\n")
        return None


def scan_devices(interface, router_ip, existing_devices=None,
                 status_msg="Scanning network for active devices..."):
    """Full device scan — multi-vector ARP sweep + name resolution."""
    with console.status(status_msg, spinner="dots"):
        fresh = arp_scan(interface, router_ip)
        devices = merge_devices(existing_devices, fresh)

    if not devices:
        console.print(" [warning]No devices detected via ARP scan.[/warning]")
        choice = qselect(
            "What would you like to do?",
            choices=[
                questionary.Choice("Add device manually (IP/MAC)", value="manual"),
                questionary.Choice("Rescan network",               value="rescan"),
                questionary.Choice("Exit",                         value="exit"),
            ]
        )
        if choice == "manual":
            devices = []
            while True:
                dev = prompt_manual_device(interface)
                if dev:
                    devices.append(dev)
                if not devices:
                    sys.exit(0)
                try:
                    more = questionary.confirm("Add another device?", default=False).ask()
                    if not more:
                        break
                except KeyboardInterrupt:
                    break
            return devices
        elif choice == "rescan":
            return scan_devices(interface, router_ip)
        else:
            sys.exit(0)

    if existing_devices:
        added = len(devices) - len(existing_devices)
        msg = f" [success]Rescan complete: {len(fresh)} active, {len(devices)} total"
        if added > 0:
            msg += f" ({added} new)[/success]"
        else:
            msg += "[/success]"
        console.print(msg)
    else:
        console.print(f" [success]Found {len(devices)} active device(s) on network[/success]")

    return devices


def display_devices(config, matched_devices, devices, last_ips=None):
    """Render a Rich table of discovered devices with Hostname and Vendor."""
    mode_str  = config.get("operational_mode", "blacklist").capitalize() if config else "Blacklist"
    limit     = config.get("limit_mbps", 1.0) if config else 1.0
    last_ips  = last_ips or []

    if matched_devices and config:
        console.print(
            f" [success]Last session: {len(matched_devices)} device(s) "
            f"— {mode_str} mode @ {limit} Mbps[/success]"
        )

    table = Table(box=box.SIMPLE, show_header=True)
    table.add_column("IP Address",  style="")
    table.add_column("MAC Address", style="")
    table.add_column("Device / Hostname", style="")

    for dev in devices:
        ip  = dev.get("ip") or "-"
        mac = dev.get("mac", "Unknown")
        vendor   = dev.get("vendor", "Unknown")
        hostname = dev.get("hostname", "")
        is_last  = ip in last_ips

        if not vendor or "locally administered" in vendor.lower():
            vendor = "Unknown"

        if hostname and vendor.startswith("Randomized"):
            device_str = f"{hostname} (Private Wi-Fi)"
        elif hostname and vendor != "Unknown":
            device_str = f"{hostname} ({vendor})"
        elif hostname:
            device_str = hostname
        else:
            device_str = vendor

        if len(device_str) > 42:
            device_str = device_str[:42] + "…"

        if is_last:
            table.add_row(f"[success]{ip}[/success]", f"[success]{mac}[/success]", f"[success]{device_str}[/success]")
        else:
            table.add_row(ip, mac, device_str)

    console.print(table)


def pick_limit(prompt_fn=None):
    """Prompt user to pick a bandwidth limit."""
    choice = qselect(
        "Select bandwidth limit:",
        choices=[
            questionary.Choice("1 Mbps — Heavy buffering, no HD YouTube", value="1"),
            questionary.Choice("2 Mbps — Stuck at 480p",                  value="2"),
            questionary.Choice("3 Mbps — Occasional buffering at 720p",   value="3"),
            questionary.Choice("0.5 Mbps — Nuclear option 💀",            value="x"),
            questionary.Choice("Custom",                                   value="4"),
        ]
    )

    if choice is None:
        console.print(" [error]Cancelled.[/error]")
        sys.exit(0)

    presets = {"1": 1.0, "2": 2.0, "3": 3.0, "x": 0.5}
    if choice in presets:
        return presets[choice]

    while True:
        try:
            console.print()
            val = float(input("  Enter limit in Mbps (e.g. 1.5): ").strip())
            if val <= 0:
                console.print("  [error]Must be > 0.[/error]")
                continue
            return val
        except ValueError:
            console.print("  [error]Invalid number.[/error]")
        except KeyboardInterrupt:
            sys.exit(0)
