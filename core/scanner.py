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
from .core_tools import is_arp_scan_installed, run_arp_scan_native

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
    Supercharged concurrent non-blocking multi-port UDP wake burst
    across ports (137, 5353, 5355, 1900, 53, 80, 443, 8080) to wake sleeping Wi-Fi radios
    (iOS/Android/IoT/Smart TVs) instantaneously before ARP sweep.
    Takes <0.05s.
    """
    if not ips:
        return

    WAKE_PORTS = (137, 5353, 5355, 1900, 53, 80, 443, 8080)

    def _poke(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.005)
            for port in WAKE_PORTS:
                try:
                    s.sendto(b"\x00", (ip, port))
                except Exception:
                    pass
            s.close()
        except Exception:
            pass

    try:
        from .logger import log_packet
        log_packet("PROBE", "UDP", "0.0.0.0", "255.255.255.255", length=1,
                   details=f"LAN Wi-Fi wake burst ({len(ips)} targets, 8 ports: 137, 5353, 5355, 1900, 53, 80, 443, 8080)")
        workers = min(len(ips), 128)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_poke, ips))
    except Exception:
        pass


def _get_arp_cache(interface_ip=None, subnet_net=None, router_ip=None, my_mac=None, router_mac=None):
    """
    Parse Windows `arp -a` cache table, strictly scoped to the interface and subnet.
    """
    devices = []
    my_mac_clean = (my_mac or "").lower().replace("-", ":")
    router_mac_clean = (router_mac or "").lower().replace("-", ":")

    from .network import get_all_local_ips_and_macs
    all_host_ips, all_host_macs = get_all_local_ips_and_macs()
    all_host_macs_clean = {m.lower().replace("-", ":") for m in all_host_macs}

    try:
        cmd = f"arp -a -N {interface_ip}" if interface_ip else "arp -a"
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        current_iface_ip = None
        for line in res.stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith("Interface:"):
                m = re.search(r"Interface:\s*(\d+\.\d+\.\d+\.\d+)", line_str)
                if m:
                    current_iface_ip = m.group(1)
                continue

            # If interface_ip is known and output has multiple interfaces, enforce matching section
            if interface_ip and current_iface_ip and current_iface_ip != interface_ip:
                continue

            parts = line_str.split()
            if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                ip  = parts[0]
                mac = parts[1].replace("-", ":").lower()
                if (re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac)
                        and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
                        and not ip.endswith(".255")
                        and not ip.startswith("224.")
                        and not ip.startswith("239.")
                        and not ip.startswith("127.")
                        and not ip.startswith("169.254.")
                        and ip != "255.255.255.255"
                        and ip != router_ip
                        and (not router_mac_clean or mac != router_mac_clean)):
                    if subnet_net:
                        try:
                            if ipaddress.ip_address(ip) not in subnet_net:
                                continue
                        except Exception:
                            continue
                    vendor = oui_lookup(mac)
                    devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""})
    except Exception as e:
        log.warning(f"ARP cache parsing failed: {e}")
    return devices


def arp_scan(interface, router_ip, aggressive=True, progress_callback=None):
    """
    DOUBLE-POWER Multi-Vector & Aggressive Network Scanner for Windows:
      1. Computes local subnet from interface IPv4 & netmask.
      2. Supercharged Multi-Port Wakeup Probe (UDP 137/5353/53/80/443/8080) to wake sleeping devices.
      3. Native C-Engine (arp-scan.exe) sweep when available (QbsuranAlang/arp-scan-windows-).
      4. Parallel Win32 SendARP sweep bound to interface.
      5. Merges with Windows kernel ARP table (`arp -a -N interface_ip`) strictly for this subnet.
      6. Multi-protocol concurrent NetBIOS, mDNS, and Reverse DNS name queries.
      7. Rich IEEE OUI vendor database + randomized MAC detection.
    """
    devices = []

    # 1. Determine local subnet IPs & interface IP and MAC
    subnet_ips = []
    subnet_net = None
    my_ip = None
    my_mac = None
    router_mac = None

    try:
        my_ip, my_mac = get_interface_ip_and_mac(interface)
        if my_mac:
            my_mac = my_mac.lower().replace("-", ":")
        if router_ip and router_ip != "0.0.0.0":
            router_mac = resolve_mac_from_arp_cache(router_ip, interface_ip=my_ip)
            if router_mac:
                router_mac = router_mac.lower().replace("-", ":")

        import psutil
        addrs = psutil.net_if_addrs().get(interface, [])
        ip4 = [(a.address, a.netmask) for a in addrs if a.family.name == "AF_INET"
               and not a.address.startswith("169.254") and a.address != "127.0.0.1"]
        if ip4:
            my_ip, netmask = ip4[0]
            subnet_net = ipaddress.IPv4Network(f"{my_ip}/{netmask}", strict=False)
            subnet_ips = [str(ip) for ip in subnet_net.hosts()]
        else:
            # Fallback based on router_ip
            if router_ip and router_ip != "0.0.0.0":
                subnet_net = ipaddress.IPv4Network(f"{router_ip}/24", strict=False)
                subnet_ips = [str(ip) for ip in subnet_net.hosts()]
    except Exception as e:
        log.warning(f"Could not compute subnet for {interface}: {e}")
        if router_ip and router_ip != "0.0.0.0":
            subnet_net = ipaddress.IPv4Network(f"{router_ip}/24", strict=False)
            subnet_ips = [str(ip) for ip in subnet_net.hosts()]

    if not subnet_ips:
        return _get_arp_cache(interface_ip=my_ip, subnet_net=subnet_net, router_ip=router_ip, my_mac=my_mac, router_mac=router_mac)

    # Limit scan to max 512 IPs if large subnet to maintain extreme speed
    if len(subnet_ips) > 512:
        subnet_ips = subnet_ips[:512]

    # 2. Wake sleeping Wi-Fi radios immediately
    _lan_wakeup_probe(subnet_ips)

    discovered = {}

    # 3. Native C-Engine Sweep (arp-scan.exe) if installed and aggressive mode active
    has_native_c = is_arp_scan_installed()
    if aggressive and has_native_c and subnet_net:
        try:
            # Build CIDR representation: e.g. 192.168.1.1/24 or router_ip/prefixlen
            scan_target = f"{router_ip or my_ip}/{subnet_net.prefixlen}"
            native_results = run_arp_scan_native(scan_target, timeout=5.0)
            for item in native_results:
                t_ip = item["ip"]
                t_mac = item["mac"].lower().replace("-", ":")
                if t_ip != router_ip and t_ip != my_ip:
                    if (not my_mac or t_mac != my_mac) and (not router_mac or t_mac != router_mac):
                        discovered[t_ip] = t_mac
                        if progress_callback:
                            progress_callback(t_ip, t_mac)
        except Exception as e:
            log.debug(f"Native arp-scan.exe sweep error: {e}")

    # 4. Parallel Native Win32 SendARP sweep across all subnet IPs bound to this adapter
    def _scan_single_ip(target_ip):
        if target_ip == router_ip or target_ip == my_ip:
            return None
        mac = win_send_arp(target_ip, src_ip=my_ip)
        if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            mac_clean = mac.lower().replace("-", ":")
            if (my_mac and mac_clean == my_mac) or (router_mac and mac_clean == router_mac):
                return None
            return (target_ip, mac_clean)
        return None

    try:
        workers = min(len(subnet_ips), 256)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = ex.map(_scan_single_ip, subnet_ips)
            for r in results:
                if r and r[0] not in discovered:
                    discovered[r[0]] = r[1]
                    if progress_callback:
                        progress_callback(r[0], r[1])
    except Exception as e:
        log.debug(f"Win32 SendARP sweep exception: {e}")

    # 5. Harvest Windows Kernel ARP Cache for this interface only
    cache_devs = _get_arp_cache(interface_ip=my_ip, subnet_net=subnet_net, router_ip=router_ip, my_mac=my_mac, router_mac=router_mac)
    for dev in cache_devs:
        ip = dev["ip"]
        mac = dev["mac"]
        if ip not in discovered and mac and ip != my_ip and ip != router_ip:
            if (not my_mac or mac != my_mac) and (not router_mac or mac != router_mac):
                discovered[ip] = mac

    # 6. Build device list, enforce subnet boundary, and resolve OUI vendors
    for ip, mac in discovered.items():
        if subnet_net:
            try:
                if ipaddress.ip_address(ip) not in subnet_net:
                    continue
            except Exception:
                continue
        if ip == router_ip or ip == my_ip:
            continue
        if (my_mac and mac == my_mac) or (router_mac and mac == router_mac):
            continue
        vendor = oui_lookup(mac)
        devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""})

    # 7. Populate Hostnames & Device Names
    devices = populate_hostnames(devices)

    # 8. Ensure Host PC itself is explicitly included in discovered devices
    if my_ip and my_mac:
        import socket
        host_hostname = socket.gethostname()
        host_dev = {
            "ip": my_ip,
            "mac": my_mac.lower().replace("-", ":"),
            "vendor": f"This PC ({interface})",
            "hostname": host_hostname,
            "is_host": True
        }
        if not any(d.get("ip") == my_ip or (d.get("mac") or "").lower() == host_dev["mac"] for d in devices):
            devices.append(host_dev)

    devices.sort(key=device_sort_key)

    from .logger import log_packet
    for d in devices:
        dev_ip = d.get("ip")
        dev_mac = d.get("mac")
        dev_name = d.get("hostname") or d.get("vendor") or "Unknown"
        log_packet("DISCOVER", "ARP", dev_mac, dev_ip, length=42, details=f"Device found: {dev_name}", session_id=interface)

    return devices


def merge_devices(existing, new_devices, subnet_net=None, my_mac=None, my_ip=None, router_ip=None, router_mac=None):
    """
    Merge two device lists, updating existing entries and adding new ones.
    Strictly prevents duplicate IPs, stale MAC assignments, and preserves Host PC.
    """
    if not existing and not new_devices:
        return []

    my_mac_clean = (my_mac or "").lower().replace("-", ":")
    router_mac_clean = (router_mac or "").lower().replace("-", ":")

    from .network import get_all_local_ips_and_macs
    all_host_ips, all_host_macs = get_all_local_ips_and_macs()
    all_host_macs_clean = {m.lower().replace("-", ":") for m in all_host_macs}

    def _is_valid(d):
        if not isinstance(d, dict):
            return False
        ip = d.get("ip")
        mac = (d.get("mac") or "").lower().replace("-", ":")

        # Router gateway is not listed as a regular device
        if router_ip and ip == router_ip:
            return False
        if router_mac_clean and mac == router_mac_clean:
            return False

        # Host PC device is explicitly kept and tagged
        if (my_ip and ip == my_ip) or (my_mac_clean and mac == my_mac_clean) or (ip in all_host_ips) or (mac in all_host_macs_clean):
            d["is_host"] = True
            if not d.get("hostname"):
                import socket
                d["hostname"] = socket.gethostname()
            if not d.get("vendor") or d.get("vendor") in ("Unknown", "unknown", "-"):
                d["vendor"] = "This PC (Host)"
            return True

        if subnet_net and ip and ip != "-":
            try:
                if ipaddress.ip_address(ip) not in subnet_net:
                    return False
            except Exception:
                return False
        return True

    clean_existing = [dict(d) for d in (existing or []) if _is_valid(d)]
    clean_new = [dict(d) for d in (new_devices or []) if _is_valid(d)]

    # Map of fresh live discoveries (authoritative for current IP -> MAC mappings)
    live_ip_to_mac = {d["ip"]: d["mac"].lower() for d in clean_new if d.get("ip") and d["ip"] != "-" and d.get("mac")}
    live_mac_to_ip = {d["mac"].lower(): d["ip"] for d in clean_new if d.get("mac") and d["mac"] not in ("unknown", "")}

    # Deduplicate existing entries against fresh live observations
    filtered_existing = []
    for d in clean_existing:
        ex_mac = (d.get("mac") or "").lower()
        ex_ip  = d.get("ip") or "-"

        # If this IP was freshly discovered on a DIFFERENT MAC, the old MAC lost this IP lease!
        if ex_ip in live_ip_to_mac and live_ip_to_mac[ex_ip] != ex_mac:
            continue

        # If this MAC was freshly discovered, clean_new will supply the updated record
        if ex_mac in live_mac_to_ip:
            continue

        filtered_existing.append(d)

    # Combine: clean_new (highest priority) + remaining non-conflicting existing
    seen_ips = set()
    seen_macs = set()
    result = []

    for d in clean_new:
        ip = d.get("ip")
        mac = (d.get("mac") or "").lower()
        if ip and ip != "-" and ip in seen_ips:
            continue
        if mac and mac not in ("unknown", "") and mac in seen_macs:
            continue
        if ip and ip != "-":
            seen_ips.add(ip)
        if mac and mac not in ("unknown", ""):
            seen_macs.add(mac)
        result.append(d)

    for d in filtered_existing:
        ip = d.get("ip")
        mac = (d.get("mac") or "").lower()
        if ip and ip != "-" and ip in seen_ips:
            continue
        if mac and mac not in ("unknown", "") and mac in seen_macs:
            continue
        if ip and ip != "-":
            seen_ips.add(ip)
        if mac and mac not in ("unknown", ""):
            seen_macs.add(mac)
        result.append(d)

    # Ensure Host PC device is present in the final merged list
    if my_ip and my_mac_clean:
        has_host = any(d.get("ip") == my_ip or (d.get("mac") or "").lower() == my_mac_clean for d in result)
        if not has_host:
            import socket
            result.append({
                "ip": my_ip,
                "mac": my_mac_clean,
                "vendor": "This PC (Host)",
                "hostname": socket.gethostname(),
                "is_host": True
            })

    result.sort(key=device_sort_key)
    return result


def resolve_mac(ip, interface=None):
    """
    Resolve MAC for an IP using native Win32 SendARP, ARP cache, and Scapy fallback.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    src_ip = None
    if interface:
        src_ip, _ = get_interface_ip_and_mac(interface)

    # 1. Native Win32 SendARP
    mac = win_send_arp(ip, src_ip=src_ip)
    if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return mac

    # 2. Windows ARP Cache
    mac = resolve_mac_from_arp_cache(ip, interface_ip=src_ip)
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
