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

# Built-in high-accuracy OUI Vendor Database (top 150+ manufacturers & IoT chipsets)
_COMMON_OUIS = {
    # Apple
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0a:27": "Apple", "00:0a:95": "Apple",
    "00:0d:93": "Apple", "00:10:fa": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
    "00:16:cb": "Apple", "00:17:f2": "Apple", "00:19:e3": "Apple", "00:1b:63": "Apple",
    "00:1c:b3": "Apple", "00:1d:4f": "Apple", "00:1e:52": "Apple", "00:1e:c2": "Apple",
    "00:1f:5b": "Apple", "00:1f:f3": "Apple", "00:21:e9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6c": "Apple", "00:23:df": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4b": "Apple", "00:25:bc": "Apple",
    "00:26:08": "Apple", "00:26:4a": "Apple", "00:26:b0": "Apple", "00:26:bb": "Apple",
    "18:65:90": "Apple", "20:c9:d0": "Apple", "28:cf:e9": "Apple", "34:36:3b": "Apple",
    "3c:07:54": "Apple", "3c:15:c2": "Apple", "40:6c:8f": "Apple", "40:b4:cd": "Apple",
    "48:d7:05": "Apple", "50:bc:96": "Apple", "58:55:ca": "Apple", "60:03:08": "Apple",
    "60:30:d4": "Apple", "60:f4:45": "Apple", "64:20:0c": "Apple", "68:5b:35": "Apple",
    "70:3e:ac": "Apple", "70:ec:e4": "Apple", "78:4f:43": "Apple", "7c:6d:62": "Apple",
    "80:e6:50": "Apple", "84:78:8b": "Apple", "88:66:a5": "Apple", "8c:85:90": "Apple",
    "90:72:40": "Apple", "90:0f:0c": "Apple", "98:01:a7": "Apple", "98:5a:eb": "Apple",
    "9c:20:7b": "Apple", "a4:83:e7": "Apple", "a8:5b:78": "Apple", "ac:bc:32": "Apple",
    "b8:78:26": "Apple", "bc:fe:d9": "Apple", "c8:6f:1d": "Apple", "cc:08:8d": "Apple",
    "d0:23:db": "Apple", "d4:9a:20": "Apple", "dc:2b:2a": "Apple", "e0:c7:67": "Apple",
    "f0:18:98": "Apple", "f4:5c:89": "Apple", "f8:27:93": "Apple", "fc:25:3f": "Apple",
    
    # Samsung
    "00:07:ab": "Samsung", "00:12:47": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
    "00:17:c9": "Samsung", "00:1a:8a": "Samsung", "00:1e:e1": "Samsung", "00:21:19": "Samsung",
    "04:d3:b0": "Samsung", "10:51:07": "Samsung", "24:4b:03": "Samsung", "28:9e:97": "Samsung",
    "30:07:4d": "Samsung", "34:be:00": "Samsung", "38:0b:40": "Samsung", "40:4e:36": "Samsung",
    "48:44:f7": "Samsung", "50:85:69": "Samsung", "5c:0a:5b": "Samsung", "68:05:71": "Samsung",
    "78:40:e4": "Samsung", "84:25:19": "Samsung", "90:f1:aa": "Samsung", "94:63:72": "Samsung",
    "a8:06:00": "Samsung", "ac:5f:3e": "Samsung", "bc:72:b9": "Samsung", "c4:73:1e": "Samsung",
    "d8:90:e8": "Samsung", "e8:50:8b": "Samsung", "f4:0e:22": "Samsung", "fc:a1:3e": "Samsung",

    # Xiaomi / Redmi / POCO
    "00:9e:c8": "Xiaomi", "04:cf:8c": "Xiaomi", "14:f6:5a": "Xiaomi", "18:59:36": "Xiaomi",
    "28:6c:07": "Xiaomi", "34:80:dc": "Xiaomi", "34:ce:00": "Xiaomi", "38:a4:ed": "Xiaomi",
    "50:64:2b": "Xiaomi", "58:44:98": "Xiaomi", "58:a0:23": "Xiaomi", "64:09:80": "Xiaomi",
    "74:23:44": "Xiaomi", "78:02:f8": "Xiaomi", "7c:1d:d9": "Xiaomi", "84:f3:eb": "Xiaomi",
    "8c:be:be": "Xiaomi", "98:fa:e3": "Xiaomi", "a4:c3:f0": "Xiaomi", "ac:c1:ee": "Xiaomi",
    "b0:e5:ed": "Xiaomi", "d4:97:0b": "Xiaomi", "dc:71:96": "Xiaomi", "f8:a4:5f": "Xiaomi",

    # Intel
    "00:02:b3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:0e:0c": "Intel",
    "00:13:02": "Intel", "00:13:e8": "Intel", "00:15:00": "Intel", "00:16:76": "Intel",
    "00:1b:21": "Intel", "00:1c:c0": "Intel", "00:21:6a": "Intel", "00:23:14": "Intel",
    "00:24:d7": "Intel", "34:13:e8": "Intel", "40:74:e0": "Intel", "48:51:b7": "Intel",
    "54:8c:a0": "Intel", "68:05:46": "Intel", "7c:57:58": "Intel", "80:86:f2": "Intel",
    "8c:8d:28": "Intel", "98:fa:9b": "Intel", "a4:bb:6d": "Intel", "c8:5b:76": "Intel",

    # TP-Link / Mercusys
    "00:0a:eb": "TP-Link", "00:14:78": "TP-Link", "00:19:e0": "TP-Link", "00:21:27": "TP-Link",
    "00:23:cd": "TP-Link", "00:25:86": "TP-Link", "14:cc:20": "TP-Link", "1c:3b:f3": "TP-Link",
    "30:b5:c2": "TP-Link", "50:c7:bf": "TP-Link", "60:32:b1": "TP-Link", "6c:5a:b0": "TP-Link",
    "70:4f:57": "TP-Link", "84:16:f9": "TP-Link", "98:48:27": "TP-Link", "98:4a:6b": "TP-Link",
    "a4:2b:b0": "TP-Link", "c0:06:c3": "TP-Link", "c0:25:67": "TP-Link", "e8:48:b8": "TP-Link",
    "f4:ec:38": "TP-Link", "f8:1a:67": "TP-Link",

    # Espressif / Tuya / Smart Home IoT
    "18:fe:34": "Espressif (ESP8266/ESP32)", "24:0a:c4": "Espressif (ESP32)", "24:6f:28": "Espressif (ESP32)",
    "24:b2:de": "Espressif (ESP32)", "2c:3a:e8": "Espressif (ESP32)", "30:ae:a4": "Espressif (ESP32)",
    "34:7d:f6": "Espressif / Smart Device", "3c:61:05": "Espressif (ESP32)", "3c:71:bf": "Espressif (ESP32)",
    "48:3f:da": "Espressif (ESP32)", "48:55:19": "Espressif (ESP32)", "54:43:b2": "Espressif (ESP32)",
    "60:01:94": "Espressif (ESP8266)", "68:c6:3a": "Espressif (ESP32)", "70:03:9f": "Espressif (ESP32)",
    "84:0d:8e": "Espressif (ESP32)", "84:f3:eb": "Tuya Smart IoT", "a4:e5:7c": "Tuya Smart IoT",
    "b4:e6:2d": "Espressif (ESP32)", "c4:4f:33": "Espressif (ESP32)", "d8:bf:c0": "Espressif (ESP32)",
    "dc:4f:22": "Espressif (ESP32)",

    # Huawei / Honor
    "00:1e:10": "Huawei", "00:25:9e": "Huawei", "04:25:7b": "Huawei", "08:19:a6": "Huawei",
    "10:1b:54": "Huawei", "1c:1d:67": "Huawei", "20:08:ed": "Huawei", "28:6e:d4": "Huawei",
    "40:4d:8e": "Huawei", "4c:54:99": "Huawei", "70:7b:e8": "Huawei", "80:b6:86": "Huawei",
    "88:86:03": "Huawei", "94:77:2b": "Huawei", "ac:e2:15": "Huawei", "cc:96:a0": "Huawei",

    # Google / Nest / Chromecast
    "00:1a:11": "Google", "18:26:49": "Google", "1c:f5:0a": "Google", "3c:5a:37": "Google",
    "54:60:09": "Google", "6c:ad:f8": "Google", "70:3e:ac": "Google", "80:ce:62": "Google",
    "94:eb:cd": "Google", "a4:77:33": "Google", "d8:6c:63": "Google", "f4:03:04": "Google",

    # Amazon (Echo, FireTV, Kindle)
    "00:fc:8b": "Amazon", "0c:47:c9": "Amazon", "18:74:2e": "Amazon", "24:4c:07": "Amazon",
    "34:d2:70": "Amazon", "38:f7:3d": "Amazon", "40:b4:cd": "Amazon", "44:65:0d": "Amazon",
    "50:dc:e7": "Amazon", "68:37:e9": "Amazon", "74:75:48": "Amazon", "ac:63:be": "Amazon",

    # Sony / PlayStation
    "00:01:4a": "Sony", "00:04:1f": "Sony", "00:13:15": "Sony", "00:19:c5": "Sony",
    "00:1a:80": "Sony", "00:1d:0d": "Sony", "00:24:8d": "Sony", "28:0d:fc": "Sony (PlayStation)",
    "70:9e:29": "Sony (PlayStation)", "f8:46:1c": "Sony (PlayStation)",

    # Microsoft / Xbox / Surface
    "00:03:ff": "Microsoft", "00:0d:3a": "Microsoft", "00:12:5a": "Microsoft", "00:15:5d": "Microsoft",
    "00:17:fa": "Microsoft", "28:18:78": "Microsoft (Surface/Xbox)", "50:1a:c5": "Microsoft",
    "7c:ed:8d": "Microsoft (Xbox)", "98:5f:d3": "Microsoft",

    # Asus, Dell, HP, Lenovo, Realtek, MediaTek, Raspberry Pi
    "00:0c:6e": "ASUS", "04:d9:f5": "ASUS", "10:7b:44": "ASUS", "2c:fd:a1": "ASUS", "38:d5:47": "ASUS",
    "00:14:22": "Dell", "00:1e:4f": "Dell", "18:66:da": "Dell", "34:e6:d7": "Dell", "d4:be:d9": "Dell",
    "00:08:02": "HP", "00:18:71": "HP", "00:21:5a": "HP", "3c:d9:2b": "HP", "70:5a:0f": "HP",
    "00:16:36": "Lenovo", "00:21:cc": "Lenovo", "48:5d:60": "Lenovo", "70:72:0d": "Lenovo",
    "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM Virtual", "08:00:27": "VirtualBox Host/VM",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "8c:c6:81": "Vivo Mobile", "14:f6:d8": "Oppo Mobile", "a8:93:4a": "Realme Mobile",
}


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


def oui_lookup(mac):
    """
    High-performance OUI lookup using built-in high-accuracy dictionary,
    Scapy manufdb fallback, and MAC randomization detection.
    """
    if not mac or mac in ("unknown", "Unknown", "-"):
        return "Unknown"
    mac_clean = mac.lower().replace("-", ":")
    if mac_clean in _VENDOR_OUI_CACHE:
        return _VENDOR_OUI_CACHE[mac_clean]

    # 1. Check built-in prefix table
    prefix = ":".join(mac_clean.split(":")[:3])
    if prefix in _COMMON_OUIS:
        vendor = _COMMON_OUIS[prefix]
        _VENDOR_OUI_CACHE[mac_clean] = vendor
        return vendor

    # 2. Check Scapy manufdb
    try:
        from scapy.all import conf
        scapy_manuf = conf.manufdb._get_manuf(mac_clean)
        if scapy_manuf and scapy_manuf.lower() != mac_clean and scapy_manuf != "Unknown":
            _VENDOR_OUI_CACHE[mac_clean] = scapy_manuf
            return scapy_manuf
    except Exception:
        pass

    # 3. Check for Private / Randomized MAC
    if is_randomized_mac(mac_clean):
        res = "Randomized MAC (Private Wi-Fi)"
    else:
        res = "Unknown"

    _VENDOR_OUI_CACHE[mac_clean] = res
    return res


def netbios_lookup(ip, timeout=0.25):
    """
    Direct NetBIOS Name Query (UDP 137) to discover Windows PC names,
    SMB hosts, NAS devices, and workgroups.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    # Standard NetBIOS wildcard query for *<00>
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
                # Type 0 is workstation service / computer name
                if n_type == 0 and name and not name.startswith("IS~") and name != "WORKGROUP":
                    return name
                offset += 18
    except Exception:
        pass
    finally:
        s.close()
    return ""


def mdns_lookup(ip, timeout=0.25):
    """
    Lightweight mDNS / ZeroConf probe to query device name (Apple, Smart TVs, IoT).
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    # Send reverse pointer query for IP in .in-addr.arpa to 224.0.0.251:5353
    try:
        rev_parts = ip.split(".")[::-1]
        qname = "".join(f"{len(p)}{p}" for p in rev_parts) + "\x07in-addr\x04arpa\x00"
        # DNS header + PTR query
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
    name = netbios_lookup(ip, timeout=0.2)
    
    # 2. Reverse DNS
    if not name:
        name = resolve_hostname(ip, timeout=0.2)
        
    # 3. mDNS probe (best for Apple / IoT / Smart devices)
    if not name:
        name = mdns_lookup(ip, timeout=0.2)

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
        log.warning(f"Win32 SendARP sweep exception: {e}")

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
