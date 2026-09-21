"""
hostname.py — Aggressive Multi-Vector Hostname & Device Name Discovery Engine.

Features:
1. Direct Router DNS PTR Queries (UDP 53) — Ultra-fast (sub-10ms) RFC 1035 query to router/DHCP server.
2. NetBIOS Node Status Query (UDP 137) — Discovers Windows PC, Samba, and SMB hostnames.
3. mDNS / ZeroConf Query (UDP 5353) — Discovers Apple (iOS/macOS), Android TV, Cast, Linux Avahi, IoT devices.
4. SSDP / UPnP Friendly Name Discovery (UDP 1900) — Discovers Smart TVs (Samsung, LG, Sony), Roku, routers.
5. LLMNR Query (UDP 5355) — Link-Local Multicast Name Resolution for modern Windows machines.
6. HTTP/HTTPS Web Title & Realm Prober (Ports 80, 8080, 8000, 443, 8443) — Discovers Routers, Switches, NAS, Printers.
7. SNMP sysName Query (UDP 161) — Discovers managed network switches and enterprise gear.
8. Native Windows nbtstat Fallback — OS-level NetBIOS table query.
9. Concurrent Multi-Threaded Execution with Thread-Safe Caching.
"""

import os
import re
import ssl
import sys
import time
import socket
import struct
import logging
import threading
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("throttwin.hostname")

# Thread-safe in-memory cache for discovered hostnames with TTL (time-to-live)
# Format: {ip: (hostname, timestamp)}
_HOSTNAME_CACHE = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 300.0  # 5 minutes for valid hostnames


def clear_hostname_cache():
    """Clear all cached hostname entries to force complete re-resolution."""
    with _CACHE_LOCK:
        _HOSTNAME_CACHE.clear()

# Common generic junk words to ignore when extracting titles or names
_IGNORE_NAMES = {
    "workgroup", "mshome", "unknown", "localhost", "broadcom", "realtek",
    "intel", "qualcomm", "atheros", "mediatek", "android", "generic",
    "home", "welcome", "index", "index of /", "default", "router", "gateway",
    "404 not found", "403 forbidden", "401 unauthorized", "500 internal server error",
    "502 bad gateway", "503 service unavailable", "error", "document moved",
    "redirect", "login", "sign in", "web service", "http server", "apache",
    "nginx", "lighttpd", "iis windows", "productagent for windows"
}


def clean_hostname(name: str) -> str:
    """Sanitize and clean up a discovered hostname or device name."""
    if not name:
        return ""
    name = str(name).strip().replace("\r", " ").replace("\n", " ")
    name = re.sub(r"\s+", " ", name)
    # Strip surrounding quotes or punctuation
    name = name.strip("\"'()[]{}<>,;:")
    if not name or len(name) < 2 or len(name) > 64:
        return ""
    # Filter out pure IP addresses or MAC addresses disguised as names
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
        return ""
    if re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", name):
        return ""
    # Filter out generic junk
    if name.lower() in _IGNORE_NAMES:
        return ""
    return name


def build_dns_ptr_query(ip: str, tx_id: int = 0x1A2B) -> bytes:
    """Build standard RFC 1035 DNS PTR query packet."""
    parts = ip.split(".")[::-1]
    qname = b"".join(bytes([len(p)]) + p.encode("ascii", "ignore") for p in parts) + b"\x07in-addr\x04arpa\x00"
    # Header: ID, Flags=0x0100 (standard query with recursion), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    # Question: QNAME + QTYPE(12 = PTR) + QCLASS(1 = IN)
    question = qname + struct.pack(">HH", 12, 1)
    return header + question


def parse_dns_response(data: bytes) -> str:
    """Parse DNS response packet and extract PTR domain name."""
    if len(data) < 12:
        return ""
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return ""
    offset = 12
    # Skip question section
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            offset += 2
            break
        else:
            offset += 1 + length
    offset += 4  # Skip QTYPE and QCLASS

    # Parse answers
    names = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10
        rdata_end = offset + rdlen
        if rtype == 12:  # PTR Record
            ptr_labels = []
            curr = offset
            visited = 0
            while curr < rdata_end and curr < len(data) and visited < 30:
                visited += 1
                b = data[curr]
                if b == 0:
                    break
                if (b & 0xC0) == 0xC0:
                    ptr_offset = struct.unpack(">H", data[curr:curr+2])[0] & 0x3FFF
                    curr = ptr_offset
                    continue
                curr += 1
                label = data[curr:curr+b].decode("latin1", errors="ignore")
                ptr_labels.append(label)
                curr += b
            if ptr_labels:
                names.append(".".join(ptr_labels))
        offset = rdata_end

    for name in names:
        # Take the leftmost hostname label
        h = name.split(".")[0].strip()
        cleaned = clean_hostname(h)
        if cleaned:
            return cleaned
    return ""


def probe_dns_ptr_direct(ip: str, gateway: str = None, timeout: float = 0.2) -> str:
    """
    Directly query router/gateway DNS server (UDP 53) for PTR record.
    Typically resolves in 2-8ms for DHCP clients.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    if not gateway or gateway in ("-", "Unknown", "0.0.0.0"):
        return ""
    try:
        pkt = build_dns_ptr_query(ip)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (gateway, 53))
        data, _ = s.recvfrom(2048)
        s.close()
        return parse_dns_response(data)
    except Exception:
        pass
    return ""


def probe_netbios(ip: str, timeout: float = 0.25) -> str:
    """
    Direct NetBIOS Node Status Query (UDP 137).
    Discovers Windows PC names, Samba hosts, NAS, and SMB servers.
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
        data, _ = s.recvfrom(2048)
        if len(data) > 56:
            num = data[56]
            offset = 57
            for _ in range(num):
                if offset + 18 > len(data):
                    break
                name = data[offset:offset+15].decode("latin1", errors="ignore").strip()
                flags = struct.unpack(">H", data[offset+16:offset+18])[0]
                is_group = bool(flags & 0x8000)
                # Filter out group names and internal tokens
                if not is_group and name and not name.startswith("IS~") and name not in ("WORKGROUP", "MSHOME"):
                    cleaned = clean_hostname(name)
                    if cleaned:
                        return cleaned
                offset += 18
    except Exception:
        pass
    finally:
        s.close()
    return ""


def probe_mdns(ip: str, timeout: float = 0.25) -> str:
    """
    Direct mDNS / ZeroConf probe (UDP 5353) to discover Apple (Mac, iPhone, iPad, Apple TV),
    Android TV, Google Cast, Linux Avahi, and Smart Home hardware.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    try:
        rev_parts = ip.split(".")[::-1]
        qname = "".join(f"{len(p)}{p}" for p in rev_parts) + "\x07in-addr\x04arpa\x00"
        dns_pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname.encode("ascii", "ignore") + b"\x00\x0c\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(dns_pkt, (ip, 5353))
        data, _ = s.recvfrom(2048)
        s.close()
        if len(data) > 12:
            text = data[12:].decode("latin1", errors="ignore")
            matches = re.findall(r"([a-zA-Z0-9_\-\.]+)\.local", text)
            for m in matches:
                cand = m.split(".")[0].strip()
                if cand.lower() not in ("local", "arpa", "in-addr", "dns-sd", "udp", "tcp"):
                    cleaned = clean_hostname(cand)
                    if cleaned:
                        return cleaned
    except Exception:
        pass
    return ""


def probe_ssdp(ip: str, timeout: float = 0.3) -> str:
    """
    Direct SSDP / UPnP probe (UDP 1900) to discover Smart TVs (Samsung, LG, Sony, Bravia),
    Roku, Chromecast, Home Assistant, routers, and smart speakers.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    try:
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg.encode("ascii"), (ip, 1900))
        data, _ = s.recvfrom(2048)
        s.close()
        text = data.decode("latin1", errors="ignore")
        
        # 1. Check LOCATION header for XML device description
        loc_m = re.search(r"LOCATION:\s*([^\r\n]+)", text, re.IGNORECASE)
        if loc_m:
            url = loc_m.group(1).strip()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "UPnP/1.0"})
                with urllib.request.urlopen(req, timeout=0.5) as resp:
                    xml_content = resp.read(8192)
                    tree = ET.fromstring(xml_content)
                    for elem in tree.iter():
                        if elem.tag.endswith("friendlyName") and elem.text:
                            c = clean_hostname(elem.text)
                            if c:
                                return c
                        if elem.tag.endswith("modelName") and elem.text:
                            c = clean_hostname(elem.text)
                            if c:
                                return c
            except Exception:
                pass
        
        # 2. Check SERVER header
        srv_m = re.search(r"SERVER:\s*([^\r\n]+)", text, re.IGNORECASE)
        if srv_m:
            s_val = srv_m.group(1).strip()
            if s_val and not s_val.lower().startswith("upnp") and not s_val.lower().startswith("posix"):
                c = clean_hostname(s_val.split("/")[0])
                if c:
                    return c
    except Exception:
        pass
    return ""


def probe_llmnr(ip: str, timeout: float = 0.25) -> str:
    """
    Direct LLMNR query (UDP 5355) for Windows Link-Local Name Resolution.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    try:
        rev_parts = ip.split(".")[::-1]
        qname = "".join(f"{len(p)}{p}" for p in rev_parts) + "\x07in-addr\x04arpa\x00"
        pkt = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname.encode("ascii", "ignore") + b"\x00\x0c\x00\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 5355))
        data, _ = s.recvfrom(2048)
        s.close()
        if len(data) > 12:
            text = data[12:].decode("latin1", errors="ignore")
            matches = re.findall(r"([a-zA-Z0-9_\-]{2,32})", text)
            for m in matches:
                if m.lower() not in ("in-addr", "arpa", "local", "udp", "tcp") and not m.isdigit():
                    c = clean_hostname(m)
                    if c:
                        return c
    except Exception:
        pass
    return ""


def probe_http_title(ip: str, ports: tuple = (80, 8080, 8000, 8443, 443), timeout: float = 0.25) -> str:
    """
    Probe HTTP / HTTPS web management port for <title> and Realm strings.
    Extracts brand and model from routers, managed switches, cameras, and printers.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, port))
            req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii"))
            data = s.recv(4096)
            s.close()
            text = data.decode("utf-8", errors="ignore")

            # 1. HTTP Realm in 401 Header (e.g. realm="TP-Link Wireless Router")
            realm_m = re.search(r'realm="([^"]+)"', text, re.IGNORECASE)
            if realm_m:
                r = realm_m.group(1).strip()
                cleaned_realm = clean_hostname(r)
                if cleaned_realm and not cleaned_realm.lower().startswith("auth"):
                    return cleaned_realm

            # 2. HTML <title> tag
            title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if title_m:
                t = title_m.group(1).strip().replace("\n", " ").replace("\r", " ")
                cleaned = clean_hostname(t)
                if cleaned:
                    return cleaned
        except Exception:
            pass
    return ""


def probe_snmp(ip: str, community: str = "public", timeout: float = 0.25) -> str:
    """
    Query SNMP sysName.0 (OID 1.3.6.1.2.1.1.5.0) via UDP 161.
    Discovers names of managed switches, enterprise APs, and printers.
    """
    if not ip or ip in ("-", "Unknown"):
        return ""
    try:
        comm_bytes = community.encode("ascii")
        oid = b"\x2b\x06\x01\x02\x01\x01\x05\x00"
        varbind = b"\x30" + bytes([len(oid) + 4]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
        pdu = b"\xa0" + bytes([len(varbind_list) + 9]) + b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + varbind_list
        snmp_pkt = b"\x30" + bytes([len(comm_bytes) + len(pdu) + 5]) + b"\x02\x01\x00\x04" + bytes([len(comm_bytes)]) + comm_bytes + pdu

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(snmp_pkt, (ip, 161))
        data, _ = s.recvfrom(2048)
        s.close()
        if len(data) > 20:
            text = data[20:].decode("latin1", errors="ignore")
            matches = re.findall(r"[\x20-\x7E]{3,50}", text)
            if matches:
                cand = matches[-1].strip()
                if cand and cand != community:
                    c = clean_hostname(cand)
                    if c:
                        return c
    except Exception:
        pass
    return ""


def probe_nbtstat(ip: str, timeout: float = 1.0) -> str:
    """
    Execute native Windows nbtstat -A <ip> to parse remote NetBIOS table.
    Used as OS-level fallback.
    """
    if sys.platform != "win32" or not ip or ip in ("-", "Unknown"):
        return ""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

        res = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=timeout,
            startupinfo=startupinfo
        )
        for line in res.stdout.splitlines():
            line_str = line.strip()
            if "<00>" in line_str and "UNIQUE" in line_str:
                parts = line_str.split()
                if parts:
                    name = parts[0].strip()
                    cleaned = clean_hostname(name)
                    if cleaned and cleaned not in ("WORKGROUP", "MSHOME"):
                        return cleaned
    except Exception:
        pass
    return ""


def probe_os_reverse_dns(ip: str, timeout: float = 0.25) -> str:
    """Fallback standard OS reverse DNS lookup."""
    if not ip or ip in ("-", "Unknown"):
        return ""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(old)
        if host and host != ip:
            cleaned = clean_hostname(host.split(".")[0])
            if cleaned:
                return cleaned
    except Exception:
        pass
    return ""


def probe_nmap_batch(ips: list, gateway: str = None, timeout: float = 3.5) -> dict:
    """
    Execute Nmap in batch against target IPs to extract PTR hostnames and NetBIOS names.
    Returns {ip: clean_hostname}.
    """
    from .core_tools import get_nmap_path, is_nmap_installed
    if not ips or not is_nmap_installed():
        return {}

    nmap_exe = get_nmap_path()
    if not nmap_exe or not os.path.isfile(nmap_exe):
        return {}

    cmd = [
        nmap_exe,
        "-sn", "-Pn", "-R",
        "--script", "nbstat",
        "-T4",
        "--max-rtt-timeout", "350ms",
        "--max-retries", "1",
        "-oX", "-"
    ]
    if gateway and gateway not in ("-", "Unknown", "0.0.0.0"):
        cmd.extend(["--dns-servers", gateway])

    cmd.extend(ips)

    startupinfo = None
    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

    results = {}
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, startupinfo=startupinfo)
        if res.stdout:
            try:
                root = ET.fromstring(res.stdout)
                for host in root.findall("host"):
                    ip_elem = host.find(".//address[@addrtype='ipv4']")
                    if ip_elem is None:
                        continue
                    ip = ip_elem.get("addr")
                    if not ip:
                        continue

                    # 1. Check PTR hostname
                    hn_elem = host.find(".//hostnames/hostname")
                    if hn_elem is not None and hn_elem.get("name"):
                        raw_hn = hn_elem.get("name").split(".")[0]
                        c = clean_hostname(raw_hn)
                        if c:
                            results[ip] = c
                            continue

                    # 2. Check nbstat script output
                    script_elem = host.find(".//hostscript/script[@id='nbstat']")
                    if script_elem is not None and script_elem.get("output"):
                        m = re.search(r"NetBIOS name:\s*([A-Za-z0-9_\-\.]+)", script_elem.get("output"))
                        if m:
                            c = clean_hostname(m.group(1))
                            if c and c not in ("WORKGROUP", "MSHOME"):
                                results[ip] = c
                                continue
            except Exception:
                pass
    except Exception:
        pass

    return results


def probe_nmap_hostname(ip: str, gateway: str = None, timeout: float = 2.0) -> str:
    """Query single target IP via Nmap."""
    if not ip or ip in ("-", "Unknown", "0.0.0.0"):
        return ""
    batch_res = probe_nmap_batch([ip], gateway=gateway, timeout=timeout)
    return batch_res.get(ip, "")


def resolve_device_name_aggressive(ip: str, gateway: str = None, force_refresh: bool = False) -> str:
    """
    Ultra-Fast Aggressive Hostname Resolver.
    Tier 0 (Nmap First): High-grade security scanner probe (if Nmap installed).
    Tier 1 (Native Direct DNS PTR): Direct RFC 1035 UDP 53 to router DHCP leases + NetBIOS UDP 137.
    Tier 2 (Native Multicast): mDNS UDP 5353 + SSDP UDP 1900 + LLMNR UDP 5355.
    Tier 3 (Native Management): HTTP Web Management Title + SNMP sysName.
    Returns the best human-readable name or empty string.
    """
    if not ip or ip in ("-", "Unknown", "0.0.0.0", "127.0.0.1"):
        return ""

    now = time.time()
    if not force_refresh:
        with _CACHE_LOCK:
            if ip in _HOSTNAME_CACHE:
                cached_name, cached_time = _HOSTNAME_CACHE[ip]
                if cached_name and (now - cached_time < _CACHE_TTL):
                    return cached_name

    # --- Tier 0: Nmap First (if installed) ---
    nmap_name = probe_nmap_hostname(ip, gateway=gateway, timeout=1.8)
    if nmap_name:
        with _CACHE_LOCK:
            _HOSTNAME_CACHE[ip] = (nmap_name, now)
        return nmap_name

    # --- Tier 1 Fallback: Fast-Path (Direct DNS PTR to Router DHCP table + NetBIOS) ---
    dns_name = ""
    nb_name = ""
    try:
        with ThreadPoolExecutor(max_workers=2) as ex:
            f_dns = ex.submit(probe_dns_ptr_direct, ip, gateway, timeout=0.15)
            f_nb = ex.submit(probe_netbios, ip, timeout=0.15)
            dns_name = f_dns.result()
            nb_name = f_nb.result()
    except Exception:
        pass

    if nb_name:
        with _CACHE_LOCK:
            _HOSTNAME_CACHE[ip] = (nb_name, now)
        return nb_name

    if dns_name:
        with _CACHE_LOCK:
            _HOSTNAME_CACHE[ip] = (dns_name, now)
        return dns_name

    # --- Tier 2 Fallback: mDNS (Apple/Linux/IoT) + SSDP / UPnP (Smart TVs/Routers) + LLMNR ---
    mdns_name = ""
    ssdp_name = ""
    llmnr_name = ""
    try:
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_mdns = ex.submit(probe_mdns, ip, timeout=0.15)
            f_ssdp = ex.submit(probe_ssdp, ip, timeout=0.2)
            f_llmnr = ex.submit(probe_llmnr, ip, timeout=0.15)
            mdns_name = f_mdns.result()
            ssdp_name = f_ssdp.result()
            llmnr_name = f_llmnr.result()
    except Exception:
        pass

    if ssdp_name:
        with _CACHE_LOCK:
            _HOSTNAME_CACHE[ip] = (ssdp_name, now)
        return ssdp_name

    if mdns_name:
        with _CACHE_LOCK:
            _HOSTNAME_CACHE[ip] = (mdns_name, now)
        return mdns_name

    if llmnr_name:
        with _CACHE_LOCK:
            _HOSTNAME_CACHE[ip] = (llmnr_name, now)
        return llmnr_name

    # --- Tier 3 Fallback: HTTP Title (Port 80) + SNMP (UDP 161) ---
    http_name = ""
    snmp_name = ""
    try:
        with ThreadPoolExecutor(max_workers=2) as ex:
            f_http = ex.submit(probe_http_title, ip, ports=(80, 8080), timeout=0.15)
            f_snmp = ex.submit(probe_snmp, ip, timeout=0.15)
            http_name = f_http.result()
            snmp_name = f_snmp.result()
    except Exception:
        pass

    best_name = http_name or snmp_name or ""
    best_name = clean_hostname(best_name)

    with _CACHE_LOCK:
        if best_name:
            _HOSTNAME_CACHE[ip] = (best_name, now)

    return best_name


def populate_hostnames_aggressive(devices: list, gateway: str = None, force_refresh: bool = False) -> list:
    """
    Populate hostnames across a list of device dictionaries concurrently.
    Uses Nmap first when installed, with seamless fallback to Native Multi-Vector Engine.
    devices: [{'ip': '...', 'mac': '...', 'hostname': '...'}, ...]
    """
    if not devices:
        return devices

    now = time.time()
    to_resolve = []
    for d in devices:
        ip = d.get("ip")
        if ip and ip not in ("-", "Unknown", "0.0.0.0"):
            if not force_refresh:
                with _CACHE_LOCK:
                    entry = _HOSTNAME_CACHE.get(ip)
                if entry:
                    cached_name, cached_time = entry
                    if cached_name and (now - cached_time < _CACHE_TTL):
                        d["hostname"] = cached_name
                        continue
            # If not in cache, expired, force refresh, or empty hostname
            to_resolve.append(ip)

    if not to_resolve:
        for d in devices:
            if "hostname" not in d:
                d["hostname"] = ""
        return devices

    results = {}

    # 1. Run Nmap First in Batch (if installed)
    try:
        nmap_results = probe_nmap_batch(to_resolve, gateway=gateway, timeout=3.5)
        for ip, name in nmap_results.items():
            if name:
                results[ip] = name
                with _CACHE_LOCK:
                    _HOSTNAME_CACHE[ip] = (name, now)
    except Exception as e:
        log.debug(f"Nmap batch probe error: {e}")

    # 2. For remaining un-resolved IPs, run parallel fallback to Native Engine
    remaining = [ip for ip in to_resolve if ip not in results]
    if remaining:
        def _fallback_worker(ip):
            return ip, resolve_device_name_aggressive(ip, gateway=gateway, force_refresh=force_refresh)

        max_workers = min(len(remaining), 32)
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                for ip, name in ex.map(_fallback_worker, remaining):
                    if name:
                        results[ip] = name
        except Exception as e:
            log.debug(f"Fallback hostname batch failed: {e}")

    for d in devices:
        ip = d.get("ip")
        if ip in results and results[ip]:
            d["hostname"] = results[ip]
        elif "hostname" not in d:
            d["hostname"] = ""

    return devices
