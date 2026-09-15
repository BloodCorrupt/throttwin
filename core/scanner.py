import re
import sys
import logging
import socket
import subprocess
import ipaddress
import questionary
from concurrent.futures import ThreadPoolExecutor

from .console import console, Table, box, qselect, custom_style
from .network import resolve_mac_from_arp_cache, resolve_hostname, get_scapy_interface

log = logging.getLogger("throttwin")

_HOSTNAME_CACHE = {}
_VENDOR_OUI_CACHE = {}


def _oui_lookup(mac):
    """Simple OUI vendor lookup using cached Scapy manuf database."""
    if not mac or mac == "unknown":
        return "Unknown"
    if mac in _VENDOR_OUI_CACHE:
        return _VENDOR_OUI_CACHE[mac]
    try:
        from scapy.all import conf
        vendor = conf.manufdb._get_manuf(mac)
        result = vendor if vendor else "Unknown"
    except Exception:
        result = "Unknown"
    _VENDOR_OUI_CACHE[mac] = result
    return result


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


def populate_hostnames(devices):
    """Batch concurrent hostname resolution for all devices."""
    ips = [d["ip"] for d in devices if d.get("ip") and d["ip"] not in ("-", "Unknown") and not d.get("hostname")]
    if not ips:
        for d in devices:
            if "hostname" not in d:
                d["hostname"] = ""
        return devices

    try:
        with ThreadPoolExecutor(max_workers=min(len(ips), 16)) as ex:
            results = list(ex.map(resolve_hostname, ips))
        ip_map = dict(zip(ips, results))
        for d in devices:
            ip = d.get("ip")
            if ip in ip_map and ip_map[ip]:
                d["hostname"] = ip_map[ip]
            elif "hostname" not in d:
                d["hostname"] = ""
    except Exception:
        for d in devices:
            if "hostname" not in d:
                d["hostname"] = ""
    return devices


def arp_scan(interface, router_ip):
    """
    Active ARP sweep using Scapy srp() broadcast on the local subnet.
    Falls back to reading Windows ARP cache if Scapy scan yields nothing.
    """
    devices = []

    # --- Determine subnet from interface IP ---
    try:
        import psutil
        addrs = psutil.net_if_addrs().get(interface, [])
        ip4 = [(a.address, a.netmask) for a in addrs if a.family.name == "AF_INET"
               and not a.address.startswith("169.254")]
        if not ip4:
            raise ValueError("No IPv4 on interface")
        my_ip, netmask = ip4[0]
        net = ipaddress.IPv4Network(f"{my_ip}/{netmask}", strict=False)
        subnet = str(net)
    except Exception as e:
        log.warning(f"Could not determine subnet for {interface}: {e}")
        return _arp_cache_scan(router_ip)

    # --- Active Scapy ARP sweep ---
    try:
        from scapy.all import Ether, ARP, srp, conf as scapy_conf

        npf_iface = get_scapy_interface(interface)
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            iface=npf_iface,
            timeout=2,
            verbose=0,
            retry=1
        )

        for _, rcv in ans:
            ip  = rcv[ARP].psrc
            mac = rcv[Ether].src.lower()
            if ip == router_ip or ip == scapy_conf.route.route("0.0.0.0")[1]:
                continue
            vendor = _oui_lookup(mac)
            devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""})

    except Exception as e:
        log.warning(f"Scapy ARP sweep failed: {e}")

    # Supplement with ARP cache entries that Scapy may have missed
    cache_devs = _arp_cache_scan(router_ip)
    devices = merge_devices(devices, cache_devs)
    devices = populate_hostnames(devices)
    devices.sort(key=device_sort_key)
    return devices


def _arp_cache_scan(router_ip):
    """
    Parse Windows `arp -a` output to discover devices from the ARP cache.
    """
    devices = []
    try:
        result = subprocess.run("arp -a", shell=True, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                ip  = parts[0]
                mac = parts[1].replace("-", ":").lower()
                typ = parts[2] if len(parts) > 2 else ""

                # Skip broadcast, multicast, gateway, and static-only entries
                if (ip == router_ip
                        or ip.endswith(".255")
                        or ip.startswith("224.")
                        or ip.startswith("239.")
                        or ip == "255.255.255.255"
                        or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
                        or not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac)):
                    continue

                vendor = _oui_lookup(mac)
                devices.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""})
    except Exception as e:
        log.warning(f"ARP cache scan failed: {e}")
    return devices


def merge_devices(existing, new_devices):
    """Merge two device lists, updating existing entries and adding new ones."""
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
    """Resolve MAC for an IP using ARP cache (Windows arp -a)."""
    mac = resolve_mac_from_arp_cache(ip)
    if mac:
        return mac
    # Try Scapy ARP request
    try:
        from scapy.all import Ether, ARP, srp
        npf = get_scapy_interface(interface) if interface else None
        kwargs = {"iface": npf} if npf else {}
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=1, verbose=0, **kwargs)
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
            # Try to find IP from ARP cache
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
        vendor = name if name else "Manual Entry"

        dev = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": ""}
        console.print(f"  [success]✓ Added: {ip} ({mac}) — {vendor}[/success]\n")
        return dev
    except KeyboardInterrupt:
        console.print("\n  [dim]Cancelled.[/dim]\n")
        return None


def scan_devices(interface, router_ip, existing_devices=None,
                 status_msg="Scanning network for active devices..."):
    """Full device scan — ARP sweep + ARP cache, merged with existing."""
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
        console.print(f" [success]Found {len(devices)} device(s) on network[/success]")

    return devices


def display_devices(config, matched_devices, devices, last_ips=None):
    """Render a Rich table of discovered devices."""
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
    table.add_column("Device",      style="")

    for dev in devices:
        ip  = dev.get("ip") or "-"
        mac = dev.get("mac", "Unknown")
        vendor   = dev.get("vendor", "Unknown")
        hostname = dev.get("hostname", "")
        is_last  = ip in last_ips

        if not vendor or "locally administered" in vendor.lower():
            vendor = "Unknown"

        device_str = f"{hostname} ({vendor})" if hostname and vendor != "Unknown" else (hostname or vendor)
        if len(device_str) > 32:
            device_str = device_str[:32] + "…"

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
