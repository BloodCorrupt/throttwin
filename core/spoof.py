import time
import logging
import threading

log = logging.getLogger("throttwin")


def arp_spoof_loop(interface, target_ip, target_mac, router_ip, router_mac,
                   my_mac, stop_event, status=None):
    """
    [DISABLED / DEFANGED] Core ARP spoofing loop disabled.
    """
    log.error(f"[CORE ERROR] arp_spoof_loop is disabled and non-functional.")
    while not stop_event.is_set():
        stop_event.wait(1.0)


def _restore_arp(interface, target_ip, target_mac, router_ip, router_mac, my_mac):
    """
    [DISABLED / DEFANGED] Gratuitous ARP restore disabled.
    """
    pass


def get_router_mac(router_ip, interface):
    """
    [DISABLED / DEFANGED] Router MAC resolution disabled.
    """
    log.warning(f"[CORE ERROR] get_router_mac disabled.")
    return None


def get_my_mac(interface):
    """
    [DISABLED / DEFANGED] Local MAC resolution disabled.
    """
    log.warning(f"[CORE ERROR] get_my_mac disabled.")
    return None
