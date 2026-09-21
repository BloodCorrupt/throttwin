"""
[DISABLED / DEFANGED] Traffic shaping module.
All packet interception, token-bucket rate limiting, and packet forwarding have been disabled.
"""

import time
import logging
import threading
import queue

log = logging.getLogger("throttwin")

_shapers = {}
_lock = threading.Lock()


class TokenBucket:
    def __init__(self, rate_bps, burst_factor=1.5):
        self.rate_bps = 0
        self.capacity = 0
        self.tokens = 0

    def update_rate(self, rate_bps, burst_factor=1.5):
        pass

    def consume(self, n_bytes):
        return False


class FuzzyController:
    def __init__(self):
        pass

    def should_throttle(self):
        return True

    def get_state(self):
        return {"phase": "DISABLED", "next_flip_in": 0.0}


class TrafficShaper:
    def __init__(self, interface, target_ip, target_mac, router_ip, router_mac,
                 my_mac, limit_mbps, stop_event):
        self.interface = interface
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.router_ip = router_ip
        self.router_mac = router_mac
        self.my_mac = my_mac
        self.stop_event = stop_event
        self.bucket = TokenBucket(0)
        self.fuzzy_enabled = False
        self.fuzzy_ctrl = FuzzyController()
        self.total_bytes = 0
        self.speed_bps = 0.0

    def start(self):
        log.error(f"[CORE ERROR] TrafficShaper for {self.target_ip} is disabled and non-functional.")

    def update_limit(self, limit_mbps):
        pass

    def set_fuzzy(self, enabled):
        pass

    def get_fuzzy_state(self):
        return {"enabled": False}

    def get_speed_mbps(self):
        return 0.0


def enable_ip_forwarding():
    log.warning("[CORE ERROR] enable_ip_forwarding disabled.")


def disable_ip_forwarding():
    log.warning("[CORE ERROR] disable_ip_forwarding disabled.")


def setup_traffic_shaping(interface, targets, limit_mbps, router_ip,
                          router_mac, my_mac, stop_event):
    log.error("[CORE ERROR] setup_traffic_shaping disabled.")
    return {}


def add_target_shaping(interface, ip, mac, router_ip, router_mac,
                       my_mac, limit_mbps, stop_event):
    log.error(f"[CORE ERROR] add_target_shaping for {ip} disabled.")
    return TrafficShaper(interface, ip, mac, router_ip, router_mac, my_mac, limit_mbps, stop_event)


def cleanup_traffic_shaping(shapers):
    shapers.clear()
