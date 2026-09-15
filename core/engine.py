"""
ThrottwinEngine — central singleton coordinating scanning, spoofing,
traffic shaping, telemetry, and SSE event streaming for the Web UI.
"""

import threading
import time
import logging
import queue

from .network import get_interfaces, get_default_gateway, get_scapy_interface
from .scanner import arp_scan, merge_devices, device_sort_key
from .spoof import arp_spoof_loop, get_router_mac, get_my_mac
from .shaping import (
    enable_ip_forwarding, disable_ip_forwarding,
    setup_traffic_shaping, add_target_shaping, cleanup_traffic_shaping
)
from .config import (
    load_config, save_config,
    get_predefined_whitelist, get_predefined_blacklist,
    load_predefined_rules, save_predefined_rules
)

log = logging.getLogger("throttwin")


class ThrottwinEngine:
    _instance = None
    _lock     = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_engine()
            return cls._instance

    # ─── Init ──────────────────────────────────────────────────────────────────

    def _init_engine(self):
        self.lock = threading.Lock()

        self.status            = "IDLE"   # IDLE | SCANNING | RUNNING | STOPPING
        self.devices           = []
        self.current_interface = None
        self.current_router_ip = None
        self.operational_mode  = "blacklist"
        self.limit_mbps        = 1.0

        self.targets    = []
        self.whitelisted = []
        self.session_start_time = None

        self.stop_event    = None
        self.spoof_threads = {}   # {ip: (thread, stop_evt)}
        self.shapers       = {}   # {ip: TrafficShaper}
        self.monitor_thread = None
        self.watcher_thread = None

        self.event_queues = []

        # Detect defaults
        ifaces = get_interfaces()
        if ifaces:
            self.current_interface = ifaces[0]
            self.current_router_ip = get_default_gateway(self.current_interface) or "192.168.1.1"

        # Background device discovery
        self._bg_stop = threading.Event()
        self._bg_thread = threading.Thread(target=self._bg_discovery_worker, daemon=True)
        self._bg_thread.start()

    # ─── SSE Events ────────────────────────────────────────────────────────────

    def subscribe_events(self):
        q = queue.Queue(maxsize=200)
        with self.lock:
            self.event_queues.append(q)
        return q

    def unsubscribe_events(self, q):
        with self.lock:
            if q in self.event_queues:
                self.event_queues.remove(q)

    def broadcast_event(self, event_type, data):
        msg = {"type": event_type, "data": data, "timestamp": time.time()}
        with self.lock:
            for q in list(self.event_queues):
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass

    # ─── Scanning ──────────────────────────────────────────────────────────────

    def scan(self, interface=None, router_ip=None):
        iface  = interface  or self.current_interface
        router = router_ip  or self.current_router_ip
        if not iface or not router:
            return self.devices

        with self.lock:
            was_running = self.status == "RUNNING"
            if not was_running:
                self.status = "SCANNING"

        try:
            fresh = arp_scan(iface, router)
            with self.lock:
                prev_count  = len(self.devices)
                self.devices = merge_devices(self.devices, fresh)
                self.current_interface = iface
                self.current_router_ip = router
                devices_snap = list(self.devices)

            if len(devices_snap) > prev_count:
                self.broadcast_event("devices_updated", {
                    "devices":   devices_snap,
                    "new_count": len(devices_snap) - prev_count
                })
            return devices_snap
        finally:
            with self.lock:
                if not was_running:
                    self.status = "IDLE"

    def _bg_discovery_worker(self):
        while not self._bg_stop.is_set():
            if self._bg_stop.wait(15):
                break
            if not self.current_interface or not self.current_router_ip:
                continue
            try:
                fresh = arp_scan(self.current_interface, self.current_router_ip)
                if fresh:
                    with self.lock:
                        prev_ips = {d.get("ip") for d in self.devices}
                        self.devices = merge_devices(self.devices, fresh)
                        new_devs = [d for d in self.devices if d.get("ip") not in prev_ips]
                    if new_devs:
                        self.broadcast_event("devices_discovered", {
                            "new_devices": new_devs,
                            "all_devices": list(self.devices)
                        })
            except Exception:
                pass

    def get_interfaces(self):
        return get_interfaces()

    def get_default_gateway(self, interface=None):
        return get_default_gateway(interface or self.current_interface)

    def add_manual_device(self, ip=None, mac=None, vendor="Manual Entry", hostname=""):
        with self.lock:
            mac_clean = (mac or "").replace("-", ":").strip().lower() or "Unknown"
            ip_clean  = (ip or "").strip() or "-"
            dev = {"ip": ip_clean, "mac": mac_clean, "vendor": vendor or "Manual Entry", "hostname": hostname or ""}

            existing_idx = None
            for idx, d in enumerate(self.devices):
                d_mac = d.get("mac", "").lower()
                if (mac_clean not in ("unknown", "") and d_mac == mac_clean) \
                        or (ip_clean != "-" and d.get("ip") == ip_clean):
                    existing_idx = idx
                    break

            if existing_idx is not None:
                self.devices[existing_idx] = dev
            else:
                self.devices.append(dev)
            self.devices.sort(key=device_sort_key)

        self.broadcast_event("device_added", {"device": dev, "all_devices": list(self.devices)})
        return dev

    def clear_cache(self):
        with self.lock:
            if self.status == "RUNNING":
                return False, "Cannot clear cache while session is running."
            self.devices = []
        self.broadcast_event("cache_cleared", {})
        return True, "Device cache cleared."

    # ─── Session ───────────────────────────────────────────────────────────────

    def start_session(self, interface, router_ip, mode, targets, limit_mbps, whitelisted=None):
        with self.lock:
            if self.status == "RUNNING":
                return False, "A session is already running."
            self.status = "RUNNING"
            self.current_interface = interface
            self.current_router_ip = router_ip
            self.operational_mode  = mode
            self.limit_mbps        = float(limit_mbps)

            global_wl_macs = {m.lower() for m in get_predefined_whitelist().keys()}
            safe_macs = set(global_wl_macs)
            raw_wl = list(whitelisted or [])
            for dev in raw_wl:
                if isinstance(dev, dict) and dev.get("mac"):
                    safe_macs.add(dev["mac"].lower())
            safe_ips = {
                (dev.get("ip") if isinstance(dev, dict) else dev)
                for dev in raw_wl
                if (dev.get("ip") if isinstance(dev, dict) else dev)
            }

            filtered = []
            for tgt in targets:
                tgt_ip  = tgt.get("ip")  if isinstance(tgt, dict) else tgt
                tgt_mac = (tgt.get("mac") if isinstance(tgt, dict) else "").lower()
                if (tgt_mac and tgt_mac in safe_macs) or (tgt_ip and tgt_ip in safe_ips):
                    continue
                filtered.append(tgt)

            self.targets          = filtered
            self.whitelisted      = raw_wl
            self.session_start_time = time.time()
            self.stop_event       = threading.Event()
            self.spoof_threads    = {}
            self.shapers          = {}

        try:
            enable_ip_forwarding()

            router_mac = get_router_mac(router_ip, interface)
            my_mac     = get_my_mac(interface)

            if not router_mac:
                self.status = "IDLE"
                return False, f"Could not resolve router MAC for {router_ip}. Are you on the right interface?"
            if not my_mac:
                self.status = "IDLE"
                return False, "Could not determine local MAC address."

            self.shapers = setup_traffic_shaping(
                interface, self.targets, self.limit_mbps,
                router_ip, router_mac, my_mac, self.stop_event
            )

            for tgt in self.targets:
                tgt_ip  = tgt.get("ip")  if isinstance(tgt, dict) else tgt
                tgt_mac = tgt.get("mac") if isinstance(tgt, dict) else ""
                if tgt_ip and tgt_ip != "-":
                    self._spawn_spoofer(interface, tgt_ip, tgt_mac, router_ip, router_mac, my_mac)

            save_config(interface, router_ip, mode, self.targets, self.limit_mbps,
                        whitelisted=self.whitelisted)

            self.broadcast_event("session_started", self.get_state())
            return True, "Session started successfully."
        except Exception as e:
            log.error(f"Failed to start session: {e}")
            self._do_stop()
            return False, str(e)

    def _spawn_spoofer(self, interface, target_ip, target_mac, router_ip, router_mac, my_mac):
        evt = threading.Event()
        t   = threading.Thread(
            target=arp_spoof_loop,
            args=(interface, target_ip, target_mac, router_ip, router_mac, my_mac, evt),
            daemon=True
        )
        t.start()
        self.spoof_threads[target_ip] = (t, evt)

    def _stop_spoofer(self, target_ip):
        if target_ip in self.spoof_threads:
            t, evt = self.spoof_threads.pop(target_ip)
            evt.set()
            t.join(timeout=3)

    def update_limit(self, new_limit_mbps):
        with self.lock:
            self.limit_mbps = float(new_limit_mbps)
            for shaper in self.shapers.values():
                shaper.update_limit(self.limit_mbps)
        self.broadcast_event("limit_updated", {"limit_mbps": self.limit_mbps})
        return True, f"Limit updated to {self.limit_mbps} Mbps."

    def toggle_target(self, ip, should_throttle):
        with self.lock:
            if self.status != "RUNNING":
                return False, "No session running."

            target_dev = next((d for d in self.devices if d.get("ip") == ip), {"ip": ip, "mac": "Unknown", "vendor": "Unknown"})
            dev_mac    = (target_dev.get("mac") or "").lower()
            global_wl  = {m.lower() for m in get_predefined_whitelist().keys()}
            session_wl = {(w.get("mac") if isinstance(w, dict) else "").lower() for w in self.whitelisted}

            if should_throttle:
                if dev_mac and (dev_mac in global_wl or dev_mac in session_wl):
                    return False, f"{ip} is protected by whitelist."
                if ip in self.shapers:
                    return True, f"{ip} is already being throttled."

                router_mac = get_router_mac(self.current_router_ip, self.current_interface)
                my_mac     = get_my_mac(self.current_interface)
                shaper = add_target_shaping(
                    self.current_interface, ip, dev_mac,
                    self.current_router_ip, router_mac, my_mac,
                    self.limit_mbps, self.stop_event
                )
                self.shapers[ip] = shaper
                self._spawn_spoofer(self.current_interface, ip, dev_mac,
                                    self.current_router_ip, router_mac, my_mac)
                self.targets.append(target_dev)
                msg = f"Started throttling {ip}."
            else:
                if ip not in self.shapers:
                    return True, f"{ip} is not currently throttled."
                self._stop_spoofer(ip)
                del self.shapers[ip]
                self.targets = [t for t in self.targets if (t.get("ip") if isinstance(t, dict) else t) != ip]
                msg = f"Stopped throttling {ip}."

        self.broadcast_event("target_toggled", {"ip": ip, "throttled": should_throttle, "state": self.get_state()})
        return True, msg

    def stop_session(self):
        with self.lock:
            if self.status not in ("RUNNING", "STOPPING"):
                return True, "No session running."
            self.status = "STOPPING"
        self._do_stop()
        return True, "Session stopped and network restored."

    def _do_stop(self):
        if self.stop_event:
            self.stop_event.set()

        for ip, (t, evt) in list(self.spoof_threads.items()):
            evt.set()
        for ip, (t, evt) in list(self.spoof_threads.items()):
            t.join(timeout=2)
        self.spoof_threads.clear()

        cleanup_traffic_shaping(self.shapers)
        disable_ip_forwarding()

        with self.lock:
            self.status             = "IDLE"
            self.session_start_time = None
            self.shapers            = {}

        self.broadcast_event("session_stopped", self.get_state())

    # ─── State ─────────────────────────────────────────────────────────────────

    def get_state(self):
        with self.lock:
            uptime = time.time() - self.session_start_time if self.session_start_time else 0.0

            telemetry = {}
            total_speed_bps = 0.0
            total_bytes     = 0
            for ip, shaper in self.shapers.items():
                speed_mbps = shaper.get_speed_mbps()
                total_speed_bps += speed_mbps * 1_000_000 / 8
                total_bytes     += shaper.total_bytes
                telemetry[ip] = {
                    "speed_mbps":  round(speed_mbps, 3),
                    "speed_kbps":  round(speed_mbps * 1000, 1),
                    "total_bytes": shaper.total_bytes,
                    "mac":         next((t.get("mac","") for t in self.targets if (t.get("ip") if isinstance(t,dict) else t)==ip), ""),
                    "vendor":      next((t.get("vendor","") for t in self.targets if (t.get("ip") if isinstance(t,dict) else t)==ip), ""),
                }

            return {
                "status":           self.status,
                "interface":        self.current_interface,
                "router_ip":        self.current_router_ip,
                "operational_mode": self.operational_mode,
                "limit_mbps":       self.limit_mbps,
                "uptime":           round(uptime, 1),
                "target_count":     len(self.targets),
                "targets":          list(self.targets),
                "whitelisted":      list(self.whitelisted),
                "devices":          list(self.devices),
                "telemetry":        telemetry,
                "total_speed_kbps": round(total_speed_bps / 125, 1),
                "total_speed_mbps": round(total_speed_bps / 125000, 3),
                "total_data_mb":    round(total_bytes / (1024 * 1024), 2),
            }
