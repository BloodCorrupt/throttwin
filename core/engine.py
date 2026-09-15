"""
ThrottwinEngine — Multi-interface session registry coordinating scanning,
spoofing, traffic shaping, telemetry, and SSE event streaming for the Web UI.

Architecture:
  ThrottwinEngine (singleton)
    └── sessions: dict[str, InterfaceSession]
        └── Each session owns: devices, targets, shapers, spoof threads, bg discovery
"""

import threading
import time
import logging
import queue
import ipaddress

from .network import (
    get_interfaces, get_active_interfaces, get_default_gateway, get_scapy_interface,
    get_interface_ip_and_mac, resolve_mac_from_arp_cache, get_all_local_ips_and_macs
)
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


# ─── InterfaceSession ──────────────────────────────────────────────────────────

class InterfaceSession:
    """Independent throttling session for ONE interface+gateway pair."""

    def __init__(self, session_id, interface, router_ip, engine):
        self.session_id = session_id
        self.interface = interface
        self.router_ip = router_ip
        self.engine = engine  # back-reference for broadcasting

        self.lock = threading.Lock()

        self.status = "IDLE"
        self.link_status = "ONLINE"
        self.operational_mode = "blacklist"
        self.limit_mbps = 1.0

        self.devices = []
        self.targets = []
        self.whitelisted = []
        self.session_start_time = None

        self.stop_event = None
        self.spoof_threads = {}
        self.shapers = {}
        self.watcher_thread = None

        # Background device discovery
        self._bg_stop = threading.Event()
        self._bg_thread = threading.Thread(target=self._bg_discovery_worker, daemon=True)
        self._bg_thread.start()

    def get_subnet(self):
        """Return IPv4Network object for this session's interface."""
        try:
            import psutil
            addrs = psutil.net_if_addrs().get(self.interface, [])
            ip4 = [(a.address, a.netmask) for a in addrs if a.family.name == "AF_INET"
                   and not a.address.startswith("169.254") and a.address != "127.0.0.1"]
            if ip4:
                my_ip, netmask = ip4[0]
                return ipaddress.IPv4Network(f"{my_ip}/{netmask}", strict=False)
            elif self.router_ip and self.router_ip != "0.0.0.0":
                return ipaddress.IPv4Network(f"{self.router_ip}/24", strict=False)
        except Exception:
            pass
        return None

    # ─── Background Discovery ──────────────────────────────────────────────

    def _bg_discovery_worker(self):
        first_run = True
        while not self._bg_stop.is_set():
            delay = 1.0 if first_run else 8.0
            if self._bg_stop.wait(delay):
                break
            first_run = False

            if not self.interface or not self.router_ip or self.link_status == "DISCONNECTED":
                continue
            try:
                fresh = arp_scan(self.interface, self.router_ip)
                my_ip, my_mac = get_interface_ip_and_mac(self.interface)
                router_mac = resolve_mac_from_arp_cache(self.router_ip, interface_ip=my_ip)
                with self.lock:
                    prev_ips = {d.get("ip") for d in self.devices}
                    self.devices = merge_devices(
                        self.devices, fresh,
                        subnet_net=self.get_subnet(),
                        my_mac=my_mac, my_ip=my_ip,
                        router_ip=self.router_ip, router_mac=router_mac
                    )
                    new_devs = [d for d in self.devices if d.get("ip") not in prev_ips]
                    all_devs = list(self.devices)

                    if new_devs:
                        self.engine.broadcast_event("devices_discovered", {
                            "session_id": self.session_id,
                            "new_devices": new_devs,
                            "all_devices": all_devs
                        })
                    elif len(all_devs) > len(prev_ips):
                        self.engine.broadcast_event("devices_updated", {
                            "session_id": self.session_id,
                            "devices": all_devs
                        })
            except Exception as e:
                log.debug(f"[{self.session_id}] Background discovery error: {e}")

    def stop_bg_discovery(self):
        self._bg_stop.set()

    # ─── Hot Link Status & Auto-Rebind ─────────────────────────────────────

    def on_link_status_change(self, new_status, new_gateway=None):
        """Handle interface state changes (connect, disconnect, gateway renewal)."""
        with self.lock:
            old_status = self.link_status
            self.link_status = new_status
            if new_gateway and new_gateway != self.router_ip:
                self.router_ip = new_gateway

        if old_status != new_status:
            log.info(f"[{self.session_id}] Interface link status changed: {old_status} -> {new_status}")
            self.engine.broadcast_event("interface_status_changed", {
                "session_id": self.session_id,
                "interface": self.interface,
                "link_status": new_status,
                "router_ip": self.router_ip,
                "state": self.get_state()
            })

            # If reconnected while session was running: auto-rebind!
            if old_status == "DISCONNECTED" and new_status == "ONLINE" and self.status == "RUNNING":
                threading.Thread(target=self._rebind_running_session, daemon=True).start()

    def _rebind_running_session(self):
        """Re-resolve MACs and refresh spoofers/shapers when interface recovers."""
        try:
            time.sleep(1.0)  # Short pause for DHCP/ARP table settling
            router_mac = get_router_mac(self.router_ip, self.interface)
            my_mac = get_my_mac(self.interface)
            if not router_mac or not my_mac:
                log.debug(f"[{self.session_id}] Rebind delayed: router MAC not yet reachable.")
                return

            log.info(f"[{self.session_id}] Auto-rebinding running session on reconnected interface...")
            cleanup_traffic_shaping(self.shapers)
            self.shapers = setup_traffic_shaping(
                self.interface, self.targets, self.limit_mbps,
                self.router_ip, router_mac, my_mac, self.stop_event
            )

            for ip, (t, evt) in list(self.spoof_threads.items()):
                evt.set()
            self.spoof_threads.clear()

            for tgt in self.targets:
                tgt_ip = tgt.get("ip") if isinstance(tgt, dict) else tgt
                tgt_mac = tgt.get("mac") if isinstance(tgt, dict) else ""
                if tgt_ip and tgt_ip != "-":
                    self._spawn_spoofer(tgt_ip, tgt_mac, router_mac, my_mac)

            self.engine.broadcast_event("session_reconnected", {
                "session_id": self.session_id,
                **self.get_state()
            })
            log.info(f"[{self.session_id}] Session successfully restored after reconnect.")
        except Exception as e:
            log.debug(f"[{self.session_id}] Rebind error: {e}")

    # ─── Scanning ──────────────────────────────────────────────────────────

    def scan(self):
        if not self.interface or not self.router_ip:
            return self.devices
        fresh = arp_scan(self.interface, self.router_ip)
        my_ip, my_mac = get_interface_ip_and_mac(self.interface)
        router_mac = resolve_mac_from_arp_cache(self.router_ip, interface_ip=my_ip)
        with self.lock:
            prev_count = len(self.devices)
            self.devices = merge_devices(
                self.devices, fresh,
                subnet_net=self.get_subnet(),
                my_mac=my_mac, my_ip=my_ip,
                router_ip=self.router_ip, router_mac=router_mac
            )
            devices_snap = list(self.devices)
        if len(devices_snap) > prev_count:
            self.engine.broadcast_event("devices_updated", {
                "session_id": self.session_id,
                "devices": devices_snap,
                "new_count": len(devices_snap) - prev_count
            })
        return devices_snap

    def add_manual_device(self, ip=None, mac=None, vendor="Manual Entry", hostname=""):
        with self.lock:
            mac_clean = (mac or "").replace("-", ":").strip().lower() or "Unknown"
            ip_clean = (ip or "").strip() or "-"
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

        self.engine.broadcast_event("device_added", {
            "session_id": self.session_id,
            "device": dev,
            "all_devices": list(self.devices)
        })
        return dev

    def clear_cache(self):
        with self.lock:
            if self.status == "RUNNING":
                return False, "Cannot clear cache while session is running."
            self.devices = []
        self.engine.broadcast_event("cache_cleared", {"session_id": self.session_id})
        return True, "Device cache cleared."

    # ─── Session Control ───────────────────────────────────────────────────

    def start_session(self, mode, targets, limit_mbps, whitelisted=None):
        with self.lock:
            if self.status == "RUNNING":
                return False, "A session is already running on this interface."
            self.status = "RUNNING"
            self.operational_mode = mode
            self.limit_mbps = float(limit_mbps)

            all_host_ips, all_host_macs = get_all_local_ips_and_macs()
            my_ip, my_mac = get_interface_ip_and_mac(self.interface)

            global_wl_macs = {m.lower().replace("-", ":") for m in get_predefined_whitelist().keys()}
            safe_macs = set(global_wl_macs)
            safe_macs.update(all_host_macs)
            if my_mac:
                safe_macs.add(my_mac.lower().replace("-", ":"))

            raw_wl = list(whitelisted or [])
            for dev in raw_wl:
                if isinstance(dev, dict) and dev.get("mac"):
                    safe_macs.add(dev["mac"].lower().replace("-", ":"))

            safe_ips = set(all_host_ips)
            if my_ip:
                safe_ips.add(my_ip)
            if self.router_ip:
                safe_ips.add(self.router_ip)

            for dev in raw_wl:
                ip_val = dev.get("ip") if isinstance(dev, dict) else dev
                if ip_val and ip_val != "-":
                    safe_ips.add(ip_val)

            # Resolve router MAC
            router_mac = get_router_mac(self.router_ip, self.interface)
            if router_mac:
                safe_macs.add(router_mac.lower().replace("-", ":"))

            filtered = []
            for tgt in targets:
                tgt_ip = tgt.get("ip") if isinstance(tgt, dict) else tgt
                tgt_mac = (tgt.get("mac") if isinstance(tgt, dict) else "").lower().replace("-", ":")
                if (
                    not tgt_ip
                    or tgt_ip in safe_ips
                    or tgt_mac in safe_macs
                    or tgt_ip in all_host_ips
                    or tgt_mac in all_host_macs
                    or tgt_ip == self.router_ip
                    or (router_mac and tgt_mac == router_mac.lower().replace("-", ":"))
                ):
                    continue
                filtered.append(tgt)

            self.targets = filtered
            self.whitelisted = raw_wl
            self.session_start_time = time.time()
            self.stop_event = threading.Event()
            self.spoof_threads = {}
            self.shapers = {}

        try:
            enable_ip_forwarding()

            if not router_mac:
                router_mac = get_router_mac(self.router_ip, self.interface)
            if not my_mac:
                my_mac = get_my_mac(self.interface)

            if not router_mac:
                self.status = "IDLE"
                return False, f"Could not resolve router MAC for {self.router_ip}. Are you on the right interface?"
            if not my_mac:
                self.status = "IDLE"
                return False, "Could not determine local MAC address."

            self.shapers = setup_traffic_shaping(
                self.interface, self.targets, self.limit_mbps,
                self.router_ip, router_mac, my_mac, self.stop_event
            )

            for tgt in self.targets:
                tgt_ip = tgt.get("ip") if isinstance(tgt, dict) else tgt
                tgt_mac = tgt.get("mac") if isinstance(tgt, dict) else ""
                if tgt_ip and tgt_ip != "-":
                    self._spawn_spoofer(tgt_ip, tgt_mac, router_mac, my_mac)

            save_config(self.interface, self.router_ip, mode, self.targets,
                        self.limit_mbps, whitelisted=self.whitelisted)

            # Start dynamic whitelist watcher if in whitelist mode
            if mode == "whitelist":
                self.watcher_thread = threading.Thread(
                    target=self._whitelist_watcher_worker, daemon=True)
                self.watcher_thread.start()

            self.engine.broadcast_event("session_started", {
                "session_id": self.session_id,
                **self.get_state()
            })
            return True, "Session started successfully."
        except Exception as e:
            log.error(f"[{self.session_id}] Failed to start session: {e}")
            self._do_stop()
            return False, str(e)

    def _spawn_spoofer(self, target_ip, target_mac, router_mac, my_mac):
        all_host_ips, all_host_macs = get_all_local_ips_and_macs()
        global_wl_macs = {m.lower().replace("-", ":") for m in get_predefined_whitelist().keys()}
        t_mac = (target_mac or "").lower().replace("-", ":")
        r_mac = (router_mac or "").lower().replace("-", ":")
        m_mac = (my_mac or "").lower().replace("-", ":")

        if (
            not target_ip
            or target_ip in ("-", "0.0.0.0", "127.0.0.1", self.router_ip)
            or target_ip in all_host_ips
            or t_mac in all_host_macs
            or t_mac in global_wl_macs
            or t_mac in (r_mac, m_mac)
        ):
            log.warning(f"[{self.session_id}] Refusing to spawn spoofer for host/gateway/whitelist: {target_ip} ({target_mac})")
            return

        evt = threading.Event()
        t = threading.Thread(
            target=arp_spoof_loop,
            args=(self.interface, target_ip, target_mac,
                  self.router_ip, router_mac, my_mac, evt),
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
        self.engine.broadcast_event("limit_updated", {
            "session_id": self.session_id,
            "limit_mbps": self.limit_mbps
        })
        return True, f"Limit updated to {self.limit_mbps} Mbps."

    def toggle_target(self, ip, should_throttle):
        with self.lock:
            if self.status != "RUNNING":
                return False, "No session running."

            target_dev = next((d for d in self.devices if d.get("ip") == ip),
                              {"ip": ip, "mac": "Unknown", "vendor": "Unknown"})
            dev_mac = (target_dev.get("mac") or "").lower()
            global_wl = {m.lower() for m in get_predefined_whitelist().keys()}
            session_wl = {(w.get("mac") if isinstance(w, dict) else "").lower()
                          for w in self.whitelisted}

            if should_throttle:
                if dev_mac and (dev_mac in global_wl or dev_mac in session_wl):
                    return False, f"{ip} is protected by whitelist."
                if ip in self.shapers:
                    return True, f"{ip} is already being throttled."

                router_mac = get_router_mac(self.router_ip, self.interface)
                my_mac = get_my_mac(self.interface)
                shaper = add_target_shaping(
                    self.interface, ip, dev_mac,
                    self.router_ip, router_mac, my_mac,
                    self.limit_mbps, self.stop_event
                )
                self.shapers[ip] = shaper
                self._spawn_spoofer(ip, dev_mac, router_mac, my_mac)
                self.targets.append(target_dev)
                msg = f"Started throttling {ip}."
            else:
                if ip not in self.shapers:
                    return True, f"{ip} is not currently throttled."
                self._stop_spoofer(ip)
                del self.shapers[ip]
                self.targets = [t for t in self.targets
                                if (t.get("ip") if isinstance(t, dict) else t) != ip]
                msg = f"Stopped throttling {ip}."

        self.engine.broadcast_event("target_toggled", {
            "session_id": self.session_id,
            "ip": ip,
            "throttled": should_throttle,
            "state": self.get_state()
        })
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

        if self.watcher_thread and self.watcher_thread.is_alive():
            self.watcher_thread = None

        cleanup_traffic_shaping(self.shapers)

        # Only disable IP forwarding if no other sessions are running
        any_running = any(
            s.status == "RUNNING" and s.session_id != self.session_id
            for s in self.engine.sessions.values()
        )
        if not any_running:
            disable_ip_forwarding()

        with self.lock:
            self.status = "IDLE"
            self.session_start_time = None
            self.shapers = {}

        self.engine.broadcast_event("session_stopped", {
            "session_id": self.session_id,
            **self.get_state()
        })

    def _whitelist_watcher_worker(self):
        """
        Dynamic high-speed ARP watcher for Whitelist Mode.
        Actively scans the local network every 8-10s. Any newly arriving device
        outside the whitelist is automatically throttled and spoofed on the fly
        without session interruption.
        Strictly protects the host machine and default gateway from being throttled.
        """
        while self.stop_event and not self.stop_event.is_set():
            if self.stop_event.wait(8):
                break
            if not self.interface or not self.router_ip or self.operational_mode != "whitelist":
                continue

            try:
                found = arp_scan(self.interface, self.router_ip)
            except Exception as e:
                log.warning(f"[{self.session_id}] Whitelist watcher scan error: {e}")
                continue

            all_host_ips, all_host_macs = get_all_local_ips_and_macs()
            my_ip, my_mac = get_interface_ip_and_mac(self.interface)
            router_mac = resolve_mac_from_arp_cache(self.router_ip, interface_ip=my_ip) or get_router_mac(self.router_ip, self.interface)

            safe_macs = {
                (dev.get("mac") if isinstance(dev, dict) else "").lower().replace("-", ":")
                for dev in self.whitelisted
                if isinstance(dev, dict) and dev.get("mac")
            }
            safe_macs.update(all_host_macs)
            for pmac in get_predefined_whitelist().keys():
                safe_macs.add(pmac.lower().replace("-", ":"))
            if router_mac:
                safe_macs.add(router_mac.lower().replace("-", ":"))
            if my_mac:
                safe_macs.add(my_mac.lower().replace("-", ":"))

            safe_ips = {
                (dev.get("ip") if isinstance(dev, dict) else dev)
                for dev in self.whitelisted
                if (dev.get("ip") if isinstance(dev, dict) else dev) and
                   (dev.get("ip") if isinstance(dev, dict) else dev) != "-"
            }
            safe_ips.update(all_host_ips)
            if self.router_ip:
                safe_ips.add(self.router_ip)
            if my_ip:
                safe_ips.add(my_ip)

            with self.lock:
                self.devices = merge_devices(
                    self.devices, found,
                    subnet_net=self.get_subnet(),
                    my_mac=my_mac, my_ip=my_ip,
                    router_ip=self.router_ip, router_mac=router_mac
                )

            for dev in found:
                if self.stop_event and self.stop_event.is_set():
                    break

                dev_ip = dev.get("ip")
                dev_mac = (dev.get("mac") or "").lower().replace("-", ":")

                if not dev_ip or dev_ip in ("-", "0.0.0.0", "127.0.0.1", self.router_ip):
                    continue

                if (
                    dev_mac in safe_macs
                    or dev_ip in safe_ips
                    or dev_ip in all_host_ips
                    or dev_mac in all_host_macs
                    or (my_ip and dev_ip == my_ip)
                    or (my_mac and dev_mac == my_mac.lower().replace("-", ":"))
                    or (router_mac and dev_mac == router_mac.lower().replace("-", ":"))
                ):
                    if dev_mac and dev_mac in safe_macs and dev_ip not in safe_ips:
                        safe_ips.add(dev_ip)
                    continue

                with self.lock:
                    if dev_ip in self.shapers:
                        continue

                    shaper = add_target_shaping(
                        self.interface, dev_ip, dev_mac,
                        self.router_ip, router_mac, my_mac,
                        self.limit_mbps, self.stop_event
                    )
                    self.shapers[dev_ip] = shaper
                    self._spawn_spoofer(dev_ip, dev_mac, router_mac, my_mac)
                    self.targets.append(dev)
                    log.info(f"[{self.session_id}] Auto-trapped: {dev_ip} ({dev_mac})")

                self.engine.broadcast_event("device_auto_throttled", {
                    "session_id": self.session_id,
                    "device": dev,
                    "limit_mbps": self.limit_mbps,
                    "target_count": len(self.targets),
                    "state": self.get_state()
                })

    # ─── State ─────────────────────────────────────────────────────────────

    def get_state(self):
        with self.lock:
            uptime = int(time.time() - self.session_start_time) if self.session_start_time else 0

            telemetry_list = []
            total_speed_kbps = 0.0
            total_bytes = 0

            for ip, shaper in self.shapers.items():
                speed_mbps = shaper.get_speed_mbps()
                speed_kbps = round(speed_mbps * 125.0, 1)
                total_speed_kbps += speed_kbps
                total_bytes += shaper.total_bytes

                target_dev = next(
                    (t for t in self.targets
                     if (t.get("ip") if isinstance(t, dict) else t) == ip), {})
                mac = target_dev.get("mac", "Unknown") if isinstance(target_dev, dict) else "Unknown"
                vendor = target_dev.get("vendor", "Unknown") if isinstance(target_dev, dict) else "Unknown"
                hostname = target_dev.get("hostname", "") if isinstance(target_dev, dict) else ""

                telemetry_list.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "speed_kbps": speed_kbps,
                    "speed_mbps": round(speed_mbps, 2),
                    "total_bytes": shaper.total_bytes,
                    "total_mb": round(shaper.total_bytes / (1024 * 1024), 2),
                    "is_online": True,
                    "is_new": getattr(shaper, "is_new", False)
                })

            return {
                "session_id": self.session_id,
                "status": self.status,
                "link_status": self.link_status,
                "interface": self.interface,
                "router_ip": self.router_ip,
                "operational_mode": self.operational_mode,
                "limit_mbps": self.limit_mbps,
                "uptime": uptime,
                "target_count": len(self.targets),
                "total_speed_kbps": round(total_speed_kbps, 1),
                "total_speed_mbps": round(total_speed_kbps / 125.0, 2),
                "total_data_mb": round(total_bytes / (1024 * 1024), 2),
                "targets": list(self.targets),
                "whitelisted": list(self.whitelisted),
                "devices": list(self.devices),
                "telemetry": telemetry_list
            }

    def destroy(self):
        """Tear down this session completely."""
        if self.status == "RUNNING":
            self.stop_session()
        self.stop_bg_discovery()


# ─── ThrottwinEngine — Session Registry ────────────────────────────────────────

class ThrottwinEngine:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_engine()
            return cls._instance

    def _init_engine(self):
        self.lock = threading.Lock()
        self.sessions = {}        # {session_id: InterfaceSession}
        self.event_queues = []

        # Auto-detect all active interfaces and create sessions
        self._auto_detect_sessions()

        # Continuous background interface hot-plug / disconnect monitor daemon
        self._monitor_stop = threading.Event()
        self._monitor_thread = threading.Thread(target=self._interface_monitor_worker, daemon=True)
        self._monitor_thread.start()

    def _auto_detect_sessions(self):
        """Create an InterfaceSession for each active interface with a gateway."""
        ifaces = get_active_interfaces()
        for iface in ifaces:
            name = iface["name"]
            gateway = iface.get("gateway")
            if gateway and name not in self.sessions:
                self.sessions[name] = InterfaceSession(
                    session_id=name,
                    interface=name,
                    router_ip=gateway,
                    engine=self
                )
                log.info(f"Auto-created session: {name} (gateway: {gateway})")

        # If no sessions were created, create one for the first interface
        if not self.sessions and ifaces:
            first = ifaces[0]
            gw = first.get("gateway") or get_default_gateway(first["name"]) or "192.168.1.1"
            self.sessions[first["name"]] = InterfaceSession(
                session_id=first["name"],
                interface=first["name"],
                router_ip=gw,
                engine=self
            )

    def _interface_monitor_worker(self):
        """
        Continuous daemon monitoring for interface hot-plug, disconnect, and reconnect.
        Runs every 2.5s to detect physical adapter insertions, link-drops, and gateway updates.
        """
        last_iface_set = set()
        while not self._monitor_stop.is_set():
            if self._monitor_stop.wait(2.5):
                break
            try:
                active_ifaces = get_active_interfaces()
                active_map = {i["name"]: i for i in active_ifaces}
                current_iface_set = set(active_map.keys())

                # 1. Update link state and gateway for all registered sessions
                for sid, session in list(self.sessions.items()):
                    iface_name = session.interface
                    if iface_name in active_map:
                        gw = active_map[iface_name].get("gateway")
                        session.on_link_status_change("ONLINE", new_gateway=gw)
                    else:
                        session.on_link_status_change("DISCONNECTED")

                # 2. Check for hot-plugged new interfaces
                changed = current_iface_set != last_iface_set
                for iface in active_ifaces:
                    name = iface["name"]
                    gateway = iface.get("gateway")
                    if gateway and name not in self.sessions:
                        new_session = InterfaceSession(
                            session_id=name,
                            interface=name,
                            router_ip=gateway,
                            engine=self
                        )
                        self.sessions[name] = new_session
                        changed = True
                        log.info(f"Hot-detected new interface: {name} (gateway: {gateway})")
                        self.broadcast_event("session_created", {
                            "session_id": name,
                            "interface": name,
                            "router_ip": gateway,
                        })

                if changed:
                    last_iface_set = current_iface_set
                    self.broadcast_event("interfaces_updated", {
                        "interfaces": [i["name"] for i in active_ifaces],
                        "interfaces_full": active_ifaces,
                        "sessions": self.get_all_sessions_state(),
                        "session_ids": list(self.sessions.keys())
                    })

            except Exception as e:
                log.debug(f"Interface monitor error: {e}")

    # ─── SSE Events ────────────────────────────────────────────────────────

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

    # ─── Session Management ────────────────────────────────────────────────

    def get_session(self, session_id=None):
        """Get a specific session by ID, or the first session if no ID given."""
        if session_id and session_id in self.sessions:
            return self.sessions[session_id]
        if self.sessions:
            return next(iter(self.sessions.values()))
        return None

    def create_session(self, interface, router_ip=None):
        """Create a new session for an interface."""
        if interface in self.sessions:
            return self.sessions[interface], "Session already exists."
        gw = router_ip or get_default_gateway(interface) or "192.168.1.1"
        session = InterfaceSession(
            session_id=interface,
            interface=interface,
            router_ip=gw,
            engine=self
        )
        self.sessions[interface] = session
        self.broadcast_event("session_created", {
            "session_id": interface,
            "interface": interface,
            "router_ip": gw,
        })
        log.info(f"Created session: {interface} (gateway: {gw})")
        return session, "Session created."

    def delete_session(self, session_id):
        """Delete a session (must be IDLE)."""
        session = self.sessions.get(session_id)
        if not session:
            return False, "Session not found."
        if session.status == "RUNNING":
            return False, "Cannot delete a running session. Stop it first."
        session.destroy()
        del self.sessions[session_id]
        self.broadcast_event("session_deleted", {"session_id": session_id})
        return True, f"Session '{session_id}' deleted."

    # ─── Compatibility Helpers ─────────────────────────────────────────────
    # These maintain backward compatibility with existing code paths

    def get_interfaces(self):
        return get_interfaces()

    def get_active_interfaces_full(self):
        return get_active_interfaces()

    def get_default_gateway(self, interface=None):
        return get_default_gateway(interface)

    # ─── Aggregate State ───────────────────────────────────────────────────

    def get_all_sessions_state(self):
        """Return state for all sessions."""
        states = {}
        for sid, session in self.sessions.items():
            states[sid] = session.get_state()
        return states

    def get_state(self, session_id=None):
        """Get state for a specific session (backward compat)."""
        session = self.get_session(session_id)
        if session:
            return session.get_state()
        # Empty default state
        return {
            "session_id": None,
            "status": "IDLE",
            "interface": None,
            "router_ip": None,
            "operational_mode": "blacklist",
            "limit_mbps": 1.0,
            "uptime": 0,
            "target_count": 0,
            "total_speed_kbps": 0,
            "total_speed_mbps": 0,
            "total_data_mb": 0,
            "targets": [],
            "whitelisted": [],
            "devices": [],
            "telemetry": []
        }
