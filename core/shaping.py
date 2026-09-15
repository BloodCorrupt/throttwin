"""
Traffic shaping for Windows via Scapy packet interception + Token Bucket.

How it works:
  1. We ARP-spoof the target so its traffic is routed through our machine.
  2. We sniff those intercepted packets on the interface with Scapy.
  3. A Token Bucket rate-limiter enforces the bandwidth cap.
  4. Conforming packets are re-injected (forwarded) with corrected MACs.
  5. Byte counters feed into per-target telemetry for the live monitor.

This replaces Linux `tc` (HTB qdisc) entirely with a pure-Python solution.
"""

import time
import threading
import logging
import queue

log = logging.getLogger("throttwin")

# We track per-IP shapers keyed by target IP
_shapers = {}   # {ip: TrafficShaper}
_lock = threading.Lock()


class TokenBucket:
    """
    Standard token-bucket rate limiter.
    `rate_bps`   — allowed bytes per second (the cap)
    `burst_bytes` — max burst size (headroom above steady rate)
    """

    def __init__(self, rate_bps, burst_factor=1.5):
        self.rate_bps    = rate_bps
        self.capacity    = max(rate_bps * burst_factor, 8192)
        self.tokens      = self.capacity
        self._last_refill = time.monotonic()
        self._lock       = threading.Lock()

    def update_rate(self, rate_bps, burst_factor=1.5):
        with self._lock:
            self.rate_bps = rate_bps
            self.capacity = max(rate_bps * burst_factor, 8192)

    def consume(self, n_bytes):
        """
        Attempt to consume n_bytes of tokens.
        Returns True immediately if tokens available, False if packet should be dropped/delayed.
        """
        with self._lock:
            now     = time.monotonic()
            elapsed = now - self._last_refill
            self._last_refill = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_bps)

            if self.tokens >= n_bytes:
                self.tokens -= n_bytes
                return True
            return False


class TrafficShaper:
    """
    Per-target traffic shaper.
    Sniffs packets from the target, rate-limits them, then forwards.
    Collects telemetry (bytes, speed).
    """

    def __init__(self, interface, target_ip, target_mac, router_ip, router_mac,
                 my_mac, limit_mbps, stop_event):
        self.interface  = interface
        self.target_ip  = target_ip
        self.target_mac = target_mac
        self.router_ip  = router_ip
        self.router_mac = router_mac
        self.my_mac     = my_mac
        self.stop_event = stop_event

        self.observed_ipv6_addrs = set()

        rate_bps = int(limit_mbps * 1_000_000 / 8)
        self.bucket = TokenBucket(rate_bps)

        self.total_bytes     = 0
        self.last_bytes      = 0
        self.last_speed_time = time.monotonic()
        self.speed_bps       = 0.0

        self._pkt_queue  = queue.Queue(maxsize=512)
        self._fwd_thread = threading.Thread(target=self._forwarder, daemon=True)
        self._sniff_thread = threading.Thread(target=self._sniffer, daemon=True)

    def start(self):
        self._fwd_thread.start()
        self._sniff_thread.start()
        log.info(f"Traffic shaper started for {self.target_ip} @ {self.bucket.rate_bps/125000:.2f} Mbps")

    def update_limit(self, limit_mbps):
        rate_bps = int(limit_mbps * 1_000_000 / 8)
        self.bucket.update_rate(rate_bps)
        log.info(f"Updated limit for {self.target_ip} to {limit_mbps} Mbps")

    def get_speed_mbps(self):
        """Return current throughput in Mbps (computed over last ~1s)."""
        now     = time.monotonic()
        elapsed = now - self.last_speed_time
        if elapsed >= 0.5:
            delta = self.total_bytes - self.last_bytes
            self.speed_bps    = (delta * 8) / elapsed
            self.last_bytes   = self.total_bytes
            self.last_speed_time = now
        return self.speed_bps / 1_000_000

    def _sniffer(self):
        """Capture both IPv4 and IPv6 packets from the intercepted target on our interface with auto-recovery."""
        from scapy.all import sniff
        from .network import get_scapy_interface

        # Capture:
        # 1. Upstream: all packets sent from target MAC (both IPv4 and IPv6)
        # 2. Downstream IPv4: all packets returning from router to target IPv4
        # 3. Downstream IPv6: all intercepted IPv6 packets from router to our MAC
        if self.target_mac and self.target_mac not in ("unknown", "Unknown", "-", ""):
            bpf = f"(ether src {self.target_mac}) or (dst host {self.target_ip}) or (ether src {self.router_mac} and ip6 and ether dst {self.my_mac})"
        else:
            bpf = f"src host {self.target_ip} or dst host {self.target_ip}"

        while not self.stop_event.is_set():
            try:
                npf_iface = get_scapy_interface(self.interface)
                sniff(
                    iface=npf_iface,
                    filter=bpf,
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _: self.stop_event.is_set(),
                )
            except Exception as e:
                log.debug(f"Sniffer error for {self.target_ip} (interface may be reconnecting): {e}")
                if self.stop_event.wait(1.5):
                    break

    def _on_packet(self, pkt):
        """Queue captured packet for rate-limited forwarding."""
        try:
            self._pkt_queue.put_nowait(pkt)
        except queue.Full:
            pass  # Drop when queue full (congestion control)

    def _forwarder(self):
        """Dequeue packets, apply token-bucket limit, then forward with dual-stack IPv4/IPv6 support."""
        try:
            from scapy.all import Ether, IP, sendp
            from scapy.layers.inet6 import IPv6
            from .network import get_scapy_interface
            npf_iface = get_scapy_interface(self.interface)

            target_mac_lower = (self.target_mac or "").lower()
            router_mac_lower = (self.router_mac or "").lower()
            my_mac_lower = (self.my_mac or "").lower()

            while not self.stop_event.is_set():
                try:
                    pkt = self._pkt_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                if Ether not in pkt:
                    continue

                pkt_src_mac = pkt[Ether].src.lower()
                pkt_dst_mac = pkt[Ether].dst.lower()

                # Avoid looping our own forwarded packets
                if pkt_src_mac == my_mac_lower:
                    continue

                # Dynamically learn target's outbound IPv6 addresses
                if IPv6 in pkt and pkt_src_mac == target_mac_lower:
                    self.observed_ipv6_addrs.add(pkt[IPv6].src.lower())

                # Classify stream direction:
                is_upstream = (pkt_src_mac == target_mac_lower) or (IP in pkt and pkt[IP].src == self.target_ip)
                is_downstream = (IP in pkt and pkt[IP].dst == self.target_ip) or (IPv6 in pkt and pkt[IPv6].dst.lower() in self.observed_ipv6_addrs) or (pkt_src_mac == router_mac_lower and pkt_dst_mac == my_mac_lower)

                if not is_upstream and not is_downstream:
                    continue

                pkt_len = len(pkt)

                # Token bucket: drop if over limit (meters both IPv4 and IPv6 traffic)
                if not self.bucket.consume(pkt_len):
                    continue  # Packet dropped — enforcing rate limit

                self.total_bytes += pkt_len

                # Rewrite MACs for forwarding (dual-stack IPv4 and IPv6):
                # Packets FROM target → send to router MAC
                # Packets TO target   → send to target MAC
                try:
                    if is_upstream:
                        if IP in pkt:
                            fwd = Ether(src=self.my_mac, dst=self.router_mac) / pkt[IP]
                        elif IPv6 in pkt:
                            fwd = Ether(src=self.my_mac, dst=self.router_mac) / pkt[IPv6]
                        else:
                            fwd = Ether(src=self.my_mac, dst=self.router_mac) / pkt.payload
                        sendp(fwd, iface=npf_iface, verbose=0)
                    else:
                        if IP in pkt:
                            fwd = Ether(src=self.my_mac, dst=self.target_mac) / pkt[IP]
                        elif IPv6 in pkt:
                            fwd = Ether(src=self.my_mac, dst=self.target_mac) / pkt[IPv6]
                        else:
                            fwd = Ether(src=self.my_mac, dst=self.target_mac) / pkt.payload
                        sendp(fwd, iface=npf_iface, verbose=0)
                except Exception as e:
                    log.debug(f"Forward error (interface reconnecting?): {e}")
                    npf_iface = get_scapy_interface(self.interface)

        except Exception as e:
            log.debug(f"Forwarder error for {self.target_ip}: {e}")


def enable_ip_forwarding():
    """
    Enable dual-stack IPv4 and IPv6 forwarding on Windows via registry + netsh.
    Required so that intercepted packets can be forwarded.
    """
    try:
        import subprocess
        # Enable IPv4 & IPv6 routing via netsh
        subprocess.run(
            "netsh int ipv4 set global forwarding=enabled",
            shell=True, capture_output=True
        )
        subprocess.run(
            "netsh int ipv6 set global forwarding=enabled",
            shell=True, capture_output=True
        )
        # Also set via registry for persistence across reboots
        subprocess.run(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
            r'/v IPEnableRouter /t REG_DWORD /d 1 /f',
            shell=True, capture_output=True
        )
        subprocess.run(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" '
            r'/v IPEnableRouter /t REG_DWORD /d 1 /f',
            shell=True, capture_output=True
        )
        log.info("Dual-stack IPv4/IPv6 forwarding enabled.")
    except Exception as e:
        log.warning(f"Could not enable IP forwarding: {e}")


def disable_ip_forwarding():
    """Disable dual-stack IP forwarding after session ends."""
    try:
        import subprocess
        subprocess.run(
            "netsh int ipv4 set global forwarding=disabled",
            shell=True, capture_output=True
        )
        subprocess.run(
            "netsh int ipv6 set global forwarding=disabled",
            shell=True, capture_output=True
        )
        subprocess.run(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
            r'/v IPEnableRouter /t REG_DWORD /d 0 /f',
            shell=True, capture_output=True
        )
        subprocess.run(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" '
            r'/v IPEnableRouter /t REG_DWORD /d 0 /f',
            shell=True, capture_output=True
        )
        log.info("Dual-stack IPv4/IPv6 forwarding disabled.")
    except Exception as e:
        log.warning(f"Could not disable IP forwarding: {e}")


def setup_traffic_shaping(interface, targets, limit_mbps, router_ip,
                          router_mac, my_mac, stop_event):
    """
    Start TrafficShaper instances for each target.
    Returns dict of {ip: TrafficShaper}.
    """
    shapers = {}
    for tgt in targets:
        ip  = tgt.get("ip") if isinstance(tgt, dict) else tgt
        mac = tgt.get("mac", "") if isinstance(tgt, dict) else ""
        if not ip or ip == "-":
            continue
        shaper = TrafficShaper(
            interface=interface,
            target_ip=ip,
            target_mac=mac,
            router_ip=router_ip,
            router_mac=router_mac,
            my_mac=my_mac,
            limit_mbps=limit_mbps,
            stop_event=stop_event,
        )
        shaper.start()
        shapers[ip] = shaper
    return shapers


def add_target_shaping(interface, ip, mac, router_ip, router_mac,
                       my_mac, limit_mbps, stop_event):
    """Hotplug a new target into a running session."""
    shaper = TrafficShaper(
        interface=interface,
        target_ip=ip,
        target_mac=mac,
        router_ip=router_ip,
        router_mac=router_mac,
        my_mac=my_mac,
        limit_mbps=limit_mbps,
        stop_event=stop_event,
    )
    shaper.start()
    return shaper


def cleanup_traffic_shaping(shapers):
    """Stop all shapers (stop_event does the actual stopping)."""
    log.info(f"Traffic shaping cleanup: {len(shapers)} shaper(s) stopped.")
    shapers.clear()
