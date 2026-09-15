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

try:
    from scapy.all import conf
    conf.sniff_promisc = False
except Exception:
    pass

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
        self.target_mac = (target_mac or "").lower().replace("-", ":")
        self.router_ip  = router_ip
        self.router_mac = (router_mac or "").lower().replace("-", ":")
        self.my_mac     = (my_mac or "").lower().replace("-", ":")
        self.stop_event = stop_event

        self.observed_ipv6_addrs = set()

        from .network import get_all_local_ips_and_macs, get_all_local_ipv6_addrs, mac_to_ipv6_ll
        all_ips, all_macs = get_all_local_ips_and_macs()
        self.local_ips = set(all_ips)
        self.local_macs = {m.lower().replace("-", ":") for m in all_macs}
        self.local_ipv6 = get_all_local_ipv6_addrs()
        self.target_ipv6_ll = mac_to_ipv6_ll(self.target_mac).lower() if self.target_mac else ""

        from .config import get_predefined_whitelist
        global_wl_macs = {m.lower().replace("-", ":") for m in get_predefined_whitelist().keys()}

        if (
            not self.target_ip
            or self.target_ip in ("-", "0.0.0.0", "127.0.0.1", self.router_ip)
            or self.target_ip in self.local_ips
            or self.target_mac in self.local_macs
            or self.target_mac in global_wl_macs
            or self.target_mac in (self.router_mac, self.my_mac)
        ):
            self._disabled = True
            log.warning(f"TrafficShaper disabled for self/gateway/whitelist: {self.target_ip} ({self.target_mac})")
        else:
            self._disabled = False

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
        if self._disabled:
            log.warning(f"Refusing to start TrafficShaper for self/gateway {self.target_ip}")
            return
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
        """Capture packets strictly from/to the intercepted target without over-matching host's traffic."""
        if self._disabled:
            return
        from scapy.all import sniff
        from .network import get_scapy_interface

        # Capture packets associated with this target strictly
        if self.target_mac and self.target_mac not in ("unknown", "Unknown", "-", ""):
            bpf = f"(ether src {self.target_mac}) or (dst host {self.target_ip})"
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
                    promisc=False,
                    stop_filter=lambda _: self.stop_event.is_set(),
                )
            except Exception as e:
                log.debug(f"Sniffer error for {self.target_ip} (interface may be reconnecting): {e}")
                if self.stop_event.wait(1.5):
                    break

    def _on_packet(self, pkt):
        """Queue captured packet for rate-limited forwarding after strictly discarding host's own packets."""
        try:
            from scapy.all import Ether, IP
            from scapy.layers.inet6 import IPv6

            if Ether not in pkt:
                return

            pkt_src_mac = pkt[Ether].src.lower()
            pkt_dst_mac = pkt[Ether].dst.lower()

            # Host's own outgoing packets must never be queued
            if pkt_src_mac == self.my_mac or pkt_src_mac in self.local_macs:
                return

            # Exclude packets where source or destination IP belongs to the host machine
            if IP in pkt:
                if pkt[IP].src in self.local_ips or pkt[IP].dst in self.local_ips:
                    return

            if IPv6 in pkt:
                src6 = pkt[IPv6].src.lower()
                dst6 = pkt[IPv6].dst.lower()
                if src6 in self.local_ipv6 or dst6 in self.local_ipv6:
                    return

            self._pkt_queue.put_nowait(pkt)
        except queue.Full:
            pass  # Drop when queue full (congestion control)
        except Exception:
            pass

    def _forwarder(self):
        """Dequeue packets, apply token-bucket limit, then forward with dual-stack IPv4/IPv6 support."""
        try:
            from scapy.all import Ether, IP, sendp
            from scapy.layers.inet6 import IPv6
            from .network import get_scapy_interface
            npf_iface = get_scapy_interface(self.interface)

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
                if pkt_src_mac == self.my_mac:
                    continue

                # Dynamically learn target's outbound IPv6 addresses
                if IPv6 in pkt and pkt_src_mac == self.target_mac:
                    self.observed_ipv6_addrs.add(pkt[IPv6].src.lower())

                # Classify stream direction strictly:
                is_upstream = (pkt_src_mac == self.target_mac) or (IP in pkt and pkt[IP].src == self.target_ip)
                is_downstream = (
                    (IP in pkt and pkt[IP].dst == self.target_ip)
                    or (IPv6 in pkt and (pkt[IPv6].dst.lower() in self.observed_ipv6_addrs or (self.target_ipv6_ll and pkt[IPv6].dst.lower() == self.target_ipv6_ll)))
                )

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
                    npf_iface = get_scapy_interface(interface)

        except Exception as e:
            log.debug(f"Forwarder error for {self.target_ip}: {e}")


def enable_ip_forwarding():
    """
    Preserve host network stack stability and avoid disruptive netsh resets.
    Packet interception and forwarding is performed entirely in userspace by
    TrafficShaper._forwarder via Scapy sendp(), preserving rate limiting.
    We deliberately avoid calling disruptive 'netsh int ... set global forwarding'
    which resets active TCP sockets on Windows and breaks DNS.
    """
    log.info("Host TCP/IP stack preserved in client mode (userspace Scapy forwarding active).")


def disable_ip_forwarding():
    """Clean up after session ends."""
    pass


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
