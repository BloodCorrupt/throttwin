"""
core.logger — Centralized Logging & Packet Activity Telemetry for Throttwin.

Provides:
  1. Thread-safe in-memory circular ring buffers for:
     - System / Debug logs (Python standard logging records)
     - Real-time Packet logs (ARP spoofing, NDP, Token Bucket FWD/DROP, UDP Probes)
  2. Custom logging.Handler to capture Python logs and stream them to Web UI via SSE.
  3. High-performance log_packet() dispatcher for low-latency network telemetry.
  4. Querying, filtering, clearing, and log-level adjustment APIs.
"""

import time
import logging
import threading
from collections import deque
from datetime import datetime

MAX_DEBUG_LOGS = 2000
MAX_PACKET_LOGS = 3000

_lock = threading.RLock()
_debug_logs = deque(maxlen=MAX_DEBUG_LOGS)
_packet_logs = deque(maxlen=MAX_PACKET_LOGS)

_next_debug_id = 1
_next_packet_id = 1
_logging_enabled = True
_packet_capture_enabled = True

_broadcast_callback = None
_handler_installed = False
_flusher_started = False

_pending_debug_batch = []
_pending_packet_batch = []
_batch_lock = threading.Lock()


def register_broadcast_callback(callback):
    """Register a callback function(event_type, data) to broadcast to SSE."""
    global _broadcast_callback
    with _lock:
        _broadcast_callback = callback
    _ensure_flusher_running()


def _dispatch_broadcast(event_type, data):
    """Safely invoke the broadcast callback if registered."""
    cb = _broadcast_callback
    if cb:
        try:
            cb(event_type, data)
        except Exception:
            pass


def _ensure_flusher_running():
    """Ensure the background SSE batch flusher thread is running."""
    global _flusher_started
    with _lock:
        if _flusher_started:
            return
        _flusher_started = True
        t = threading.Thread(target=_batch_flusher_loop, daemon=True)
        t.start()


def _batch_flusher_loop():
    """Flushes pending buffered packet and log events every 500ms to avoid SSE flood."""
    while True:
        try:
            time.sleep(0.5)
            with _batch_lock:
                debug_batch = list(_pending_debug_batch)
                _pending_debug_batch.clear()

                packet_batch = list(_pending_packet_batch)
                _pending_packet_batch.clear()

            if debug_batch:
                if len(debug_batch) == 1:
                    _dispatch_broadcast("log_event", debug_batch[0])
                else:
                    _dispatch_broadcast("log_batch", {"events": debug_batch})

            if packet_batch:
                if len(packet_batch) == 1:
                    _dispatch_broadcast("packet_event", packet_batch[0])
                else:
                    _dispatch_broadcast("packet_batch", {"events": packet_batch})
        except Exception:
            pass


# ─── Custom Log Handler ────────────────────────────────────────────────────────

class ThrottwinLogHandler(logging.Handler):
    """
    Captures Python logging records, stores them in the circular debug buffer,
    and dispatches live 'log_event' to connected Web UI clients.
    Exits immediately with zero CPU overhead if logging is disabled.
    """

    def emit(self, record):
        global _next_debug_id, _logging_enabled
        if not _logging_enabled:
            return

        try:
            # Ignore Werkzeug noise if it slipped through
            if record.name == "werkzeug" and record.levelno < logging.ERROR:
                return

            msg = self.format(record)
            now = time.time()
            time_str = datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]

            with _lock:
                log_id = _next_debug_id
                _next_debug_id += 1
                entry = {
                    "id": log_id,
                    "timestamp": now,
                    "time_str": time_str,
                    "level": record.levelname,
                    "name": record.name,
                    "module": record.module,
                    "funcName": record.funcName,
                    "lineno": record.lineno,
                    "message": record.getMessage(),
                    "formatted": msg,
                }
                _debug_logs.append(entry)

            # High priority logs (WARNING/ERROR/CRITICAL) dispatch immediately; INFO/DEBUG batch smoothly
            if record.levelno >= logging.WARNING:
                _dispatch_broadcast("log_event", entry)
            else:
                with _batch_lock:
                    if len(_pending_debug_batch) < 100:
                        _pending_debug_batch.append(entry)
        except Exception:
            self.handleError(record)


def install_log_handler():
    """Attach the ThrottwinLogHandler to the root logger once."""
    global _handler_installed
    with _lock:
        if _handler_installed:
            return
        handler = ThrottwinLogHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s", datefmt="%H:%M:%S"))
        
        root_logger = logging.getLogger()
        if not any(isinstance(h, ThrottwinLogHandler) for h in root_logger.handlers):
            root_logger.addHandler(handler)

        if root_logger.level == logging.NOTSET or root_logger.level > logging.INFO:
            root_logger.setLevel(logging.INFO)
            
        _handler_installed = True
    _ensure_flusher_running()


# ─── Packet Activity Telemetry ────────────────────────────────────────────────

def log_packet(action, proto, src, dst, length=0, details="", session_id=None):
    """
    Record a packet action (SPOOF, FWD_UP, FWD_DOWN, DROP, PROBE, RESTORE, DISCOVER)
    into the circular packet buffer and stream it via SSE.
    """
    global _next_packet_id, _packet_capture_enabled
    if not _packet_capture_enabled:
        return

    try:
        now = time.time()
        time_str = datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]
        action_str = str(action).upper()

        with _lock:
            pkt_id = _next_packet_id
            _next_packet_id += 1
            entry = {
                "id": pkt_id,
                "timestamp": now,
                "time_str": time_str,
                "action": action_str,
                "proto": str(proto).upper(),
                "src": str(src or "-"),
                "dst": str(dst or "-"),
                "length": int(length or 0),
                "details": str(details or ""),
                "session_id": session_id,
            }
            _packet_logs.append(entry)

        # High-priority / rare control events dispatch immediately; routine FWD/DROP batch smoothly
        if action_str in ("SPOOF", "DISCOVER", "PROBE", "RESTORE"):
            _dispatch_broadcast("packet_event", entry)
        else:
            with _batch_lock:
                if len(_pending_packet_batch) < 100:
                    _pending_packet_batch.append(entry)
    except Exception:
        pass


# ─── Query & Control Functions ────────────────────────────────────────────────

def get_debug_logs(limit=200, level=None, search=None, since_id=0):
    """Fetch recent debug logs with optional level, search, and since_id filters."""
    with _lock:
        logs = list(_debug_logs)

    if since_id > 0:
        logs = [x for x in logs if x["id"] > since_id]

    if level and level.upper() != "ALL":
        target_level = level.upper()
        logs = [x for x in logs if x["level"] == target_level]

    if search:
        s = search.lower()
        logs = [
            x for x in logs
            if s in x["message"].lower() or s in x["name"].lower() or s in x["module"].lower()
        ]

    if limit and limit > 0:
        logs = logs[-limit:]

    return logs


def get_packet_logs(limit=200, filter_term=None, action=None, proto=None, since_id=0):
    """Fetch recent packet logs with optional filters."""
    with _lock:
        pkts = list(_packet_logs)

    if since_id > 0:
        pkts = [x for x in pkts if x["id"] > since_id]

    if action and action.upper() != "ALL":
        act = action.upper()
        pkts = [x for x in pkts if x["action"] == act or act in x["action"]]

    if proto and proto.upper() != "ALL":
        pr = proto.upper()
        pkts = [x for x in pkts if x["proto"] == pr]

    if filter_term:
        ft = filter_term.lower()
        pkts = [
            x for x in pkts
            if ft in x["src"].lower() or ft in x["dst"].lower() or ft in x["details"].lower() or ft in x["action"].lower()
        ]

    if limit and limit > 0:
        pkts = pkts[-limit:]

    return pkts


def clear_debug_logs():
    """Clear in-memory debug log buffer."""
    with _lock:
        _debug_logs.clear()
    _dispatch_broadcast("logs_cleared", {"type": "debug"})


def clear_packet_logs():
    """Clear in-memory packet log buffer."""
    with _lock:
        _packet_logs.clear()
    _dispatch_broadcast("logs_cleared", {"type": "packet"})


def clear_all_logs():
    """Clear all debug and packet log buffers."""
    with _lock:
        _debug_logs.clear()
        _packet_logs.clear()
    _dispatch_broadcast("logs_cleared", {"type": "all"})


def set_logging_enabled(enabled):
    """Enable or disable Python system logging capture (CPU saver)."""
    global _logging_enabled
    with _lock:
        _logging_enabled = bool(enabled)
    _dispatch_broadcast("system_logging_toggled", {"enabled": _logging_enabled})
    return _logging_enabled


def is_logging_enabled():
    """Return whether Python system logging capture is active."""
    return _logging_enabled


def set_packet_capture(enabled):
    """Enable or disable packet telemetry capture."""
    global _packet_capture_enabled
    with _lock:
        _packet_capture_enabled = bool(enabled)
    _dispatch_broadcast("packet_capture_toggled", {"enabled": _packet_capture_enabled})
    return _packet_capture_enabled


def is_packet_capture_enabled():
    """Return whether packet telemetry capture is active."""
    return _packet_capture_enabled


def set_cpu_saver_mode(enabled):
    """
    Toggle CPU Saver Mode:
    When True: Disables both system logging and packet capture to run at zero CPU overhead.
    When False: Re-enables system logging and packet capture.
    """
    global _logging_enabled, _packet_capture_enabled
    with _lock:
        if enabled:
            _logging_enabled = False
            _packet_capture_enabled = False
        else:
            _logging_enabled = True
            _packet_capture_enabled = True

    _dispatch_broadcast("cpu_saver_toggled", {
        "cpu_saver_mode": bool(enabled),
        "logging_enabled": _logging_enabled,
        "packet_capture_enabled": _packet_capture_enabled,
    })
    return bool(enabled)


def set_log_level(level_str):
    """Dynamically change root and throttwin logging level (DEBUG, INFO, WARNING, ERROR)."""
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    lvl = level_map.get(str(level_str).upper(), logging.INFO)
    logging.getLogger("throttwin").setLevel(lvl)
    logging.getLogger().setLevel(lvl)
    
    current = get_log_level_name()
    _dispatch_broadcast("log_level_changed", {"level": current})
    return current


def get_log_level_name():
    """Get current throttwin logger level name."""
    lvl = logging.getLogger("throttwin").getEffectiveLevel()
    return logging.getLevelName(lvl)


def get_log_status():
    """Return summary statistics of log buffers, CPU saver state, and capture settings."""
    with _lock:
        debug_count = len(_debug_logs)
        packet_count = len(_packet_logs)
        latest_debug_id = _next_debug_id - 1
        latest_packet_id = _next_packet_id - 1

    return {
        "debug_count": debug_count,
        "debug_max": MAX_DEBUG_LOGS,
        "packet_count": packet_count,
        "packet_max": MAX_PACKET_LOGS,
        "latest_debug_id": latest_debug_id,
        "latest_packet_id": latest_packet_id,
        "logging_enabled": _logging_enabled,
        "packet_capture_enabled": _packet_capture_enabled,
        "cpu_saver_mode": (not _logging_enabled) and (not _packet_capture_enabled),
        "log_level": get_log_level_name(),
    }
