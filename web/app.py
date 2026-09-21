import os
import json
import time
import logging
from flask import Flask, render_template, request, jsonify, Response, send_from_directory

from core.engine import ThrottwinEngine
from core.config import (
    load_predefined_rules, save_predefined_rules,
    load_config, save_config, RULES_FILE
)
from core.core_tools import get_core_status, download_arp_scan, is_arp_scan_installed
from core.logger import (
    get_debug_logs, get_packet_logs, clear_debug_logs, clear_packet_logs,
    clear_all_logs, set_log_level, get_log_level_name, set_packet_capture,
    is_packet_capture_enabled, set_logging_enabled, is_logging_enabled,
    set_cpu_saver_mode, get_log_status, install_log_handler
)

# Initialize logger handler early
install_log_handler()

log = logging.getLogger("throttwin.web")

WEB_DIR      = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(WEB_DIR, "templates")
STATIC_DIR   = os.path.join(WEB_DIR, "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config["SECRET_KEY"] = "throttwin-web-secret"

engine = ThrottwinEngine()


def _sid(data=None):
    """Extract session_id from request args, JSON body, or use default."""
    if data and isinstance(data, dict) and data.get("session_id"):
        return data["session_id"]
    sid = request.args.get("session_id")
    if sid:
        return sid
    return None  # Will use default session


# ─── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(STATIC_DIR, "favicon.svg", mimetype="image/svg+xml")


# ─── SSE Stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream")
def sse_stream():
    def event_generator():
        q = engine.subscribe_events()
        try:
            # Send initial state for all sessions + core tools + logs status
            all_states = engine.get_all_sessions_state()
            session_ids = list(all_states.keys())
            initial = json.dumps({
                "type": "init",
                "sessions": all_states,
                "session_ids": session_ids,
                "active_session_id": session_ids[0] if session_ids else None,
                "core": get_core_status(),
                "log_status": get_log_status(),
                "recent_debug_logs": get_debug_logs(limit=60),
                "recent_packet_logs": get_packet_logs(limit=60),
            })
            yield f"data: {initial}\n\n"
            while True:
                try:
                    msg = q.get(timeout=15.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except Exception:
                    yield ": keepalive\n\n"
        finally:
            engine.unsubscribe_events(q)

    return Response(event_generator(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })


# ─── Core Tools Management ───────────────────────────────────────────────────

@app.route("/api/core/status")
def get_core_tools_status():
    """Get status of native core binaries (arp-scan.exe)."""
    return jsonify({
        "success": True,
        "core": get_core_status()
    })


@app.route("/api/core/download", methods=["POST"])
def download_core_tool():
    """Download and install arp-scan.exe from GitHub repository."""
    data = request.get_json(silent=True) or {}
    arch = data.get("arch")  # Optional override 'x64' or 'x86'
    
    ok, msg = download_arp_scan(arch=arch)
    core_status = get_core_status()
    
    # Broadcast status change to all open web clients
    engine.broadcast_event("core_tools_updated", {
        "core": core_status,
        "message": msg,
        "installed": ok
    })

    if ok:
        return jsonify({
            "success": True,
            "message": msg,
            "core": core_status
        })
    return jsonify({
        "success": False,
        "error": msg,
        "core": core_status
    }), 500


@app.route("/api/core/verify", methods=["POST"])
def verify_core_tool():
    """Verify execution of installed core binaries."""
    installed = is_arp_scan_installed()
    return jsonify({
        "success": installed,
        "installed": installed,
        "core": get_core_status()
    })


# ─── Sessions Management ──────────────────────────────────────────────────────

@app.route("/api/sessions")
def get_sessions():
    """List all interface sessions with their states."""
    all_states = engine.get_all_sessions_state()
    return jsonify({
        "success": True,
        "sessions": all_states,
        "session_ids": list(all_states.keys())
    })


@app.route("/api/sessions/create", methods=["POST"])
def create_session():
    """Create a new session for an interface."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    router_ip = data.get("router_ip")
    if not interface:
        return jsonify({"success": False, "error": "Interface name required."}), 400
    session, msg = engine.create_session(interface, router_ip)
    return jsonify({
        "success": True,
        "message": msg,
        "session": session.get_state(),
        "sessions": engine.get_all_sessions_state(),
        "session_ids": list(engine.sessions.keys())
    })


@app.route("/api/sessions/<session_id>/delete", methods=["POST"])
def delete_session(session_id):
    """Delete an idle session."""
    ok, msg = engine.delete_session(session_id)
    if ok:
        return jsonify({
            "success": True,
            "message": msg,
            "sessions": engine.get_all_sessions_state(),
            "session_ids": list(engine.sessions.keys())
        })
    return jsonify({"success": False, "error": msg}), 400


# ─── Status & Interfaces ───────────────────────────────────────────────────────

@app.route("/api/status")
def get_status():
    sid = _sid()
    return jsonify({
        "success": True,
        "data": engine.get_state(sid),
        "sessions": engine.get_all_sessions_state(),
        "session_ids": list(engine.sessions.keys())
    })


@app.route("/api/interfaces")
def get_interfaces_list():
    iface_param = request.args.get("interface")
    if iface_param:
        gw = engine.get_default_gateway(iface_param)
        return jsonify({
            "success":           True,
            "interface":        iface_param,
            "default_gateway":   gw or "192.168.1.1",
        })

    active = engine.get_active_interfaces_full()
    iface_names = [i["name"] for i in active]
    default_iface = active[0]["name"] if active else None
    default_gw = active[0].get("gateway") if active else None

    return jsonify({
        "success":           True,
        "interfaces":        iface_names,
        "interfaces_full":   active,
        "default_interface": default_iface,
        "default_gateway":   default_gw or engine.get_default_gateway(),
    })


# ─── Scanning ──────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan_network():
    data   = request.get_json(silent=True) or {}
    sid    = _sid(data)
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No active session found."}), 404

    # Allow overriding interface/router for this scan
    if data.get("interface"):
        session.interface = data["interface"]
    if data.get("router_ip"):
        session.router_ip = data["router_ip"]

    aggressive = bool(data.get("aggressive", True))
    devs = session.scan(aggressive=aggressive)
    return jsonify({
        "success": True,
        "devices": devs,
        "count": len(devs),
        "aggressive": aggressive,
        "engine": "Dual-Engine (Native C + Win32 Multi-Vector)" if (aggressive and is_arp_scan_installed()) else "Win32 Multi-Vector",
        "session_id": session.session_id
    })


# ─── Devices ───────────────────────────────────────────────────────────────────

@app.route("/api/devices/manual", methods=["POST"])
def add_manual_device():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip")
    mac  = data.get("mac")
    sid  = _sid(data)
    if not ip and not mac:
        return jsonify({"success": False, "error": "IP or MAC required."}), 400
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No active session found."}), 404
    dev = session.add_manual_device(ip=ip, mac=mac, vendor=data.get("vendor", "Manual Entry"))
    return jsonify({"success": True, "device": dev})


@app.route("/api/devices/clear", methods=["POST"])
def clear_devices():
    data = request.get_json(silent=True) or {}
    sid = _sid(data)
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No active session found."}), 404
    ok, msg = session.clear_cache()
    if ok:
        return jsonify({"success": True, "message": msg})
    return jsonify({"success": False, "error": msg}), 400


# ─── Rules ─────────────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def get_rules():
    return jsonify({"success": True, "rules": load_predefined_rules()})


@app.route("/api/rules", methods=["POST"])
def add_rule():
    data     = request.get_json(silent=True) or {}
    category = data.get("category")
    mac      = (data.get("mac") or "").lower().strip()
    name     = (data.get("name") or "").strip()

    if category not in ("whitelist", "blacklist"):
        return jsonify({"success": False, "error": "Category must be 'whitelist' or 'blacklist'."}), 400
    if not mac:
        return jsonify({"success": False, "error": "MAC address required."}), 400

    rules = load_predefined_rules()
    rules[category][mac] = name
    save_predefined_rules(rules)
    return jsonify({"success": True, "rules": rules})


@app.route("/api/rules/<category>/<mac>", methods=["DELETE"])
def delete_rule(category, mac):
    mac = mac.lower().strip()
    if category not in ("whitelist", "blacklist"):
        return jsonify({"success": False, "error": "Invalid category."}), 400
    rules = load_predefined_rules()
    if mac in rules.get(category, {}):
        del rules[category][mac]
        save_predefined_rules(rules)
        return jsonify({"success": True, "rules": rules})
    return jsonify({"success": False, "error": "Rule not found."}), 404


# ─── Session ───────────────────────────────────────────────────────────────────

@app.route("/api/session/start", methods=["POST"])
def start_session():
    data        = request.get_json(silent=True) or {}
    sid         = _sid(data) or data.get("interface")
    session     = engine.get_session(sid)

    if not session:
        # Auto-create session for the requested interface
        iface = data.get("interface")
        router = data.get("router_ip")
        if iface:
            session, _ = engine.create_session(iface, router)
        else:
            return jsonify({"success": False, "error": "No session found. Specify an interface."}), 400

    mode        = data.get("mode", "blacklist")
    targets     = data.get("targets", [])
    whitelisted = data.get("whitelisted", [])
    limit_mbps  = float(data.get("limit_mbps", 1.0))

    if data.get("router_ip"):
        session.router_ip = data["router_ip"]

    if mode == "blacklist" and not targets:
        return jsonify({"success": False, "error": "Select at least one target in blacklist mode."}), 400

    ok, msg = session.start_session(mode, targets, limit_mbps, whitelisted)
    if ok:
        return jsonify({
            "success": True,
            "message": msg,
            "state": session.get_state(),
            "sessions": engine.get_all_sessions_state()
        })
    return jsonify({"success": False, "error": msg}), 500


@app.route("/api/session/stop", methods=["POST"])
def stop_session():
    data = request.get_json(silent=True) or {}
    sid = _sid(data)
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No session found."}), 404
    ok, msg = session.stop_session()
    return jsonify({
        "success": ok,
        "message": msg,
        "state": session.get_state(),
        "sessions": engine.get_all_sessions_state()
    })


@app.route("/api/session/limit", methods=["POST"])
def update_limit():
    data = request.get_json(silent=True) or {}
    sid = _sid(data)
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No session found."}), 404
    lim = data.get("limit_mbps")
    if lim is None:
        return jsonify({"success": False, "error": "limit_mbps required."}), 400
    try:
        lim = float(lim)
        if lim <= 0:
            return jsonify({"success": False, "error": "limit_mbps must be > 0."}), 400
    except ValueError:
        return jsonify({"success": False, "error": "Invalid limit_mbps."}), 400

    ok, msg = session.update_limit(lim)
    return jsonify({"success": ok, "message": msg, "limit_mbps": lim})


@app.route("/api/session/fuzzy", methods=["POST"])
def toggle_fuzzy():
    data = request.get_json(silent=True) or {}
    sid = _sid(data)
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No session found."}), 404
    enabled = data.get("enabled")
    if enabled is None:
        return jsonify({"success": False, "error": "enabled (true/false) required."}), 400
    ok, msg = session.toggle_fuzzy(bool(enabled))
    return jsonify({"success": ok, "message": msg, "fuzzy_enabled": session.fuzzy_enabled})


@app.route("/api/target/toggle", methods=["POST"])
def toggle_target():
    data            = request.get_json(silent=True) or {}
    ip              = data.get("ip")
    should_throttle = data.get("should_throttle")
    sid             = _sid(data)
    if not ip or should_throttle is None:
        return jsonify({"success": False, "error": "ip and should_throttle required."}), 400
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No session found."}), 404
    ok, msg = session.toggle_target(ip, bool(should_throttle))
    if ok:
        return jsonify({"success": True, "message": msg, "state": session.get_state()})
    return jsonify({"success": False, "error": msg}), 400


@app.route("/api/target/fuzzy", methods=["POST"])
def toggle_target_fuzzy():
    data    = request.get_json(silent=True) or {}
    ip      = data.get("ip")
    enabled = data.get("enabled")
    sid     = _sid(data)
    if not ip:
        return jsonify({"success": False, "error": "ip required."}), 400
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": False, "error": "No session found."}), 404
    ok, msg = session.toggle_target_fuzzy(ip, enabled)
    if ok:
        shaper = session.shapers.get(ip)
        f_state = shaper.fuzzy_enabled if shaper else False
        return jsonify({"success": True, "message": msg, "ip": ip, "fuzzy_enabled": f_state, "state": session.get_state()})
    return jsonify({"success": False, "error": msg}), 400


@app.route("/api/telemetry")
def get_telemetry():
    sid = _sid()
    session = engine.get_session(sid)
    if not session:
        return jsonify({"success": True, "status": "IDLE", "telemetry": []})
    state = session.get_state()
    return jsonify({
        "success":          True,
        "session_id":       session.session_id,
        "status":           state["status"],
        "uptime":           state["uptime"],
        "total_speed_kbps": state["total_speed_kbps"],
        "total_speed_mbps": state["total_speed_mbps"],
        "total_data_mb":    state["total_data_mb"],
        "target_count":     state["target_count"],
        "telemetry":        state["telemetry"],
    })


# ─── Settings ──────────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
def get_settings():
    cfg = load_config() or {}
    all_sessions = engine.get_all_sessions_state()
    active_ifaces = engine.get_active_interfaces_full()
    
    # Merge saved session configs with active runtime state
    saved_sessions = cfg.get("sessions", {})
    interfaces_config = []
    
    for iface in active_ifaces:
        name = iface["name"]
        saved = saved_sessions.get(name, {})
        sess_state = all_sessions.get(name, {})
        
        gw = sess_state.get("router_ip") or saved.get("router_ip") or iface.get("gateway") or "192.168.1.1"
        lim = sess_state.get("limit_mbps") or saved.get("limit_mbps") or cfg.get("limit_mbps", 1.0)
        
        interfaces_config.append({
            "name": name,
            "ip": iface["ip"],
            "mac": iface["mac"],
            "metric": iface.get("metric", 9999),
            "gateway": gw,
            "default_limit": lim,
            "link_status": sess_state.get("link_status", "ONLINE"),
            "session_status": sess_state.get("status", "IDLE"),
            "device_count": len(sess_state.get("devices", [])),
        })

    return jsonify({
        "success": True,
        "interfaces": interfaces_config,
        "global": {
            "discovery_interval": cfg.get("discovery_interval", 8),
            "hotplug_detection": True,
            "default_mode": cfg.get("operational_mode", "blacklist"),
            "default_limit": cfg.get("limit_mbps", 1.0),
            "ip_forwarding_enabled": True
        }
    })


@app.route("/api/settings", methods=["POST"])
def save_settings_api():
    data = request.get_json(silent=True) or {}
    
    # 1. Multi-interface configurations payload
    sessions_data = data.get("sessions") or {}
    for iface_name, iface_cfg in sessions_data.items():
        router = iface_cfg.get("router_ip")
        lim = iface_cfg.get("limit_mbps") or iface_cfg.get("default_limit")
        
        session = engine.get_session(iface_name)
        if session:
            if router:
                session.router_ip = router
            if lim:
                try:
                    session.limit_mbps = float(lim)
                except ValueError:
                    pass
        
        # Save to config.json
        save_config(
            interface=iface_name,
            router_ip=router or (session.router_ip if session else ""),
            mode=session.operational_mode if session else "blacklist",
            targets=session.targets if session else [],
            limit_mbps=float(lim or 1.0),
            whitelisted=session.whitelisted if session else []
        )

    # 2. Legacy single-session payload fallback
    if not sessions_data:
        iface = data.get("interface")
        router = data.get("router_ip")
        limit = float(data.get("default_limit") or data.get("limit_mbps") or 1.0)
        sid = _sid(data) or iface

        session = engine.get_session(sid)
        if session:
            if iface:
                session.interface = iface
            if router:
                session.router_ip = router
            if limit:
                session.limit_mbps = limit

        save_config(
            interface=iface or (session.interface if session else ""),
            router_ip=router or (session.router_ip if session else ""),
            mode=session.operational_mode if session else "blacklist",
            targets=session.targets if session else [],
            limit_mbps=limit,
            whitelisted=session.whitelisted if session else []
        )

    return jsonify({"success": True, "message": "All network settings saved successfully."})


# ─── Logs & Packet Telemetry API ──────────────────────────────────────────────

@app.route("/api/logs")
def get_logs_endpoint():
    """Fetch recent debug or packet logs with filtering."""
    log_type = request.args.get("type", "debug").lower()
    limit = int(request.args.get("limit", 100))
    since_id = int(request.args.get("since_id", 0))
    
    if log_type == "packet":
        action = request.args.get("action")
        proto = request.args.get("proto")
        filter_term = request.args.get("filter") or request.args.get("search")
        packets = get_packet_logs(limit=limit, filter_term=filter_term, action=action, proto=proto, since_id=since_id)
        return jsonify({
            "success": True,
            "type": "packet",
            "packets": packets,
            "status": get_log_status()
        })
    elif log_type == "all":
        debugs = get_debug_logs(limit=limit, since_id=since_id)
        packets = get_packet_logs(limit=limit, since_id=since_id)
        return jsonify({
            "success": True,
            "type": "all",
            "logs": debugs,
            "packets": packets,
            "status": get_log_status()
        })
    else:
        level = request.args.get("level", "ALL")
        search = request.args.get("search")
        logs = get_debug_logs(limit=limit, level=level, search=search, since_id=since_id)
        return jsonify({
            "success": True,
            "type": "debug",
            "logs": logs,
            "status": get_log_status()
        })


@app.route("/api/logs/clear", methods=["POST"])
def clear_logs_endpoint():
    """Clear in-memory debug logs, packet logs, or both."""
    data = request.get_json(silent=True) or {}
    log_type = data.get("type", "all").lower()
    
    if log_type == "debug":
        clear_debug_logs()
        msg = "Debug logs cleared."
    elif log_type == "packet":
        clear_packet_logs()
        msg = "Packet activity stream cleared."
    else:
        clear_all_logs()
        msg = "All logs and packet streams cleared."
        
    return jsonify({
        "success": True,
        "message": msg,
        "status": get_log_status()
    })


@app.route("/api/logs/level", methods=["POST"])
def set_log_level_endpoint():
    """Dynamically set runtime logging level."""
    data = request.get_json(silent=True) or {}
    level = data.get("level", "INFO")
    active_level = set_log_level(level)
    return jsonify({
        "success": True,
        "level": active_level,
        "status": get_log_status()
    })


@app.route("/api/logs/system_logging", methods=["POST"])
def set_system_logging_endpoint():
    """Enable or disable Python system logging capture (CPU saver)."""
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", True)
    active = set_logging_enabled(enabled)
    return jsonify({
        "success": True,
        "logging_enabled": active,
        "status": get_log_status()
    })


@app.route("/api/logs/packet_capture", methods=["POST"])
def set_packet_capture_endpoint():
    """Toggle real-time packet telemetry capture on/off."""
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", True)
    active = set_packet_capture(enabled)
    return jsonify({
        "success": True,
        "packet_capture_enabled": active,
        "status": get_log_status()
    })


@app.route("/api/logs/cpu_saver", methods=["POST"])
def set_cpu_saver_endpoint():
    """Toggle CPU Saver Mode (disables/enables both system and packet logging)."""
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", True)
    active = set_cpu_saver_mode(enabled)
    return jsonify({
        "success": True,
        "cpu_saver_mode": active,
        "status": get_log_status()
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
