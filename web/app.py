import os
import json
import time
import logging
from flask import Flask, render_template, request, jsonify, Response

from core.engine import ThrottwinEngine
from core.config import (
    load_predefined_rules, save_predefined_rules,
    load_config, save_config, RULES_FILE
)

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


# ─── SSE Stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream")
def sse_stream():
    def event_generator():
        q = engine.subscribe_events()
        try:
            # Send initial state for all sessions
            all_states = engine.get_all_sessions_state()
            session_ids = list(all_states.keys())
            initial = json.dumps({
                "type": "init",
                "sessions": all_states,
                "session_ids": session_ids,
                "active_session_id": session_ids[0] if session_ids else None
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

    devs = session.scan()
    return jsonify({
        "success": True,
        "devices": devs,
        "count": len(devs),
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
    session = engine.get_session()
    return jsonify({
        "success": True,
        "settings": {
            "interface": cfg.get("interface") or (session.interface if session else None),
            "router_ip": cfg.get("router_ip") or (session.router_ip if session else None),
            "default_limit": cfg.get("limit_mbps", 1.0),
        }
    })


@app.route("/api/settings", methods=["POST"])
def save_settings_api():
    data = request.get_json(silent=True) or {}
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
    return jsonify({"success": True, "message": "Settings saved successfully."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
