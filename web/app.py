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
            # Send initial state
            initial = json.dumps({"type": "init", "state": engine.get_state()})
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


# ─── Status & Interfaces ───────────────────────────────────────────────────────

@app.route("/api/status")
def get_status():
    return jsonify({"success": True, "data": engine.get_state()})


@app.route("/api/interfaces")
def get_interfaces_list():
    return jsonify({
        "success":           True,
        "interfaces":        engine.get_interfaces(),
        "default_interface": engine.current_interface,
        "default_gateway":   engine.get_default_gateway(),
    })


# ─── Scanning ──────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan_network():
    data   = request.get_json(silent=True) or {}
    iface  = data.get("interface") or engine.current_interface
    router = data.get("router_ip") or engine.current_router_ip
    devs   = engine.scan(interface=iface, router_ip=router)
    return jsonify({"success": True, "devices": devs, "count": len(devs)})


# ─── Devices ───────────────────────────────────────────────────────────────────

@app.route("/api/devices/manual", methods=["POST"])
def add_manual_device():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip")
    mac  = data.get("mac")
    if not ip and not mac:
        return jsonify({"success": False, "error": "IP or MAC required."}), 400
    dev = engine.add_manual_device(ip=ip, mac=mac, vendor=data.get("vendor", "Manual Entry"))
    return jsonify({"success": True, "device": dev})


@app.route("/api/devices/clear", methods=["POST"])
def clear_devices():
    ok, msg = engine.clear_cache()
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
    data       = request.get_json(silent=True) or {}
    iface      = data.get("interface")  or engine.current_interface
    router     = data.get("router_ip")  or engine.current_router_ip
    mode       = data.get("mode", "blacklist")
    targets    = data.get("targets", [])
    whitelisted = data.get("whitelisted", [])
    limit_mbps = float(data.get("limit_mbps", 1.0))

    if not iface or not router:
        return jsonify({"success": False, "error": "Interface and router IP required."}), 400
    if mode == "blacklist" and not targets:
        return jsonify({"success": False, "error": "Select at least one target in blacklist mode."}), 400

    ok, msg = engine.start_session(iface, router, mode, targets, limit_mbps, whitelisted)
    if ok:
        return jsonify({"success": True, "message": msg, "state": engine.get_state()})
    return jsonify({"success": False, "error": msg}), 500


@app.route("/api/session/stop", methods=["POST"])
def stop_session():
    ok, msg = engine.stop_session()
    return jsonify({"success": ok, "message": msg, "state": engine.get_state()})


@app.route("/api/session/limit", methods=["POST"])
def update_limit():
    data = request.get_json(silent=True) or {}
    lim  = data.get("limit_mbps")
    if lim is None:
        return jsonify({"success": False, "error": "limit_mbps required."}), 400
    try:
        lim = float(lim)
        if lim <= 0:
            return jsonify({"success": False, "error": "limit_mbps must be > 0."}), 400
    except ValueError:
        return jsonify({"success": False, "error": "Invalid limit_mbps."}), 400

    ok, msg = engine.update_limit(lim)
    return jsonify({"success": ok, "message": msg, "limit_mbps": lim})


@app.route("/api/target/toggle", methods=["POST"])
def toggle_target():
    data           = request.get_json(silent=True) or {}
    ip             = data.get("ip")
    should_throttle = data.get("should_throttle")
    if not ip or should_throttle is None:
        return jsonify({"success": False, "error": "ip and should_throttle required."}), 400
    ok, msg = engine.toggle_target(ip, bool(should_throttle))
    if ok:
        return jsonify({"success": True, "message": msg, "state": engine.get_state()})
    return jsonify({"success": False, "error": msg}), 400


@app.route("/api/telemetry")
def get_telemetry():
    state = engine.get_state()
    return jsonify({
        "success":          True,
        "status":           state["status"],
        "uptime":           state["uptime"],
        "total_speed_kbps": state["total_speed_kbps"],
        "total_speed_mbps": state["total_speed_mbps"],
        "total_data_mb":    state["total_data_mb"],
        "target_count":     state["target_count"],
        "telemetry":        state["telemetry"],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
