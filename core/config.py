import json
import os
import logging
import sys
import re
import ipaddress
import questionary

from .console import custom_style, console, Panel, Group, Table, box, qselect
from .scanner import prompt_manual_device, device_sort_key

log = logging.getLogger("throttwin")

# Store configuration files in the 'config' directory within the project root
CONFIG_DIR  = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
RULES_FILE  = os.path.join(CONFIG_DIR, "rules.json")


def _ensure_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)


# ─── Session Config ────────────────────────────────────────────────────────────

def save_config(interface, router_ip, mode, targets, limit_mbps, whitelisted=None):
    _ensure_dir()
    existing = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                existing = json.load(f) or {}
        except Exception:
            existing = {}

    sessions = existing.get("sessions", {})
    if "interface" in existing and "sessions" not in existing:
        old_iface = existing.get("interface")
        if old_iface:
            sessions[old_iface] = dict(existing)

    sess_config = {
        "interface":        interface,
        "router_ip":        router_ip,
        "operational_mode": mode,
        "targets":          targets,
        "limit_mbps":       limit_mbps,
    }
    if whitelisted is not None:
        sess_config["whitelisted"] = whitelisted

    if interface:
        sessions[interface] = sess_config

    full_config = {
        "interface":        interface,
        "router_ip":        router_ip,
        "operational_mode": mode,
        "targets":          targets,
        "limit_mbps":       limit_mbps,
        "whitelisted":      whitelisted or [],
        "sessions":         sessions
    }

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(full_config, f, indent=4)
    except Exception as e:
        log.warning(f"Failed to save config: {e}")


def load_config(interface=None):
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        if not data:
            return None

        sessions = data.get("sessions")
        if sessions and isinstance(sessions, dict):
            if interface and interface in sessions:
                return sessions[interface]
            elif interface:
                return None
            return data

        if interface and data.get("interface") != interface:
            return None

        return data
    except Exception as e:
        log.warning(f"Failed to load config: {e}")
        return None


def clear_saved_config(interface=None):
    if not os.path.exists(CONFIG_FILE):
        return True
    try:
        if not interface:
            os.remove(CONFIG_FILE)
            return True
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f) or {}
        sessions = data.get("sessions", {})
        if interface in sessions:
            del sessions[interface]
            data["sessions"] = sessions
            with open(CONFIG_FILE, "w") as f:
                json.dump(data, f, indent=4)
        return True
    except Exception as e:
        log.warning(f"Failed to clear config: {e}")
        return False


def match_saved_config(config, devices):
    if not config:
        return None
    saved_targets = config.get("targets", [])
    if not saved_targets and "target_ip" in config:
        saved_targets = [{"ip": config.get("target_ip"), "mac": config.get("target_mac", "")}]

    matched = []
    for saved in saved_targets:
        saved_mac = (saved.get("mac", "") if isinstance(saved, dict) else "").lower()
        saved_ip  = saved.get("ip") if isinstance(saved, dict) else saved
        for d in devices:
            if saved_mac and d.get("mac", "").lower() == saved_mac:
                matched.append(d)
                break
            elif not saved_mac and d.get("ip") == saved_ip:
                matched.append(d)
                break
    return matched if matched else None


def match_saved_whitelist(config, devices):
    if not config or not config.get("whitelisted"):
        return None
    saved = config.get("whitelisted", [])
    matched = []
    for s in saved:
        s_mac = (s.get("mac", "") if isinstance(s, dict) else "").lower()
        s_ip  = s.get("ip") if isinstance(s, dict) else s
        for d in devices:
            if s_mac and d.get("mac", "").lower() == s_mac:
                matched.append(d)
                break
            elif not s_mac and d.get("ip") == s_ip:
                matched.append(d)
                break
    return matched if matched else None


# ─── Rules ─────────────────────────────────────────────────────────────────────

def load_predefined_rules():
    rules = {"whitelist": {}, "blacklist": {}}
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r") as f:
                data = json.load(f)
            for cat in ("whitelist", "blacklist"):
                for item in data.get(cat, []):
                    if isinstance(item, dict):
                        mac  = item.get("mac", "").lower().strip()
                        name = item.get("name", "").strip()
                        if mac:
                            rules[cat][mac] = name
                    elif isinstance(item, str):
                        mac = item.lower().strip()
                        if mac:
                            rules[cat][mac] = ""
        except Exception as e:
            log.warning(f"Failed to load rules: {e}")

    # Automatically ensure all local host adapter MACs are included in the whitelist
    try:
        from .network import get_all_local_ips_and_macs
        _, all_macs = get_all_local_ips_and_macs()
        for mac in all_macs:
            mac_clean = mac.lower().replace("-", ":")
            if mac_clean and mac_clean not in rules["whitelist"]:
                rules["whitelist"][mac_clean] = "Host Machine (This PC)"
    except Exception:
        pass

    return rules


def save_predefined_rules(rules):
    _ensure_dir()
    data = {
        "whitelist": [{"mac": mac, "name": name} if name else mac
                      for mac, name in rules.get("whitelist", {}).items()],
        "blacklist": [{"mac": mac, "name": name} if name else mac
                      for mac, name in rules.get("blacklist", {}).items()],
    }
    try:
        with open(RULES_FILE, "w") as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        log.warning(f"Failed to save rules: {e}")
        return False


def get_predefined_whitelist():
    return load_predefined_rules().get("whitelist", {})


def get_predefined_blacklist():
    return load_predefined_rules().get("blacklist", {})


# ─── Interactive CLI helpers ────────────────────────────────────────────────────

def prompt_operational_mode():
    choice = qselect(
        "Select operational mode:",
        choices=[
            questionary.Choice("Blacklist — throttle specific devices",          value="blacklist"),
            questionary.Choice("Whitelist — throttle everyone except safe list", value="whitelist"),
        ]
    )
    if choice is None:
        sys.exit(0)
    return choice


def prompt_blacklist_selection(devices, matched_dev=None, interface=None):
    max_ip = max((len(d.get("ip") or "-") for d in devices), default=15)
    choices = []
    choices.append(questionary.Choice("+ [Add device manually]", value="__manual__"))

    for dev in devices:
        mac    = dev.get("mac", "").lower()
        ip_str = dev.get("ip") or "-"
        vendor = dev.get("vendor", "Unknown")
        host   = dev.get("hostname", "")
        label  = f"{host} ({vendor})" if host else vendor
        if len(label) > 28:
            label = label[:28] + "…"
        pre_checked = bool(matched_dev and any(
            (d.get("mac", "").lower() == mac) or (d.get("ip") == ip_str)
            for d in matched_dev
        ))
        display = f"{ip_str:<{max_ip}}  {mac:<17}  {label}"
        choices.append(questionary.Choice(title=display, value=dev, checked=pre_checked))

    selected = questionary.checkbox(
        "Select devices to THROTTLE:",
        qmark="",
        instruction="(Space=toggle, Enter=confirm)",
        choices=choices,
        style=custom_style
    ).ask(kbi_msg="")

    if not selected:
        console.print(" [error]No devices selected. Exiting.[/error]")
        sys.exit(0)

    targets = []
    if "__manual__" in selected:
        dev = prompt_manual_device(interface)
        if dev:
            targets.append(dev)
    for dev in selected:
        if dev != "__manual__":
            targets.append(dev)

    if not targets:
        console.print(" [error]No targets selected.[/error]")
        sys.exit(0)
    return targets


def prompt_whitelist_selection(devices, matched_wl=None, interface=None):
    max_ip = max((len(d.get("ip") or "-") for d in devices), default=15)
    choices = []
    choices.append(questionary.Choice("+ [Add device manually]", value="__manual__"))

    for dev in devices:
        mac    = dev.get("mac", "").lower()
        ip_str = dev.get("ip") or "-"
        vendor = dev.get("vendor", "Unknown")
        host   = dev.get("hostname", "")
        label  = f"{host} ({vendor})" if host else vendor
        if len(label) > 28:
            label = label[:28] + "…"
        pre_checked = bool(matched_wl and any(
            (d.get("mac", "").lower() == mac) or (d.get("ip") == ip_str)
            for d in matched_wl
        ))
        display = f"{ip_str:<{max_ip}}  {mac:<17}  {label}"
        choices.append(questionary.Choice(title=display, value=dev, checked=pre_checked))

    selected = questionary.checkbox(
        "Select SAFE devices (whitelist — these will NOT be throttled):",
        qmark="",
        instruction="(Space=toggle, Enter=confirm)",
        choices=choices,
        style=custom_style
    ).ask(kbi_msg="")

    safe = []
    if selected:
        if "__manual__" in selected:
            dev = prompt_manual_device(interface)
            if dev:
                safe.append(dev)
        for dev in selected:
            if dev != "__manual__":
                safe.append(dev)
    return safe


def prompt_session_review(interface, router_ip, mode, limit_mbps, targets):
    console.print()
    console.print(Panel(
        f"  [label]Interface  :[/label] [white]{interface}[/white]\n"
        f"  [label]Router     :[/label] [white]{router_ip}[/white]\n"
        f"  [label]Mode       :[/label] [white]{mode.capitalize()}[/white]\n"
        f"  [label]Limit      :[/label] [white]{limit_mbps} Mbps[/white]\n"
        f"  [label]Targets    :[/label] [white]{len(targets)} device(s)[/white]",
        title="[bold white]Session Review[/bold white]",
        border_style="dim"
    ))
    console.print()
    try:
        yn = input("  Proceed? (y/n): ").strip().lower()
        if yn != "y":
            console.print(" [error]Cancelled by user.[/error]")
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)


def ask_user_action(has_saved=False):
    choices = []
    if has_saved:
        choices.append(questionary.Choice("▶  Resume saved session",       value="use_saved"))
    choices += [
        questionary.Choice("⊕  Start new session",                         value="new_scan"),
        questionary.Choice("⟳  Rescan network",                            value="rescan"),
        questionary.Choice("+  Add device manually",                       value="add_device"),
        questionary.Choice("⚙  Manage global rules (whitelist/blacklist)", value="manage_rules"),
        questionary.Choice("✕  Clear saved session cache",                 value="clear_cache"),
    ]
    return qselect("What would you like to do?", choices=choices)


def prompt_manage_rules(devices=None, interface=None):
    devices = devices or []
    while True:
        rules = load_predefined_rules()
        wl    = rules.get("whitelist", {})
        bl    = rules.get("blacklist", {})

        action = qselect(
            "Global Rules Management:",
            choices=[
                questionary.Choice(f"View rules ({len(wl)} WL, {len(bl)} BL)", value="view"),
                questionary.Choice("Add to Whitelist",                          value="add_wl"),
                questionary.Choice("Add to Blacklist",                          value="add_bl"),
                questionary.Choice("Remove a rule",                             value="remove"),
                questionary.Choice("← Back",                                   value="back"),
            ]
        )
        if action is None or action == "back":
            break

        if action == "view":
            table = Table(box=box.SIMPLE, title="[bold white]Global Rules[/bold white]")
            table.add_column("Type")
            table.add_column("MAC")
            table.add_column("Label")
            if not wl and not bl:
                table.add_row("[dim]Empty[/dim]", "[dim]No rules configured[/dim]", "")
            for mac, name in wl.items():
                table.add_row("[green]WHITELIST[/green]", mac, name or "[dim]-[/dim]")
            for mac, name in bl.items():
                table.add_row("[red]BLACKLIST[/red]", mac, name or "[dim]-[/dim]")
            console.print(table)
            console.print(f" [dim]Rules file: {RULES_FILE}[/dim]\n")
            input("  Press Enter to continue...")

        elif action in ("add_wl", "add_bl"):
            cat = "whitelist" if action == "add_wl" else "blacklist"
            max_ip = max((len(d.get("ip") or "-") for d in devices), default=15)
            choices_dev = [questionary.Choice("+ [Add manually]", value="__manual__")]
            for dev in devices:
                mac    = dev.get("mac", "").lower()
                ip_str = dev.get("ip") or "-"
                vendor = dev.get("vendor", "")
                checked = mac in rules[cat]
                display = f"{ip_str:<{max_ip}}  {mac:<17}  {vendor}"
                choices_dev.append(questionary.Choice(display, value=dev, checked=checked))

            selected = questionary.checkbox(
                f"Add to global {cat}:",
                qmark="", instruction="(Space=toggle, Enter=confirm)",
                choices=choices_dev, style=custom_style
            ).ask(kbi_msg="")

            if selected:
                if "__manual__" in selected:
                    dev = prompt_manual_device(interface)
                    if dev:
                        mac = dev.get("mac", "").lower()
                        if mac and mac != "unknown":
                            rules[cat][mac] = dev.get("vendor", "")
                for dev in selected:
                    if dev == "__manual__":
                        continue
                    mac = dev.get("mac", "").lower()
                    if mac:
                        rules[cat][mac] = rules[cat].get(mac) or dev.get("vendor", "")
                save_predefined_rules(rules)
                console.print(f" [success]Updated global {cat}.[/success]\n")

        elif action == "remove":
            rem_choices = []
            for mac, name in wl.items():
                label = f"[WL] {mac} ({name})" if name else f"[WL] {mac}"
                rem_choices.append(questionary.Choice(label, value=("whitelist", mac)))
            for mac, name in bl.items():
                label = f"[BL] {mac} ({name})" if name else f"[BL] {mac}"
                rem_choices.append(questionary.Choice(label, value=("blacklist", mac)))
            if not rem_choices:
                console.print(" [warning]No rules to remove.[/warning]\n")
                continue
            to_remove = questionary.checkbox(
                "Select rules to remove:",
                qmark="", instruction="(Space=toggle, Enter=confirm)",
                choices=rem_choices, style=custom_style
            ).ask(kbi_msg="")
            if to_remove:
                for cat, mac in to_remove:
                    rules[cat].pop(mac, None)
                save_predefined_rules(rules)
                console.print(f" [success]Removed {len(to_remove)} rule(s).[/success]\n")
