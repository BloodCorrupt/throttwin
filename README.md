# Throttwin

Windows-native per-device bandwidth limiter via ARP spoofing — the Windows equivalent of [Throttnux Plus](../throttnux), powered by **Scapy** and **Npcap**.

> **Windows only.** For Linux, use [Throttnux Plus](../throttnux) instead.

## How It Works

1. **ARP Spoofing** — Throttwin sends forged ARP replies to trick the target device into routing all its traffic through your machine.
2. **Packet Interception** — Scapy sniffs the intercepted traffic on the interface via Npcap.
3. **Token Bucket Rate Limiting** — A pure-Python Token Bucket enforces the bandwidth cap by dropping excess packets.
4. **Packet Forwarding** — Conforming packets are re-injected with corrected MACs and forwarded to their destination.

```
Without Throttwin:
  Target Device ───────────────────→ Router → Internet

With Throttwin:
  Target Device → Your Machine (Token Bucket limiter) → Router → Internet
```

## Requirements

- **Windows 10/11** (64-bit)
- **Npcap** — [Download from npcap.com](https://npcap.com/#download) *(already installed)*
- **Python 3.9+**
- **Administrator privileges** — required for raw packet capture/injection

## Installation

```bat
:: 1. Run setup (installs Python dependencies)
setup.bat

:: 2. Launch (auto-elevates to Administrator)
run.bat
```

Or manually:

```powershell
# Install dependencies
pip install -r requirements.txt

# Run as Administrator
python main.py
```

## Usage

### CLI (Interactive)

```bat
run.bat
```

Throttwin guides you through:

1. Selecting your network interface (auto-detected if only one)
2. Selecting your gateway/router (auto-detected)
3. Choosing operational mode (Blacklist or Whitelist)
4. Picking target devices from a scanned list
5. Choosing a bandwidth limit
6. Confirming the session review
7. Live bandwidth monitor while session is running

### Web UI Dashboard

```bat
:: Option 1: Double-click or run the dedicated Web UI script
runweb.bat

:: Option 2: Run via CLI flag
run.bat --web
```

Open http://localhost:5000 in your browser.

Custom port:
```bat
runweb.bat --port 8080
```


### Example CLI Session

```
  _   _                    _   _   _        _
 | |_| |__  _ __ ___  ___| |_| |_(_)__    _(_)_ __
 | __| '_ \| '__/ _ \/ __| __| __| \ \ /\ / / | '_ \
 | |_| | | | | | (_) \__ \ |_| |_| |\ V  V /| | | | |
  \__|_| |_|_|  \___/|___/\__|\__|_| \_/\_/ |_|_| |_|

  Per-device bandwidth limiter via ARP spoofing
  Windows Edition — powered by Scapy + Npcap

 Auto-selected interface: Wi-Fi (192.168.1.50)
 Auto-selected gateway: 192.168.1.1

 Found 4 device(s) on network

  IP Address       MAC Address        Device
  ─────────────────────────────────────────────────
  192.168.1.10     aa:bb:cc:dd:ee:01  Samsung Galaxy
  192.168.1.11     aa:bb:cc:dd:ee:02  Apple iPhone
  192.168.1.20     aa:bb:cc:dd:ee:03  Unknown
  192.168.1.30     aa:bb:cc:dd:ee:04  HP Laptop

 What would you like to do?
 > Start new session

 Select operational mode:
 > Blacklist — throttle specific devices

 Select devices to THROTTLE:
 [x] 192.168.1.11  aa:bb:cc:dd:ee:02  Apple iPhone

 Select bandwidth limit:
 > 1 Mbps — Heavy buffering, no HD YouTube

  Interface  : Wi-Fi
  Router     : 192.168.1.1
  Mode       : Blacklist
  Limit      : 1.0 Mbps
  Targets    : 1 device(s)

  Proceed? (y/n): y

 ARP spoofing active — launching live monitor...

┌──────────────────────────────────────────────────────────────────────┐
│                    Throttwin — Live Monitor                          │
├─────────────────┬──────────────────────┬──────────┬────────┬────────┤
│ IP Address      │ Device               │ Speed    │ Limit  │ Total  │
├─────────────────┼──────────────────────┼──────────┼────────┼────────┤
│ 192.168.1.11    │ Apple iPhone         │ 0.94 Mbps│ 1 Mbps │ 4.2 MB │
└─────────────────┴──────────────────────┴──────────┴────────┴────────┘
Total: 0.94 Mbps  |  Transferred: 4.2 MB  |  Uptime: 00:04:12  |  Ctrl+C to stop
```

## Modes

| Mode | Behaviour |
|------|-----------|
| **Blacklist** | Throttle specific selected devices. Everyone else is unaffected. |
| **Whitelist** | Throttle everyone **except** your safe list. New devices that join the network are automatically throttled. |

## Web UI Features

| Feature | Description |
|---------|-------------|
| Live Dashboard | Real-time throughput chart, target speed, total data throttled |
| Network Scanner | ARP sweep + Windows ARP cache discovery with vendor lookup |
| Hot-toggle | Add/remove targets from a running session without stopping |
| Live Limit Change | Adjust bandwidth cap on the fly with instant effect |
| Global Rules | Persistent whitelist/blacklist rules by MAC address |
| Manual Device | Add devices by IP or MAC when ARP scan misses them |
| SSE Stream | Real-time push updates — no polling from browser |

## Architecture (Windows vs Linux)

| Component | Linux (Throttnux) | Windows (Throttwin) |
|-----------|-------------------|---------------------|
| ARP Spoofing | `arpspoof` binary | Scapy `sendp()` via Npcap |
| Traffic Shaping | Linux `tc` HTB qdisc | Pure-Python Token Bucket + Scapy packet forwarder |
| Network Scanner | `arp-scan` binary | Scapy `srp()` + `arp -a` cache |
| IP Forwarding | `/proc/sys/net/ipv4/ip_forward` | `netsh` + Registry key |
| Privileges | `sudo` / root | Windows Administrator |

## Saved Sessions

Throttwin saves your last session to `~/.throttwin/config.json`. On next launch, if the same network and targets are detected, you can resume the saved session without re-configuring.

## Global Rules

Persistent per-MAC rules are stored in `~/.throttwin/rules.json`:
- **Whitelist rules** — device is never throttled, even in whitelist mode
- **Blacklist rules** — device is always throttled in any future session

## Limitations

- **Your machine must stay on** while throttling is active — ARP spoof requires continuous packet sending.
- **Wired + Wi-Fi**: Works on both, but your interface must be on the same subnet as the targets.
- **WPA3 networks**: Some enterprise WPA3 configurations may prevent ARP spoofing.
- **Rate limiting accuracy**: Token Bucket operates at the packet level; actual throughput may vary ±10% depending on packet sizes and burst patterns.

## Disclaimer

This tool is intended for use **only on networks you own or have explicit permission to manage**. Do not use it on networks you do not control.
