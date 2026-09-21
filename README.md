# Throttwin (Privated - This code won't work)

Windows-native per-device bandwidth limiter via ARP spoofing — the Windows equivalent of [Throttnux Plus](https://github.com/BloodCorrupt/throttnux), powered by **Scapy** and **Npcap**.

> **Windows only.** For Linux, use [Throttnux Plus](https://github.com/BloodCorrupt/throttnux) instead.

## How It Works

1. **ARP Spoofing** — Throttwin sends forged ARP replies to trick the target device into routing all its traffic through your machine.
2. **Packet Interception** — Scapy sniffs the intercepted traffic on the interface via Npcap.
3. **Token Bucket Rate Limiting** — A pure-Python Token Bucket enforces the bandwidth cap by dropping excess packets.
4. **Packet Forwarding** — Conforming packets are re-injected with corrected MACs and forwarded to their destination.
5. **Double-Power Aggressive ARP Discovery** — Combines native C multi-threaded ARP sweeping ([QbsuranAlang/arp-scan-windows-](https://github.com/QbsuranAlang/arp-scan-windows-)), multi-port LAN wakeup bursts (UDP 137/5353/53/80/443/8080), and Win32 SendARP for instantaneous device detection. Downloadable directly with 1-click in the Web UI sidebar.
6. **Nmap-First Aggressive Hostname Discovery** — Resolves rich friendly hostnames (e.g., `Galaxy-A52`, `Redmi-Note-14`, `SM-WORKSTATION`, `Annihilator-PC`, `Archer-AX50`) using **Nmap** (if installed) with seamless automatic fallback to Throttwin's built-in Native Multi-Vector Engine (Direct Router RFC 1035 UDP 53 DNS PTR, NetBIOS UDP 137, mDNS UDP 5353, SSDP/UPnP UDP 1900, LLMNR UDP 5355, HTTP Title probe, and SNMP). Continuous background refinement auto-updates device hostnames in real time.

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
- **Nmap (Recommended)** — [Download from nmap.org](https://nmap.org/download.html) or run `winget install Insecure.Nmap` / `choco install nmap` for enhanced hostname discovery *(optional; native fallback included)*
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

1. Selecting your network interface(s) — select one or multiple adapters simultaneously (e.g. Ethernet + Wi-Fi)
2. Selecting or auto-detecting your gateway/router per interface
3. Choosing operational mode (Blacklist or Whitelist) for each session
4. Picking target devices from a scanned list per subnet
5. Choosing bandwidth limits
6. Grand multi-session review
7. Unified live multi-interface bandwidth monitor while sessions are running

### Web UI Dashboard

```bat
:: Option 1: Standard Web UI (binds to 0.0.0.0, accessible on LAN)
runweb.bat

:: Option 2: Localhost-Only Web UI (binds strictly to 127.0.0.1, LAN blocked)
runweb_localhost.bat

:: Option 3: Run via CLI flag
run.bat --web
```

Open http://localhost:5000 in your browser.

Custom port or host:
```bat
runweb.bat --port 8080
runweb_localhost.bat --port 8080
```


### Example CLI Session

```
 _____ _               _   _            _       
|_   _| |__  _ __ ___ | |_| |___      _(_)_ __  
  | | | '_ \| '__/ _ \| __| __\ \ /\ / / | '_ \ 
  | | | | | | | | (_) | |_| |_ \ V  V /| | | | |
  |_| |_| |_|_|  \___/ \__|\__| \_/\_/ |_|_| |_|

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
| **Multi-Interface Sessions** | Run simultaneous, independent throttling sessions across multiple network adapters (e.g. Ethernet + Wi-Fi) with tabbed switching |
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
| Network Scanner | `arp-scan` binary | Win32 `SendARP` (256-thread) + NetBIOS/mDNS + 53K IEEE OUI DB |
| IP Forwarding | `/proc/sys/net/ipv4/ip_forward` | `netsh` + Registry key |
| Privileges | `sudo` / root | Windows Administrator |

## Saved Sessions

Throttwin saves your last session to `config/config.json`. On next launch, if the same network and targets are detected, you can resume the saved session without re-configuring.

## Global Rules

Persistent per-MAC rules are stored in `config/rules.json`:
- **Whitelist rules** — device is never throttled, even in whitelist mode
- **Blacklist rules** — device is always throttled in any future session

## Limitations

- **Your machine must stay on** while throttling is active — ARP spoof requires continuous packet sending.
- **Wired + Wi-Fi**: Works on both, but your interface must be on the same subnet as the targets.
- **WPA3 networks**: Some enterprise WPA3 configurations may prevent ARP spoofing.
- **Rate limiting accuracy**: Token Bucket operates at the packet level; actual throughput may vary ±10% depending on packet sizes and burst patterns.

## Disclaimer

This tool is intended for use **only on networks you own or have explicit permission to manage**. Do not use it on networks you do not control.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

