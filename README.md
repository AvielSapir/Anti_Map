# Anti_Map

A lightweight, zero-dependency Python Host-Based Intrusion Detection System (HIDS) that catches port scans in real time and can automatically block attackers via `iptables`.

## What it does

- **Raw packet parsing (`parser.py`)** – Decodes IPv4 and TCP headers directly from raw sockets without external libraries.
- **Scan detection (`engine.py`)** – Tracks per-IP activity over sliding time windows (`deque`) to spot:
  - Unusual TCP flag scans (`NULL`, `FIN`, `XMAS`)
  - Fast port sweeps & slow distributed scans
  - Half-open `SYN` stealth scans
- **Automated blocking (`mitigation.py`)** – Optionally drops offending IPs using Linux `iptables` rules (with a safe dry-run mode enabled by default, and automatic cleanup on exit).

## Quick start

Run the unit tests:
```bash
python test_antimap.py
```

Run in dry-run mode (alerts only, no firewall changes):
```bash
python main.py
```

Run live with automatic `iptables` blocking (Linux, requires root):
```bash
sudo python3 main.py --interface eth0 --block --live
```

## Project structure

- `main.py` – Raw socket sniffer loop and CLI entry point
- `parser.py` – Binary IPv4/TCP header parser
- `engine.py` – Sliding-window `HostTracker` and `DetectionEngine`
- `mitigation.py` – `iptables` wrapper with dry-run support
- `test_antimap.py` – Unit tests for parsing, detection, and mitigation
