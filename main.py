import sys
import time
import socket
import select
import argparse
from parser import PacketParser
from engine import DetectionEngine, ScanAlert
from mitigation import MitigationEngine

def start_sniffer(interface: str, auto_block: bool = False, dry_run: bool = True):
    engine = DetectionEngine()
    mitigation = MitigationEngine(dry_run=dry_run)
    
    sock = None
    if hasattr(socket, "AF_INET") and hasattr(socket, "IPPROTO_TCP"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setblocking(False)
        except PermissionError:
            print("[ERROR] Administrator / Root privileges required for raw packet sniffing.")
            return

    try:
        while True:
            r, _, _ = select.select([sock], [], [], 0.5)
            if r:
                raw_bytes, addr = sock.recvfrom(65535)
                pkt = PacketParser.parse_raw_ipv4_tcp(raw_bytes)
                if pkt:
                    alerts = engine.process_packet(pkt)
                    for alert in alerts:
                        print(f"[{alert.severity}] Scan detected from {alert.src_ip} ({alert.scan_type.name}) - Ports: {alert.scanned_ports}")
                        if auto_block:
                            blocked = mitigation.block_ip(alert.src_ip)
                            if blocked:
                                print(f"[MITIGATION] Blocked {alert.src_ip} via iptables rule.")
    except KeyboardInterrupt:
        pass
    finally:
        if sock:
            sock.close()
        mitigation.flush_all()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--block", action="store_true", default=False)
    parser.add_argument("--live", action="store_true", default=False)
    args = parser.parse_args()

    start_sniffer(args.interface, auto_block=args.block, dry_run=not args.live)

if __name__ == "__main__":
    main()
