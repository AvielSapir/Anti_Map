import time
from collections import deque
from enum import Enum, auto
from typing import Dict, Set, List, Optional
from parser import ParsedPacket

class ScanType(Enum):
    SYN_STEALTH = auto()
    TCP_CONNECT = auto()
    NULL_SCAN = auto()
    FIN_SCAN = auto()
    XMAS_SCAN = auto()
    FAST_PORT_SWEEP = auto()
    SLOW_DISTRIBUTED = auto()

class ScanAlert:
    def __init__(self, src_ip: str, scan_type: ScanType, scanned_ports: List[int], timestamp: float, severity: str = "HIGH"):
        self.src_ip = src_ip
        self.scan_type = scan_type
        self.scanned_ports = scanned_ports
        self.timestamp = timestamp
        self.severity = severity

class HostTracker:
    def __init__(self, src_ip: str):
        self.src_ip = src_ip
        self.events = deque()
        self.syn_records: Dict[int, float] = {}
        self.completed_handshakes: Set[int] = set()

    def add_packet(self, packet: ParsedPacket, now: float):
        self.events.append((now, packet))
        while self.events and now - self.events[0][0] > 60.0:
            self.events.popleft()
            
        if packet.is_syn:
            self.syn_records[packet.dst_port] = now
        elif packet.is_ack and packet.dst_port in self.syn_records:
            self.completed_handshakes.add(packet.dst_port)

    def get_recent_ports(self, window_seconds: float, now: float) -> Set[int]:
        ports = set()
        for ts, pkt in self.events:
            if now - ts <= window_seconds:
                ports.add(pkt.dst_port)
        return ports

class DetectionEngine:
    def __init__(self):
        self.hosts: Dict[str, HostTracker] = {}
        self.fast_sweep_threshold = 10
        self.fast_sweep_window = 2.0
        self.slow_sweep_threshold = 10
        self.slow_sweep_window = 45.0

    def process_packet(self, packet: ParsedPacket, now: float = None) -> List[ScanAlert]:
        if now is None:
            now = time.time()
            
        if packet.src_ip not in self.hosts:
            self.hosts[packet.src_ip] = HostTracker(packet.src_ip)
            
        tracker = self.hosts[packet.src_ip]
        tracker.add_packet(packet, now)
        alerts = []

        if packet.is_null:
            alerts.append(ScanAlert(packet.src_ip, ScanType.NULL_SCAN, [packet.dst_port], now, "CRITICAL"))
        elif packet.is_xmas:
            alerts.append(ScanAlert(packet.src_ip, ScanType.XMAS_SCAN, [packet.dst_port], now, "CRITICAL"))
        elif packet.is_fin and not (packet.flags & 0x10):
            alerts.append(ScanAlert(packet.src_ip, ScanType.FIN_SCAN, [packet.dst_port], now, "CRITICAL"))

        fast_ports = tracker.get_recent_ports(self.fast_sweep_window, now)
        if len(fast_ports) >= self.fast_sweep_threshold:
            alerts.append(ScanAlert(packet.src_ip, ScanType.FAST_PORT_SWEEP, list(fast_ports), now, "HIGH"))

        slow_ports = tracker.get_recent_ports(self.slow_sweep_window, now)
        if len(slow_ports) >= self.slow_sweep_threshold:
            syn_uncompleted = [p for p in slow_ports if p in tracker.syn_records and p not in tracker.completed_handshakes]
            if len(syn_uncompleted) >= self.fast_sweep_threshold:
                alerts.append(ScanAlert(packet.src_ip, ScanType.SYN_STEALTH, syn_uncompleted, now, "HIGH"))
            else:
                alerts.append(ScanAlert(packet.src_ip, ScanType.SLOW_DISTRIBUTED, list(slow_ports), now, "MEDIUM"))

        return alerts
