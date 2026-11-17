import unittest
from parser import PacketParser, ParsedPacket
from engine import DetectionEngine, ScanType
from mitigation import MitigationEngine

class TestPacketParser(unittest.TestCase):
    def test_syn_packet_parsing(self):
        ip_header = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x64\xc0\xa8\x01\x01"
        tcp_header = b"\x04\xd2\x00\x50\x00\x00\x03\xe8\x00\x00\x00\x00\x50\x02\x72\x10\x00\x00\x00\x00"
        raw_pkt = ip_header + tcp_header
        
        parsed = PacketParser.parse_raw_ipv4_tcp(raw_pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.src_ip, "192.168.1.100")
        self.assertEqual(parsed.dst_ip, "192.168.1.1")
        self.assertEqual(parsed.src_port, 1234)
        self.assertEqual(parsed.dst_port, 80)
        self.assertTrue(parsed.is_syn)
        self.assertFalse(parsed.is_ack)

class TestDetectionEngine(unittest.TestCase):
    def test_null_scan_detection(self):
        engine = DetectionEngine()
        pkt = ParsedPacket("10.0.0.5", "10.0.0.1", 4000, 22, 0, 100, 0)
        alerts = engine.process_packet(pkt, now=1.0)
        self.assertTrue(any(a.scan_type == ScanType.NULL_SCAN for a in alerts))

    def test_xmas_scan_detection(self):
        engine = DetectionEngine()
        pkt = ParsedPacket("10.0.0.5", "10.0.0.1", 4000, 22, 0x29, 100, 0)
        alerts = engine.process_packet(pkt, now=1.0)
        self.assertTrue(any(a.scan_type == ScanType.XMAS_SCAN for a in alerts))

    def test_fast_port_sweep(self):
        engine = DetectionEngine()
        alerts = []
        for p in range(1, 15):
            pkt = ParsedPacket("10.0.0.8", "10.0.0.1", 4000 + p, p, 0x02, 100, 0)
            alerts.extend(engine.process_packet(pkt, now=1.0 + (p * 0.05)))
        self.assertTrue(any(a.scan_type == ScanType.FAST_PORT_SWEEP for a in alerts))

    def test_syn_stealth_scan(self):
        engine = DetectionEngine()
        alerts = []
        for p in range(1, 15):
            pkt = ParsedPacket("10.0.0.9", "10.0.0.1", 5000 + p, p, 0x02, 100, 0)
            alerts.extend(engine.process_packet(pkt, now=1.0 + p * 2.0))
        self.assertTrue(any(a.scan_type == ScanType.SYN_STEALTH for a in alerts))

class TestMitigationEngine(unittest.TestCase):
    def test_dry_run_mitigation(self):
        mitigation = MitigationEngine(dry_run=True)
        res = mitigation.block_ip("192.168.1.50")
        self.assertTrue(res)
        self.assertIn("192.168.1.50", mitigation.blocked_ips)
        res2 = mitigation.unblock_ip("192.168.1.50")
        self.assertTrue(res2)
        self.assertNotIn("192.168.1.50", mitigation.blocked_ips)

if __name__ == "__main__":
    unittest.main()
