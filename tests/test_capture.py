import unittest

from scapy.all import IP, TCP, UDP

from network_ids.capture import process_packet
from network_ids.detector import NetworkIDS


class TestPacketCapture(unittest.TestCase):
    def setUp(self):
        self.ids = NetworkIDS(port_threshold=3, window_seconds=60)

    def test_syn_packet_is_processed(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=40000, dport=80, flags="S"
        )

        alert = process_packet(packet, self.ids)

        self.assertIsNone(alert)

    def test_non_tcp_packet_is_ignored(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / UDP(
            sport=40000, dport=53
        )

        self.assertIsNone(process_packet(packet, self.ids))

    def test_syn_ack_packet_is_ignored(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=80, dport=40000, flags="SA"
        )

        self.assertIsNone(process_packet(packet, self.ids))

    def test_scan_triggers_alert(self):
        for port in (22, 80):
            packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
                sport=40000, dport=port, flags="S"
            )
            self.assertIsNone(process_packet(packet, self.ids))

        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=40000, dport=443, flags="S"
        )

        alert = process_packet(packet, self.ids)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule, "PORT_SCAN")
        self.assertEqual(alert.source_ip, "10.0.0.5")
        self.assertEqual(alert.destination_ip, "10.0.0.10")
        self.assertEqual(alert.rule, "PORT_SCAN")
        self.assertIn("3 distinct destination ports", alert.details)


if __name__ == "__main__":
    unittest.main()
