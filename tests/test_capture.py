import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import IP, TCP, UDP
from scapy.error import Scapy_Exception
from scapy.utils import PcapWriter

from network_ids.capture import (
    analyze_pcap,
    process_packet,
    start_capture,
    write_json_report,
)
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
        self.assertIn("3 distinct destination ports", alert.details)

    @patch("network_ids.capture.sniff", side_effect=PermissionError)
    def test_capture_permission_error_is_logged_and_raised(self, mock_sniff):
        with self.assertLogs("network_ids.capture", level="ERROR"):
            with self.assertRaises(PermissionError):
                start_capture(self.ids, interface="eth0")

        mock_sniff.assert_called_once()

    @patch("network_ids.capture.sniff", side_effect=KeyboardInterrupt)
    def test_capture_can_be_interrupted(self, mock_sniff):
        with self.assertLogs("network_ids.capture", level="INFO"):
            start_capture(self.ids, interface="eth0")

        mock_sniff.assert_called_once()

    @patch(
        "network_ids.capture.sniff",
        side_effect=Scapy_Exception("simulated capture failure"),
    )
    def test_scapy_error_is_logged_and_raised(self, mock_sniff):
        with self.assertLogs("network_ids.capture", level="ERROR"):
            with self.assertRaises(Scapy_Exception):
                start_capture(self.ids, interface="eth0")

        mock_sniff.assert_called_once()

    def test_analyze_pcap_counts_packets(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=40000, dport=80, flags="S"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "test.pcap"
            writer = PcapWriter(str(pcap_path), sync=True)
            writer.write(packet)
            writer.close()

            count = analyze_pcap(pcap_path, self.ids)

        self.assertEqual(count, 1)

    def test_json_report_contains_packet_count_and_alerts(self):
        from network_ids.detector import Alert

        alerts = [
            Alert(
                source_ip="10.0.0.5",
                destination_ip="10.0.0.10",
                rule="PORT_SCAN",
                details="3 distinct destination ports observed within 60 seconds",
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "reports" / "report.json"

            write_json_report(report_path, 3, alerts)

            with report_path.open(encoding="utf-8") as report_file:
                report = json.load(report_file)

        self.assertEqual(report["packets_analyzed"], 3)
        self.assertEqual(report["alert_count"], 1)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["rule"], "PORT_SCAN")
        self.assertEqual(report["alerts"][0]["source_ip"], "10.0.0.5")

    def test_json_report_without_alerts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"

            write_json_report(report_path, 3, [])

            with report_path.open(encoding="utf-8") as report_file:
                report = json.load(report_file)

        self.assertEqual(report["packets_analyzed"], 3)
        self.assertEqual(report["alert_count"], 0)
        self.assertEqual(report["alerts"], [])

    def test_analyze_missing_pcap_raises_error(self):
        with self.assertRaises(OSError):
            analyze_pcap(
                "/nonexistent-directory/missing.pcap",
                self.ids,
            )


if __name__ == "__main__":
    unittest.main()
