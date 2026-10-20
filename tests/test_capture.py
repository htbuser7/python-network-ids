
"""Tests for packet capture and PCAP analysis."""

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
from network_ids.detector import Alert, NetworkIDS


class TestPacketCapture(unittest.TestCase):
    """Test packet processing, capture, and JSON reporting."""

    def setUp(self):
        self.ids = NetworkIDS(
            port_threshold=3,
            syn_threshold=100,
            window_seconds=60,
        )

    def test_syn_packet_is_processed(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=40000, dport=80, flags="S"
        )
        self.assertEqual(process_packet(packet, self.ids), [])

    def test_non_tcp_packet_is_ignored(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / UDP(
            sport=40000, dport=53
        )
        self.assertEqual(process_packet(packet, self.ids), [])

    def test_syn_ack_packet_is_ignored(self):
        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=80, dport=40000, flags="SA"
        )
        self.assertEqual(process_packet(packet, self.ids), [])

    def test_scan_triggers_alert(self):
        for port in (22, 80):
            packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
                sport=40000, dport=port, flags="S"
            )
            self.assertEqual(process_packet(packet, self.ids), [])

        packet = IP(src="10.0.0.5", dst="10.0.0.10") / TCP(
            sport=40000, dport=443, flags="S"
        )
        alerts = process_packet(packet, self.ids)

        self.assertEqual([alert.rule for alert in alerts], ["PORT_SCAN"])
        self.assertEqual(alerts[0].source_ip, "10.0.0.5")
        self.assertEqual(alerts[0].destination_ip, "10.0.0.10")
        self.assertIn("3 distinct destination ports", alerts[0].details)

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
            try:
                writer.write(packet)
            finally:
                writer.close()

            count = analyze_pcap(pcap_path, self.ids)

        self.assertEqual(count, 1)

    def test_json_report_contains_packet_count_and_alerts(self):
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

    def test_json_report_write_error_is_propagated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"

            with patch.object(
                Path,
                "write_text",
                side_effect=PermissionError("simulated permission error"),
            ):
                with self.assertRaisesRegex(
                    PermissionError, "simulated permission error"
                ):
                    write_json_report(report_path, 3, [])

    def test_analyze_pcap_and_write_report_with_port_scan(self):
        packets = [
            IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=40000, dport=port, flags="S")
            for port in (22, 80, 443)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "scan.pcap"
            report_path = Path(temp_dir) / "report.json"

            writer = PcapWriter(str(pcap_path), sync=True)
            try:
                for packet in packets:
                    writer.write(packet)
            finally:
                writer.close()

            alerts = []
            detector = NetworkIDS(
                port_threshold=3,
                syn_threshold=100,
                window_seconds=60,
            )
            packet_count = analyze_pcap(pcap_path, detector, alerts=alerts)
            write_json_report(report_path, packet_count, alerts)

            with report_path.open(encoding="utf-8") as report_file:
                report = json.load(report_file)

        self.assertEqual(report["packets_analyzed"], 3)
        self.assertEqual(report["alert_count"], 1)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["rule"], "PORT_SCAN")
        self.assertEqual(report["alerts"][0]["source_ip"], "10.0.0.5")
        self.assertEqual(
            report["alerts"][0]["destination_ip"], "10.0.0.10"
        )

    def test_pcap_report_includes_both_rules(self):
        packets = [
            IP(src="10.0.0.5", dst="10.0.0.10")
            / TCP(sport=40000, dport=port, flags="S")
            for port in (22, 80, 443)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = Path(temp_dir) / "both_rules.pcap"
            report_path = Path(temp_dir) / "report.json"

            writer = PcapWriter(str(pcap_path), sync=True)
            try:
                for packet in packets:
                    writer.write(packet)
            finally:
                writer.close()

            alerts = []
            detector = NetworkIDS(
                port_threshold=3,
                syn_threshold=3,
                window_seconds=60,
            )
            packet_count = analyze_pcap(pcap_path, detector, alerts=alerts)
            write_json_report(report_path, packet_count, alerts)

            with report_path.open(encoding="utf-8") as report_file:
                report = json.load(report_file)

        self.assertEqual(report["packets_analyzed"], 3)
        self.assertEqual(report["alert_count"], 2)
        self.assertEqual(
            {alert["rule"] for alert in report["alerts"]},
            {"SYN_FLOOD", "PORT_SCAN"},
        )

    def test_analyze_missing_pcap_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            analyze_pcap("/nonexistent-directory/missing.pcap", self.ids)


if __name__ == "__main__":
    unittest.main()
