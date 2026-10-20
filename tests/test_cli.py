
"""Tests for the Network IDS command-line interface."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from network_ids.__main__ import main


class TestCLI(unittest.TestCase):
    """Test command-line argument handling and application flow."""

    @patch("network_ids.__main__.get_if_list", return_value=["lo", "eth0"])
    @patch("sys.argv", ["network-ids", "--list-interfaces"])
    def test_list_interfaces(self, mock_get_if_list):
        with patch("builtins.print") as mock_print:
            main()

        self.assertEqual(mock_print.call_count, 2)
        mock_print.assert_any_call("lo")
        mock_print.assert_any_call("eth0")

    @patch("network_ids.__main__.start_capture")
    @patch("network_ids.__main__.configure_logging")
    @patch("sys.argv", ["network-ids", "--threshold", "3"])
    def test_valid_threshold_starts_capture(
        self, mock_configure_logging, mock_start_capture
    ):
        mock_configure_logging.return_value = __import__("logging").getLogger(
            "test_cli"
        )

        main()

        mock_start_capture.assert_called_once()

    @patch("network_ids.__main__.start_capture")
    @patch("network_ids.__main__.configure_logging")
    @patch(
        "sys.argv",
        ["network-ids", "--threshold", "1"],
    )
    def test_invalid_threshold_exits(
        self, mock_configure_logging, mock_start_capture
    ):
        import logging

        mock_configure_logging.return_value = logging.getLogger("test_cli")

        with self.assertRaises(SystemExit) as context:
            main()

        self.assertEqual(context.exception.code, 2)
        mock_start_capture.assert_not_called()

    @patch("network_ids.__main__.start_capture")
    @patch("network_ids.__main__.analyze_pcap", return_value=3)
    @patch("network_ids.__main__.configure_logging")
    def test_pcap_argument_analyzes_file(
        self, mock_configure_logging, mock_analyze_pcap, mock_start_capture
    ):
        import logging

        mock_configure_logging.return_value = logging.getLogger("test_cli")

        with patch("sys.argv", ["network-ids", "--pcap", "demo.pcap"]):
            main()

        mock_analyze_pcap.assert_called_once()
        self.assertEqual(mock_analyze_pcap.call_args.args[0], "demo.pcap")
        mock_start_capture.assert_not_called()

    @patch("network_ids.__main__.analyze_pcap", side_effect=FileNotFoundError("missing"))
    @patch("network_ids.__main__.configure_logging")
    def test_missing_pcap_file_exits(
        self, mock_configure_logging, mock_analyze_pcap
    ):
        import logging

        mock_configure_logging.return_value = logging.getLogger("test_cli")

        with patch("sys.argv", ["network-ids", "--pcap", "missing.pcap"]):
            with self.assertRaises(SystemExit) as context:
                main()

        self.assertEqual(context.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
