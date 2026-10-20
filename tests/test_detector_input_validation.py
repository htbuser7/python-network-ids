"""Tests for IP address validation and normalization."""

import unittest

from network_ids.detector import NetworkIDS


class TestDetectorInputValidation(unittest.TestCase):
    def test_invalid_source_ip_is_rejected(self):
        ids = NetworkIDS()

        with self.assertRaisesRegex(ValueError, "source_ip"):
            ids.observe("not-an-ip", "10.0.0.10", 80, 1)

    def test_invalid_destination_ip_is_rejected(self):
        ids = NetworkIDS()

        with self.assertRaisesRegex(ValueError, "destination_ip"):
            ids.observe("10.0.0.5", "not-an-ip", 80, 1)

    def test_non_string_ip_is_rejected(self):
        ids = NetworkIDS()

        with self.assertRaisesRegex(ValueError, "source_ip"):
            ids.observe(123, "10.0.0.10", 80, 1)

    def test_equivalent_ipv6_source_addresses_are_aggregated(self):
        ids = NetworkIDS(
            port_threshold=10,
            syn_threshold=2,
            window_seconds=60,
        )

        first_alerts = ids.observe(
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::10",
            80,
            1,
        )
        self.assertFalse(
            any(alert.rule == "SYN_FLOOD" for alert in first_alerts)
        )

        alerts = ids.observe(
            "2001:db8::1",
            "2001:db8::20",
            80,
            2,
        )

        syn_alerts = [
            alert for alert in alerts if alert.rule == "SYN_FLOOD"
        ]
        self.assertEqual(len(syn_alerts), 1)
        self.assertEqual(syn_alerts[0].source_ip, "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
