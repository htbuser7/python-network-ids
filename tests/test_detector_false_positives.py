"""Tests that help prevent false-positive network alerts."""

import unittest

from network_ids.detector import NetworkIDS


class TestFalsePositivePrevention(unittest.TestCase):
    def test_syn_packets_from_different_sources_are_not_aggregated(self):
        ids = NetworkIDS(
            port_threshold=10,
            syn_threshold=3,
            window_seconds=60,
        )

        observations = [
            ("10.0.0.5", "10.0.0.10", 80, 1),
            ("10.0.0.6", "10.0.0.10", 80, 2),
            ("10.0.0.5", "10.0.0.20", 80, 3),
            ("10.0.0.6", "10.0.0.20", 80, 4),
        ]

        for source, destination, port, timestamp in observations:
            alerts = ids.observe(
                source,
                destination,
                port,
                timestamp,
            )
            self.assertFalse(
                any(alert.rule == "SYN_FLOOD" for alert in alerts),
                "SYN packets from different sources must not be combined",
            )

    def test_old_syn_observations_do_not_trigger_flood(self):
        ids = NetworkIDS(
            port_threshold=10,
            syn_threshold=3,
            window_seconds=10,
        )

        ids.observe("10.0.0.5", "10.0.0.10", 80, 1)
        ids.observe("10.0.0.5", "10.0.0.20", 80, 2)

        # The old observations should have expired.
        alerts = ids.observe("10.0.0.5", "10.0.0.30", 80, 12.1)
        self.assertFalse(
            any(alert.rule == "SYN_FLOOD" for alert in alerts)
        )

        alerts = ids.observe("10.0.0.5", "10.0.0.40", 80, 12.2)
        self.assertFalse(
            any(alert.rule == "SYN_FLOOD" for alert in alerts)
        )

        # Three fresh observations within the window should trigger an alert.
        alerts = ids.observe("10.0.0.5", "10.0.0.50", 80, 12.3)
        self.assertTrue(
            any(alert.rule == "SYN_FLOOD" for alert in alerts)
        )

    def test_ports_on_different_destinations_are_not_combined(self):
        ids = NetworkIDS(
            port_threshold=2,
            syn_threshold=100,
            window_seconds=60,
        )

        first_alerts = ids.observe(
            "10.0.0.5", "10.0.0.10", 22, 1
        )
        second_alerts = ids.observe(
            "10.0.0.5", "10.0.0.20", 23, 2
        )

        self.assertFalse(
            any(alert.rule == "PORT_SCAN" for alert in first_alerts)
        )
        self.assertFalse(
            any(alert.rule == "PORT_SCAN" for alert in second_alerts)
        )


if __name__ == "__main__":
    unittest.main()
