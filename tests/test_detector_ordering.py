"""Tests for timestamp ordering across destination IPs."""

import unittest

from network_ids.detector import NetworkIDS


class TestDetectorTimestampOrdering(unittest.TestCase):
    def test_syn_flood_rejects_out_of_order_timestamp_across_destinations(self):
        ids = NetworkIDS(
            port_threshold=10,
            syn_threshold=3,
            window_seconds=60,
        )

        # First valid observation from the source.
        self.assertEqual(
            ids.observe("10.0.0.5", "10.0.0.10", 80, 10),
            [],
        )

        # A timestamp older than the previous source observation is rejected.
        with self.assertRaisesRegex(ValueError, "non-decreasing"):
            ids.observe("10.0.0.5", "10.0.0.20", 80, 9)

        # The rejected packet must not count toward the threshold.
        alerts = ids.observe("10.0.0.5", "10.0.0.20", 80, 11)
        syn_alerts = [
            alert for alert in alerts if alert.rule == "SYN_FLOOD"
        ]
        self.assertEqual(syn_alerts, [])

        # The third valid observation triggers the alert across destinations.
        alerts = ids.observe("10.0.0.5", "10.0.0.30", 80, 12)
        syn_alerts = [
            alert for alert in alerts if alert.rule == "SYN_FLOOD"
        ]

        self.assertEqual(len(syn_alerts), 1)
        self.assertEqual(syn_alerts[0].source_ip, "10.0.0.5")
        self.assertIn("3 TCP SYN packets", syn_alerts[0].details)


if __name__ == "__main__":
    unittest.main()
