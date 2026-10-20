"""Tests for network threat detection."""

import unittest

from network_ids.detector import NetworkIDS


class TestNetworkIDS(unittest.TestCase):
    """Test TCP port scan and SYN flood detection."""

    def test_detects_port_scan(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)

        alerts = ids.observe("10.0.0.5", "10.0.0.10", 443, 3)

        self.assertEqual([a.rule for a in alerts], ["PORT_SCAN"])
        self.assertEqual(alerts[0].source_ip, "10.0.0.5")
        self.assertEqual(alerts[0].destination_ip, "10.0.0.10")
        self.assertIn("3 distinct destination ports", alerts[0].details)

    def test_repeated_port_does_not_trigger_scan(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)

        for timestamp in range(1, 6):
            alerts = ids.observe(
                "10.0.0.5", "10.0.0.10", 80, timestamp
            )

        self.assertEqual(alerts, [])

    def test_old_observations_expire(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=10)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)

        alerts = ids.observe("10.0.0.5", "10.0.0.10", 443, 20)

        self.assertEqual(alerts, [])

    def test_only_one_alert_per_detection_period(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)

        first = ids.observe("10.0.0.5", "10.0.0.10", 443, 3)
        second = ids.observe("10.0.0.5", "10.0.0.10", 8080, 4)

        self.assertEqual([a.rule for a in first], ["PORT_SCAN"])
        self.assertEqual(second, [])

    def test_detection_can_rearm_after_window_expires(self):
        ids = NetworkIDS(port_threshold=2, window_seconds=10)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        first = ids.observe("10.0.0.5", "10.0.0.10", 80, 2)

        self.assertEqual([a.rule for a in first], ["PORT_SCAN"])

        ids.observe("10.0.0.5", "10.0.0.10", 443, 20)
        second = ids.observe("10.0.0.5", "10.0.0.10", 8080, 21)

        self.assertEqual([a.rule for a in second], ["PORT_SCAN"])

    def test_out_of_order_timestamp_is_rejected(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)
        ids.observe("10.0.0.5", "10.0.0.10", 22, 10)

        with self.assertRaisesRegex(ValueError, "non-decreasing"):
            ids.observe("10.0.0.5", "10.0.0.10", 80, 9)

    def test_non_finite_timestamp_is_rejected(self):
        ids = NetworkIDS()

        for timestamp in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timestamp=timestamp):
                with self.assertRaisesRegex(ValueError, "finite"):
                    ids.observe("10.0.0.5", "10.0.0.10", 80, timestamp)

    def test_invalid_port_is_rejected(self):
        ids = NetworkIDS()

        for port in (0, 65536, -1, True, 80.0):
            with self.subTest(port=port):
                with self.assertRaisesRegex(ValueError, "destination_port"):
                    ids.observe("10.0.0.5", "10.0.0.10", port, 1)

    def test_invalid_configuration_is_rejected(self):
        invalid_configs = (
            {"port_threshold": 1},
            {"port_threshold": True},
            {"window_seconds": 0},
            {"window_seconds": float("inf")},
            {"window_seconds": float("nan")},
            {"window_seconds": True},
            {"syn_threshold": 1},
            {"syn_threshold": True},
        )

        for config in invalid_configs:
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    NetworkIDS(**config)

    def test_detects_syn_flood(self):
        ids = NetworkIDS(
            port_threshold=10, syn_threshold=3, window_seconds=60
        )

        ids.observe("10.0.0.5", "10.0.0.10", 80, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)
        alerts = ids.observe("10.0.0.5", "10.0.0.10", 80, 3)

        self.assertEqual([a.rule for a in alerts], ["SYN_FLOOD"])
        self.assertEqual(alerts[0].source_ip, "10.0.0.5")
        self.assertEqual(alerts[0].destination_ip, "10.0.0.10")
        self.assertIn("3 TCP SYN packets", alerts[0].details)

    def test_syn_flood_alert_rearms_after_window_expires(self):
        ids = NetworkIDS(
            port_threshold=10, syn_threshold=2, window_seconds=10
        )

        ids.observe("10.0.0.5", "10.0.0.10", 80, 1)
        first = ids.observe("10.0.0.5", "10.0.0.10", 80, 2)
        self.assertEqual([a.rule for a in first], ["SYN_FLOOD"])

        ids.observe("10.0.0.5", "10.0.0.10", 80, 20)
        second = ids.observe("10.0.0.5", "10.0.0.10", 80, 21)
        self.assertEqual([a.rule for a in second], ["SYN_FLOOD"])

    def test_syn_flood_does_not_trigger_below_threshold(self):
        ids = NetworkIDS(
            port_threshold=10, syn_threshold=4, window_seconds=60
        )

        for timestamp in range(1, 4):
            alerts = ids.observe(
                "10.0.0.5", "10.0.0.10", 80, timestamp
            )

        self.assertEqual(alerts, [])

    def test_syn_flood_counts_multiple_destinations_per_source(self):
        ids = NetworkIDS(
            port_threshold=10, syn_threshold=3, window_seconds=60
        )

        self.assertEqual(
            ids.observe("10.0.0.5", "10.0.0.10", 80, 1), []
        )
        self.assertEqual(
            ids.observe("10.0.0.5", "10.0.0.20", 80, 2), []
        )

        alerts = ids.observe("10.0.0.5", "10.0.0.30", 80, 3)
        syn_alerts = [a for a in alerts if a.rule == "SYN_FLOOD"]

        self.assertEqual(len(syn_alerts), 1)
        self.assertEqual(syn_alerts[0].source_ip, "10.0.0.5")
        self.assertIn("3 TCP SYN packets", syn_alerts[0].details)

    def test_both_rules_can_trigger_on_same_observation(self):
        ids = NetworkIDS(
            port_threshold=3, syn_threshold=3, window_seconds=60
        )

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)
        alerts = ids.observe("10.0.0.5", "10.0.0.10", 443, 3)

        self.assertEqual(
            {a.rule for a in alerts},
            {"SYN_FLOOD", "PORT_SCAN"},
        )


if __name__ == "__main__":
    unittest.main()
