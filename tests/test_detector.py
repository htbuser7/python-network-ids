
import unittest

from network_ids.detector import NetworkIDS


class TestNetworkIDS(unittest.TestCase):
    def test_detects_port_scan(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)

        self.assertIsNone(ids.observe("10.0.0.5", "10.0.0.10", 22, 1))
        self.assertIsNone(ids.observe("10.0.0.5", "10.0.0.10", 80, 2))

        alert = ids.observe("10.0.0.5", "10.0.0.10", 443, 3)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule, "PORT_SCAN")
        self.assertEqual(alert.source_ip, "10.0.0.5")

    def test_repeated_port_does_not_trigger_scan(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)

        for timestamp in range(1, 6):
            alert = ids.observe(
                "10.0.0.5", "10.0.0.10", 80, timestamp
            )

        self.assertIsNone(alert)

    def test_old_observations_expire(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=10)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)

        alert = ids.observe("10.0.0.5", "10.0.0.10", 443, 20)

        self.assertIsNone(alert)

    def test_invalid_port_is_rejected(self):
        ids = NetworkIDS()

        for port in (0, 65536, True, 80.5):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    ids.observe("10.0.0.5", "10.0.0.10", port, 1)

    def test_only_one_alert_per_detection_period(self):
        ids = NetworkIDS(port_threshold=3, window_seconds=60)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        ids.observe("10.0.0.5", "10.0.0.10", 80, 2)

        first_alert = ids.observe("10.0.0.5", "10.0.0.10", 443, 3)
        second_alert = ids.observe("10.0.0.5", "10.0.0.10", 8080, 4)

        self.assertIsNotNone(first_alert)
        self.assertIsNone(second_alert)

    def test_detection_can_rearm_after_window_expires(self):
        ids = NetworkIDS(port_threshold=2, window_seconds=10)

        ids.observe("10.0.0.5", "10.0.0.10", 22, 1)
        first_alert = ids.observe("10.0.0.5", "10.0.0.10", 80, 2)
        self.assertIsNotNone(first_alert)

        ids.observe("10.0.0.5", "10.0.0.10", 443, 20)
        second_alert = ids.observe("10.0.0.5", "10.0.0.10", 8080, 21)

        self.assertIsNotNone(second_alert)
        self.assertEqual(second_alert.rule, "PORT_SCAN")

    def test_out_of_order_timestamp_is_rejected(self):
        ids = NetworkIDS()

        ids.observe("10.0.0.5", "10.0.0.10", 22, 10)

        with self.assertRaises(ValueError):
            ids.observe("10.0.0.5", "10.0.0.10", 80, 9)

    def test_non_finite_timestamp_is_rejected(self):
        ids = NetworkIDS()

        for timestamp in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(ValueError):
                    ids.observe(
                        "10.0.0.5", "10.0.0.10", 22, timestamp
                    )

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            NetworkIDS(port_threshold=1)

        with self.assertRaises(ValueError):
            NetworkIDS(window_seconds=0)

        with self.assertRaises(ValueError):
            NetworkIDS(window_seconds=float("inf"))


if __name__ == "__main__":
    unittest.main()
