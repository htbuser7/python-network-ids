
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

        with self.assertRaises(ValueError):
            ids.observe("10.0.0.5", "10.0.0.10", 70000, 1)


if __name__ == "__main__":
    unittest.main()

