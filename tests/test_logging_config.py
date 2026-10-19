import logging
import tempfile
import unittest
from pathlib import Path

from network_ids.logging_config import configure_logging


class TestLoggingConfig(unittest.TestCase):
    def test_logs_to_file(self):
        logger = logging.getLogger("network_ids")
        original_handlers = logger.handlers[:]

        # Isolate this test from any previous logging configuration.
        for handler in original_handlers:
            logger.removeHandler(handler)

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_file = Path(temp_dir) / "logs" / "ids.log"

                configured_logger = configure_logging(log_file)
                configured_logger.warning("Test security alert")

                for handler in configured_logger.handlers:
                    handler.flush()

                self.assertTrue(log_file.exists())
                self.assertIn(
                    "Test security alert",
                    log_file.read_text(encoding="utf-8"),
                )
        finally:
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
                handler.close()

            for handler in original_handlers:
                logger.addHandler(handler)


if __name__ == "__main__":
    unittest.main()
