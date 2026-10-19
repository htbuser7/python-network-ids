
import logging
from pathlib import Path


def configure_logging(
    log_file: str | Path = "logs/network_ids.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure console and file logging for the IDS."""
    logger = logging.getLogger("network_ids")
    logger.setLevel(level)
    logger.propagate = False

    # Avoid adding duplicate handlers if called more than once.
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
