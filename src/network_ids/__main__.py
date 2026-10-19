
"""Command-line entry point for the network IDS."""

import argparse
import logging

from scapy.all import get_if_list

from network_ids.capture import start_capture
from network_ids.detector import NetworkIDS
from network_ids.logging_config import configure_logging


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Python Network Intrusion Detection System"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to monitor (default: Scapy default)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Distinct destination ports needed to trigger an alert (default: 10)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=60.0,
        help="Detection window in seconds (default: 60)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )
    return parser.parse_args()


def main() -> None:
    """Configure and start the IDS."""
    args = parse_args()

    if args.list_interfaces:
        for interface in get_if_list():
            print(interface)
        return

    logger = configure_logging()
    try:
        detector = NetworkIDS(
            port_threshold=args.threshold,
            window_seconds=args.window,
            logger=logger,
        )
    except ValueError as exc:
        logging.error("Invalid configuration: %s", exc)
        raise SystemExit(2) from exc

    logger.info("Starting Python Network IDS")
    start_capture(detector, interface=args.interface)


if __name__ == "__main__":
    main()
