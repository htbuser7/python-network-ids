
"""Command-line entry point for the network IDS."""

import argparse
import logging

from scapy.all import get_if_list
from scapy.error import Scapy_Exception

from network_ids.capture import analyze_pcap, start_capture, write_json_report
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
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Analyze packets from a PCAP file instead of capturing live traffic",
    )
    parser.add_argument(
        "--report",
        metavar="FILE",
        help="Write a JSON report for PCAP analysis",
    )
    return parser.parse_args()


def main() -> None:
    """Configure and run the IDS."""
    args = parse_args()

    if args.list_interfaces:
        for interface in get_if_list():
            print(interface)
        return

    if args.report and not args.pcap:
        print("--report requires --pcap", file=__import__("sys").stderr)
        raise SystemExit(2)

    logger = configure_logging()

    try:
        detector = NetworkIDS(
            port_threshold=args.threshold,
            window_seconds=args.window,
            logger=logger,
        )
    except ValueError as exc:
        logger.error("Invalid configuration: %s", exc)
        raise SystemExit(2) from exc

    if args.pcap:
        logger.info("Starting PCAP analysis: %s", args.pcap)
        alerts = []
        try:
            packet_count = analyze_pcap(args.pcap, detector, alerts=alerts)
            if args.report:
                write_json_report(args.report, packet_count, alerts)
        except (FileNotFoundError, OSError, Scapy_Exception) as exc:
            logger.error("PCAP analysis failed: %s", exc)
            raise SystemExit(1) from exc

        logger.info(
            "PCAP analysis finished: %d packets processed; %d alerts",
            packet_count,
            len(alerts),
        )
        return

    logger.info("Starting Python Network IDS")
    try:
        start_capture(detector, interface=args.interface)
    except (PermissionError, Scapy_Exception):
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
