"""Capture live TCP traffic and analyze packets from PCAP files."""

import logging
from pathlib import Path

from scapy.all import IP, TCP, sniff
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapReader

from network_ids.detector import Alert, NetworkIDS

logger = logging.getLogger("network_ids.capture")


def process_packet(
    packet: Packet,
    detector: NetworkIDS,
) -> Alert | None:
    """Process a packet and detect possible TCP port scans."""
    if IP not in packet or TCP not in packet:
        return None

    tcp = packet[TCP]
    flags = int(tcp.flags)

    # Only process initial TCP SYN packets, not SYN-ACK packets.
    if not (flags & 0x02) or (flags & 0x10):
        return None

    ip = packet[IP]

    try:
        alert = detector.observe(
            source_ip=ip.src,
            destination_ip=ip.dst,
            destination_port=int(tcp.dport),
        )
    except ValueError:
        logger.exception("Invalid packet data rejected by detector")
        return None

    if alert is not None:
        logger.warning(
            "IDS alert: rule=%s source=%s destination=%s details=%s",
            alert.rule,
            alert.source_ip,
            alert.destination_ip,
            alert.details,
        )

    return alert


def analyze_pcap(
    pcap_file: str | Path,
    detector: NetworkIDS,
) -> int:
    """Analyze packets in a PCAP file and return the number of packets read."""
    path = Path(pcap_file)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    packet_count = 0

    logger.info("Starting PCAP analysis: %s", path)

    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                packet_count += 1
                process_packet(packet, detector)
    except (Scapy_Exception, OSError):
        logger.exception("Failed to analyze PCAP file: %s", path)
        raise

    logger.info(
        "PCAP analysis completed: %s packets processed from %s",
        packet_count,
        path,
    )

    return packet_count


def start_capture(
    detector: NetworkIDS,
    interface: str | None = None,
) -> None:
    """Capture TCP packets until interrupted by the user."""
    logger.info(
        "Starting TCP capture on interface %s",
        interface or "default",
    )

    try:
        sniff(
            iface=interface,
            filter="tcp",
            prn=lambda packet: process_packet(packet, detector),
            store=False,
        )
    except KeyboardInterrupt:
        logger.info("Packet capture stopped by user")
    except PermissionError:
        logger.exception("Packet capture requires appropriate permissions")
        raise
    except Scapy_Exception:
        logger.exception("Scapy failed to capture packets")
        raise
