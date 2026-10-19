"""Capture TCP SYN packets and forward them to the IDS detector."""

import logging

from scapy.all import IP, TCP, sniff
from scapy.packet import Packet

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

    # Ignore packets that are not initial TCP SYN packets.
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
