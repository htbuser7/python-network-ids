
"""Generate a synthetic PCAP file for local IDS demonstrations."""

import argparse
from pathlib import Path

from scapy.all import IP, TCP, wrpcap


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic TCP port-scan PCAP."
    )
    parser.add_argument(
        "--output",
        default="samples/demo_port_scan.pcap",
        help="Output PCAP path (default: samples/demo_port_scan.pcap)",
    )
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    packets = [
        IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=40000, dport=port, flags="S")
        for port in (22, 80, 443)
    ]

    wrpcap(str(output), packets)
    print(
        f"Created {output} with {len(packets)} synthetic TCP SYN packets."
    )


if __name__ == "__main__":
    main()
