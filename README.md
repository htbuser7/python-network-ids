# Python Network Intrusion Detection System

A modular Python-based Network Intrusion Detection System (NIDS) for
monitoring TCP SYN traffic, identifying potential port scans and unusually
high SYN traffic, and generating structured JSON reports.

This project is an educational prototype for learning about packet analysis,
intrusion detection, Python testing, and network security.

## Project Status

The current package version is `0.1.0`. The project is under development and
is not intended to replace a production-grade intrusion detection system.

Detection rules use behavioral thresholds. An alert indicates suspicious
activity and requires investigation; it does not prove that an attack occurred.

## Features

- Live packet capture using Scapy
- Offline analysis of PCAP files
- TCP SYN packet inspection
- Port scan detection based on distinct destination ports
- SYN flood detection aggregated by source IP across destination IPs
- Configurable thresholds and detection time windows
- IPv4 and IPv6 address validation and canonicalization
- Alerts containing source and destination IP addresses
- JSON reports containing packet counts and detected alerts
- Console and file-based logging
- Command-line interface
- Automated tests and GitHub Actions integration
- Input validation and capture error handling

## Requirements

- Python 3.10 or newer
- Scapy
- Linux recommended for live packet capture
- Appropriate privileges to capture traffic on the selected interface

## Installation

Clone the repository:

```bash
git clone https://github.com/htbuser7/python-network-ids.git
cd python-network-ids
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project and development dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Usage

### List network interfaces

```bash
python -m network_ids --list-interfaces
```

### Start live monitoring

Choose an interface available on your system:

```bash
sudo .venv/bin/python -m network_ids --interface eth0
```

Replace `eth0` with your actual interface name. Live capture may require
elevated privileges. Stop monitoring with `Ctrl+C`.

### Configure detection rules

Set the number of distinct destination ports required for a port scan alert:

```bash
sudo .venv/bin/python -m network_ids \
  --interface eth0 \
  --threshold 5
```

Configure the SYN packet threshold:

```bash
sudo .venv/bin/python -m network_ids \
  --interface eth0 \
  --syn-threshold 100
```

Configure the detection window in seconds:

```bash
sudo .venv/bin/python -m network_ids \
  --interface eth0 \
  --threshold 5 \
  --syn-threshold 100 \
  --window 30
```

The default port scan threshold is 10 distinct destination ports. The default
SYN threshold is 100 packets, and the default detection window is 60 seconds.
These values are configurable defaults, not universal production settings.

### Analyze a PCAP file

Analyze a saved packet capture without starting live monitoring:

```bash
python -m network_ids \
  --pcap samples/demo_port_scan.pcap
```

### Generate a JSON report

Create a directory for reports and specify the report path:

```bash
mkdir -p reports

python -m network_ids \
  --pcap samples/demo_port_scan.pcap \
  --report reports/demo_report.json
```

Inspect the report:

```bash
cat reports/demo_report.json
```

The report includes the number of packets analyzed, the number of alerts,
and the details of each alert.

### Demonstrate both detection rules

The included sample capture contains three TCP SYN packets directed at three
distinct destination ports. Use lower thresholds to demonstrate both rules:

```bash
mkdir -p reports

python -m network_ids \
  --pcap samples/demo_port_scan.pcap \
  --report reports/demo_both_rules_report.json \
  --threshold 3 \
  --syn-threshold 3
```

Inspect the resulting report:

```bash
cat reports/demo_both_rules_report.json
```

The expected result for this sample is three analyzed packets and two alerts:
`SYN_FLOOD` and `PORT_SCAN`.

These thresholds are deliberately low for demonstration purposes and are
not recommended production settings.

## Detection Rules

### PORT_SCAN

Tracks distinct TCP destination ports for each source IP and destination IP
pair within the configured time window. An alert is generated when the
number of distinct destination ports reaches the configured threshold.

Repeated observations of the same destination port do not increase the
distinct-port count.

### SYN_FLOOD

Counts TCP SYN observations from each source IP across all destination IPs
within the configured time window. An alert is generated when the number of
observations from one source reaches the configured SYN threshold.

The destination in the alert identifies the destination associated with the
observation that triggered it. Both detection rules can trigger on the same
observation and maintain their own alert state.

A SYN packet count alone does not confirm a SYN flood. Alerts require
investigation and, where possible, additional network evidence.

## Input Validation and Timestamps

The detection engine validates IPv4 and IPv6 addresses and canonicalizes
their textual representations. Invalid addresses, invalid destination
ports, and non-finite timestamps are rejected.

For consistent window calculations, timestamps must be non-decreasing for
each source/destination pair and for each source IP's SYN flood observations.

## Logging

Events are logged to the console and, by default, to:

```text
logs/network_ids.log
```

The `logs/` directory and log files are excluded from version control.

## Running Tests

Activate the virtual environment and install the development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the full test suite:

```bash
python -m pytest -v
```

Tests cover detection rules, timestamp ordering, IP validation,
false-positive scenarios, packet processing, PCAP analysis, JSON reporting,
command-line behavior, logging, and capture errors.

## Continuous Integration

GitHub Actions runs the test suite when changes are pushed to `main` or a
pull request targets `main`. The workflow can also be started manually.

Review workflow results here:

https://github.com/htbuser7/python-network-ids/actions

## Current Limitations

- Detection focuses on TCP SYN traffic and threshold-based rules.
- Alerts can include false positives and require investigation.
- Thresholds may need tuning for different network environments.
- Live packet capture may require elevated privileges.
- Performance, resource usage, and long-running capture behavior need further
  validation before a stable release.
- This educational prototype has not been validated as a replacement for a
  production-grade IDS.

## Responsible Use

Only monitor networks and systems you own or are explicitly authorized to
assess. Packet capture can expose sensitive network information.

## License

No license has been selected yet. Do not assume the repository grants
permission to redistribute or reuse its code. Select an appropriate license
before the version 1.0 release.
