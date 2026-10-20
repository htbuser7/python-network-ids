# Python Network Intrusion Detection System

A modular, Python-based Network Intrusion Detection System (NIDS) that analyzes TCP SYN traffic, detects potential port scans and unusually high SYN traffic, and generates structured JSON reports.

This project is an educational prototype for learning about packet analysis, intrusion detection, Python testing, and network security.

## Features

- Live TCP packet capture using Scapy
- Offline analysis of PCAP files
- TCP SYN packet inspection
- Port scan detection based on distinct destination ports
- SYN flood detection based on SYN packet counts
- Configurable thresholds and detection time windows
- Security alerts with source and destination IP addresses
- JSON reports containing packet counts and detected alerts
- Console and file-based logging
- Command-line interface
- Automated tests and input validation
- Capture error handling

## Technologies

- Python 3.10+
- Scapy
- pytest
- unittest

## Requirements

- Python 3.10 or newer
- Linux recommended for live packet capture
- Appropriate privileges for capturing network traffic

## Installation

Clone the repository and enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd python-network-ids
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project and its dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

## Usage

### List network interfaces

```bash
python -m network_ids --list-interfaces
```

### Start live monitoring

Choose a network interface available on your system:

```bash
sudo .venv/bin/python -m network_ids --interface eth0
```

Replace `eth0` with your actual interface name. Live capture may require elevated privileges.

Stop monitoring with `Ctrl+C`.

### Configure detection rules

Set the number of distinct destination ports required to trigger a port scan alert:

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

The default port scan threshold is 10 distinct destination ports. The default SYN threshold is 100 packets. The default detection window is 60 seconds.

### Analyze a PCAP file

Analyze a saved packet capture without starting live monitoring:

```bash
python -m network_ids \
  --pcap samples/demo_port_scan.pcap
```

### Generate a JSON report

Specify an output path for the analysis report:

```bash
python -m network_ids \
  --pcap samples/demo_port_scan.pcap \
  --report reports/demo_report.json
```

The report includes the number of packets analyzed, the number of alerts, and the details of each alert.

### Demonstrate both detection rules

The included sample capture contains three TCP SYN packets directed at three distinct destination ports. The following command configures both detection thresholds to three:

```bash
python -m network_ids \
  --pcap samples/demo_port_scan.pcap \
  --report reports/demo_both_rules_report.json \
  --threshold 3 \
  --syn-threshold 3
```

Inspect the resulting JSON report:

```bash
cat reports/demo_both_rules_report.json
```

The expected result is three analyzed packets and two alerts: `SYN_FLOOD` and `PORT_SCAN`.

These thresholds are deliberately low for demonstration purposes; they are not recommended production settings.

## Detection Rules

### PORT_SCAN

Tracks distinct TCP destination ports for each source and destination IP pair within the configured time window. An alert is generated when the number of distinct ports reaches the configured threshold.

### SYN_FLOOD

Tracks TCP SYN packets for each source and destination IP pair within the configured time window. An alert is generated when the SYN packet count reaches the configured threshold.

Both rules can trigger on the same packet observation. Each rule maintains its own alert state, allowing alerts to be generated independently.

## Logging

Events are logged to the console and, by default, to:

```text
logs/network_ids.log
```

The `logs/` directory and log files are excluded from version control.

## Running Tests

Activate the virtual environment, then run the full test suite:

```bash
python -m pytest -v
```

The tests cover detection rules, simultaneous alerts, packet processing, PCAP analysis, JSON reporting, command-line behavior, logging, and input validation.

## Current Limitations

- Detection focuses on TCP SYN traffic and simple behavioral thresholds.
- A SYN packet count alone does not prove that a SYN flood is occurring; alerts require further investigation.
- This is an educational prototype, not a replacement for a production-grade IDS.
- Live packet capture may require elevated privileges.
- Detection thresholds may need tuning for different network environments.

## Responsible Use

Only monitor networks and systems you own or are explicitly authorized to assess. Packet capture can expose sensitive network information.

## Project Status

Early development. Detection rules, reporting, and test coverage will continue to evolve.

## License

No license has been specified yet. Add a license before distributing the project for reuse.
