# Python Network Intrusion Detection System

A modular, Python-based Network Intrusion Detection System (NIDS) that monitors TCP traffic and detects potential port-scanning activity using configurable detection rules.

## Features

- Live TCP packet capture using Scapy
- TCP SYN packet inspection
- Port scan detection based on distinct destination ports
- Configurable detection threshold and time window
- Security alerts with source and destination IP addresses
- Console and file-based logging
- Command-line interface
- Automated unit tests
- Input validation and capture error handling

## Technologies

- Python 3.10+
- Scapy
- `unittest`

## Requirements

- Python 3.10 or newer
- Linux is recommended for packet capture
- Appropriate privileges to capture network traffic

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

### List available network interfaces

```bash
python -m network_ids --list-interfaces
```

### Start monitoring

Choose an interface available on your system:

```bash
sudo .venv/bin/python -m network_ids --interface eth0
```

Replace `eth0` with the interface you want to monitor.

### Configure detection

Set the number of distinct destination ports required to trigger an alert:

```bash
sudo .venv/bin/python -m network_ids --interface eth0 --threshold 5
```

Configure the detection window in seconds:

```bash
sudo .venv/bin/python -m network_ids --interface eth0 --threshold 5 --window 30
```

The default threshold is 10 distinct destination ports within a 60-second window.

### Stop monitoring

Press `Ctrl+C` to stop packet capture.

## Logging

Security events are logged to the console and, by default, to:

```text
logs/network_ids.log
```

The `logs/` directory and log files are excluded from version control.

## Running Tests

Run the automated test suite from the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover packet processing, port scan detection, input validation, logging, and capture error handling.

## Current Limitations

- Detection currently focuses on TCP SYN traffic and potential port scans.
- This project is an educational prototype, not a replacement for a production-grade IDS.
- Packet capture may require elevated privileges.
- PCAP file analysis and network connection statistics are not yet implemented.

## Responsible Use

Only monitor networks and systems you own or are explicitly authorized to assess. Packet capture may expose sensitive network information.

## Project Status

Early development. Features, detection rules, and test coverage will evolve over time.

## License

No license has been specified yet. Add a license before distributing the project for reuse.
