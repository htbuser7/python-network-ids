
"""Detect basic network threats using TCP packet observations."""

import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from math import isfinite
from time import monotonic


@dataclass(frozen=True)
class Alert:
    """Represent a detected network security event."""

    source_ip: str
    destination_ip: str
    rule: str
    details: str


class NetworkIDS:
    """Detect TCP port scans and unusually high SYN traffic."""

    def __init__(
        self,
        port_threshold: int = 10,
        window_seconds: float = 60.0,
        logger: logging.Logger | None = None,
        syn_threshold: int = 100,
    ) -> None:
        if (
            isinstance(port_threshold, bool)
            or not isinstance(port_threshold, int)
            or port_threshold < 2
        ):
            raise ValueError("port_threshold must be an integer >= 2")

        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not isfinite(window_seconds)
            or window_seconds <= 0
        ):
            raise ValueError(
                "window_seconds must be a finite positive number"
            )

        if (
            isinstance(syn_threshold, bool)
            or not isinstance(syn_threshold, int)
            or syn_threshold < 2
        ):
            raise ValueError("syn_threshold must be an integer >= 2")

        self.port_threshold = port_threshold
        self.window_seconds = float(window_seconds)
        self.syn_threshold = syn_threshold
        self.logger = logger or logging.getLogger("network_ids")

        self._observations = defaultdict(deque)
        self._last_timestamps = {}
        self._alert_active = set()

        self._syn_observations = defaultdict(deque)
        self._syn_alert_active = set()

    def observe(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        timestamp: float | None = None,
    ) -> list[Alert]:
        """Record a TCP SYN observation and return every new alert."""
        if (
            isinstance(destination_port, bool)
            or not isinstance(destination_port, int)
            or not 1 <= destination_port <= 65535
        ):
            raise ValueError(
                "destination_port must be an integer from 1 to 65535"
            )

        now = monotonic() if timestamp is None else timestamp

        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not isfinite(now)
        ):
            raise ValueError("timestamp must be a finite number")

        key = (source_ip, destination_ip)
        last_timestamp = self._last_timestamps.get(key)

        if last_timestamp is not None and now < last_timestamp:
            raise ValueError(
                "timestamps must be non-decreasing per IP pair"
            )

        self._last_timestamps[key] = now
        cutoff = now - self.window_seconds
        alerts = []

        # Track SYN observations for the SYN_FLOOD rule.
        syn_observations = self._syn_observations[key]
        while syn_observations and syn_observations[0] < cutoff:
            syn_observations.popleft()

        syn_observations.append(now)

        if len(syn_observations) < self.syn_threshold:
            self._syn_alert_active.discard(key)

        if (
            len(syn_observations) >= self.syn_threshold
            and key not in self._syn_alert_active
        ):
            self._syn_alert_active.add(key)

            alert = Alert(
                source_ip=source_ip,
                destination_ip=destination_ip,
                rule="SYN_FLOOD",
                details=(
                    f"{len(syn_observations)} TCP SYN packets observed "
                    f"within {self.window_seconds:g} seconds"
                ),
            )
            alerts.append(alert)

            self.logger.warning(
                "Possible SYN flood detected: source=%s destination=%s "
                "syn_packets=%d window_seconds=%g",
                alert.source_ip,
                alert.destination_ip,
                len(syn_observations),
                self.window_seconds,
            )

        # Track unique destination ports for the PORT_SCAN rule.
        observations = self._observations[key]
        while observations and observations[0][0] < cutoff:
            observations.popleft()

        unique_ports = {port for _, port in observations}

        if len(unique_ports) < self.port_threshold:
            self._alert_active.discard(key)

        if destination_port not in unique_ports:
            observations.append((now, destination_port))
            unique_ports.add(destination_port)

        if (
            len(unique_ports) >= self.port_threshold
            and key not in self._alert_active
        ):
            self._alert_active.add(key)

            alert = Alert(
                source_ip=source_ip,
                destination_ip=destination_ip,
                rule="PORT_SCAN",
                details=(
                    f"{len(unique_ports)} distinct destination ports "
                    f"observed within {self.window_seconds:g} seconds"
                ),
            )
            alerts.append(alert)

            self.logger.warning(
                "Possible port scan detected: source=%s destination=%s "
                "distinct_ports=%d window_seconds=%g",
                alert.source_ip,
                alert.destination_ip,
                len(unique_ports),
                self.window_seconds,
            )

        return alerts
