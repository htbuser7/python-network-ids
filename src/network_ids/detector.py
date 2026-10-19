
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
    """Detect basic TCP port scans in a sliding time window."""

    def __init__(
        self,
        port_threshold: int = 10,
        window_seconds: float = 60.0,
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
            raise ValueError("window_seconds must be a finite positive number")

        self.port_threshold = port_threshold
        self.window_seconds = float(window_seconds)

        self._observations = defaultdict(deque)
        self._last_timestamps = {}
        self._alert_active = set()

    def observe(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        timestamp: float | None = None,
    ) -> Alert | None:
        """Record a connection and alert when unique ports reach the threshold."""
        if (
            isinstance(destination_port, bool)
            or not isinstance(destination_port, int)
            or not 1 <= destination_port <= 65535
        ):
            raise ValueError("destination_port must be an integer from 1 to 65535")

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
            raise ValueError("timestamps must be non-decreasing per IP pair")

        self._last_timestamps[key] = now
        observations = self._observations[key]
        cutoff = now - self.window_seconds

        # Expire observations outside the sliding window.
        while observations and observations[0][0] < cutoff:
            observations.popleft()

        unique_ports = {port for _, port in observations}

        # Rearm detection after the count falls below the threshold.
        if len(unique_ports) < self.port_threshold:
            self._alert_active.discard(key)

        # Record each destination port only once per window.
        if destination_port not in unique_ports:
            observations.append((now, destination_port))
            unique_ports.add(destination_port)

        # Emit one alert when the threshold is first crossed.
        if (
            len(unique_ports) >= self.port_threshold
            and key not in self._alert_active
        ):
            self._alert_active.add(key)
            return Alert(
                source_ip=source_ip,
                destination_ip=destination_ip,
                rule="PORT_SCAN",
                details=(
                    f"{len(unique_ports)} distinct destination ports "
                    f"observed within {self.window_seconds:g} seconds"
                ),
            )

        return None
