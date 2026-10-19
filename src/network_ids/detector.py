
from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic


@dataclass(frozen=True)
class Alert:
    """Represents a detected network security event."""

    source_ip: str
    destination_ip: str
    rule: str
    details: str


class NetworkIDS:
    """Detect basic TCP port scans from observed connections."""

    def __init__(
        self,
        port_threshold: int = 10,
        window_seconds: float = 60.0,
    ) -> None:
        if port_threshold < 2:
            raise ValueError("port_threshold must be at least 2")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self._observations = defaultdict(deque)

    def observe(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        timestamp: float | None = None,
    ) -> Alert | None:
        """Record a connection attempt and detect possible port scans."""
        if not 1 <= destination_port <= 65535:
            raise ValueError("destination_port must be between 1 and 65535")

        now = monotonic() if timestamp is None else timestamp
        key = (source_ip, destination_ip)
        observations = self._observations[key]

        cutoff = now - self.window_seconds

        while observations and observations[0][0] < cutoff:
            observations.popleft()

        # Keep each destination port only once within the time window.
        if not any(port == destination_port for _, port in observations):
            observations.append((now, destination_port))

        unique_ports = {port for _, port in observations}

        if len(unique_ports) >= self.port_threshold:
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
