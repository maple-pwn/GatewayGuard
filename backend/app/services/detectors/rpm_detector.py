"""RPM anomaly detector for CAN bus."""

from typing import List
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent


class RPMDetector:
    """Detect RPM anomalies (out-of-range, sudden spikes)."""

    def __init__(
        self,
        rpm_can_id: str = "0x0C0",
        max_rpm: float = 8000.0,
        spike_threshold: float = 2000.0,
    ):
        self.rpm_can_id = rpm_can_id
        self.max_rpm = max_rpm
        self.spike_threshold = spike_threshold
        self.last_rpm = None

    def _decode_rpm(self, payload_hex: str) -> float:
        """Decode RPM from payload: (b0 << 8 | b1) * 0.25"""
        if not payload_hex or len(payload_hex) < 4:
            return 0.0
        try:
            b0 = int(payload_hex[0:2], 16)
            b1 = int(payload_hex[2:4], 16)
            return ((b0 << 8) | b1) * 0.25
        except (ValueError, IndexError):
            return 0.0

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Detect RPM anomalies."""
        anomalies = []
        for packet in packets:
            if packet.msg_id != self.rpm_can_id or not packet.payload_hex:
                continue

            rpm = self._decode_rpm(packet.payload_hex)

            # Out-of-range check
            if rpm > self.max_rpm:
                anomalies.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="rpm_out_of_range",
                        severity="high",
                        description=f"RPM {rpm:.1f} exceeds max {self.max_rpm}",
                        confidence=0.95,
                    )
                )

            # Spike detection
            if self.last_rpm is not None:
                delta = abs(rpm - self.last_rpm)
                if delta > self.spike_threshold:
                    anomalies.append(
                        AnomalyEvent(
                            timestamp=packet.timestamp,
                            anomaly_type="rpm_spike",
                            severity="medium",
                            description=f"RPM spike: {delta:.1f} RPM change",
                            confidence=0.85,
                        )
                    )

            self.last_rpm = rpm
        return anomalies
