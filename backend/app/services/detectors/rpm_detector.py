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
        carry_state: bool = False,
    ):
        self.rpm_can_id = rpm_can_id
        self.max_rpm = max_rpm
        self.spike_threshold = spike_threshold
        self.carry_state = carry_state
        self.last_rpm = None

    def reset(self) -> None:
        """Reset cross-batch state."""
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
        prev_rpm = self.last_rpm if self.carry_state else None
        for packet in packets:
            if packet.msg_id != self.rpm_can_id or not packet.payload_hex:
                continue

            rpm = self._decode_rpm(packet.payload_hex)

            # Out-of-range check
            if rpm >= self.max_rpm:
                anomalies.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="rpm_out_of_range",
                        detection_method="rpm_range_check",
                        severity="high",
                        description=f"RPM {rpm:.1f} exceeds max {self.max_rpm}",
                        confidence=0.95,
                        evidence=[f"rpm={rpm:.1f}", f"max={self.max_rpm}"],
                    )
                )

            # Spike detection
            if prev_rpm is not None:
                delta = abs(rpm - prev_rpm)
                if delta > self.spike_threshold:
                    anomalies.append(
                        AnomalyEvent(
                            timestamp=packet.timestamp,
                            anomaly_type="rpm_spike",
                            detection_method="rpm_spike_detection",
                            severity="medium",
                            description=f"RPM spike: {delta:.1f} RPM change",
                            confidence=0.85,
                            evidence=[f"delta={delta:.1f}", f"threshold={self.spike_threshold}"],
                        )
                    )

            prev_rpm = rpm

        if self.carry_state:
            self.last_rpm = prev_rpm
        else:
            self.last_rpm = None
        return anomalies
