"""GEAR state anomaly detector for CAN bus."""

from typing import List
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent


class GearDetector:
    """Detect invalid gear states."""

    VALID_GEARS = {"P", "R", "N", "D", "1", "2", "3", "4", "5", "6"}

    def __init__(self, gear_can_id: str = "0x130"):
        self.gear_can_id = gear_can_id

    def _decode_gear(self, payload_hex: str) -> str:
        """Decode gear from payload byte 0."""
        if not payload_hex or len(payload_hex) < 2:
            return "UNKNOWN"
        try:
            gear_byte = int(payload_hex[0:2], 16)
            gear_map = {
                0: "P",
                1: "R",
                2: "N",
                3: "D",
                4: "1",
                5: "2",
                6: "3",
                7: "4",
                8: "5",
                9: "6",
            }
            return gear_map.get(gear_byte, "INVALID")
        except (ValueError, IndexError):
            return "UNKNOWN"

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Detect gear anomalies."""
        anomalies = []
        for packet in packets:
            if packet.msg_id != self.gear_can_id or not packet.payload_hex:
                continue

            gear = self._decode_gear(packet.payload_hex)

            if gear not in self.VALID_GEARS:
                anomalies.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="invalid_gear_state",
                        detection_method="gear_state_validation",
                        severity="high",
                        description=f"Invalid gear state: {gear}",
                        confidence=0.90,
                        evidence=[f"gear={gear}", f"valid_gears={','.join(self.VALID_GEARS)}"],
                    )
                )

        return anomalies
