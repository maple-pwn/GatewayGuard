from typing import List
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.profiles.can_profile import ProfileManager, _is_can_family


class PayloadProfileDetector:
    def __init__(self, profile_manager: ProfileManager):
        self.profile_mgr = profile_manager

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        for p in packets:
            if not _is_can_family(p) or not p.payload_hex:
                continue
            prof = self.profile_mgr.get_profile(p.msg_id)
            if not prof:
                continue

            byte_list = [
                p.payload_hex[i : i + 2].lower()
                for i in range(0, len(p.payload_hex), 2)
            ]
            unique_bytes = set(byte_list)

            if len(unique_bytes) == 1 and len(p.payload_hex) >= 8:
                byte_val = list(unique_bytes)[0]

                if prof.payload_constant_ratio >= 0.2:
                    continue
                if byte_val in ("00", "ff") and prof.payload_zero_ff_ratio >= 0.15:
                    continue

                severity = "high" if byte_val in ("ff", "00") else "low"
                confidence = 0.7 if byte_val in ("ff", "00") else 0.5

                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="payload_anomaly",
                        severity=severity,
                        confidence=confidence,
                        protocol=p.protocol,
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=f"Payload all 0x{byte_val} for {p.msg_id}, baseline constant={prof.payload_constant_ratio:.2f}",
                        detection_method="payload_profile",
                    )
                )
        return alerts
