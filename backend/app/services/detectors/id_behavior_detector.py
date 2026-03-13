from collections import Counter, defaultdict
from typing import List
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.profiles.can_profile import (
    ProfileManager,
    _is_can_family,
    _median_gap,
)


class IDBehaviorDetector:
    def __init__(
        self, profile_manager: ProfileManager, unknown_id_policy: str = "strict_profile"
    ):
        self.profile_mgr = profile_manager
        self.policy = unknown_id_policy

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        alerts.extend(self._detect_unknown_ids(packets))
        alerts.extend(self._detect_dlc_anomaly(packets))
        alerts.extend(self._detect_burst_frequency(packets))
        return alerts

    def _detect_unknown_ids(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        seen = set()
        for p in packets:
            if not _is_can_family(p) or p.msg_id in seen:
                continue
            if not self.profile_mgr.is_known_id(p.msg_id, self.policy):
                seen.add(p.msg_id)
                severity = "high" if self.policy == "strict_profile" else "medium"
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="unknown_can_id",
                        severity=severity,
                        confidence=0.8 if self.policy == "strict_profile" else 0.6,
                        protocol=p.protocol,
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=f"Unknown CAN ID: {p.msg_id}",
                        detection_method="id_behavior_unknown",
                    )
                )
        return alerts

    def _detect_dlc_anomaly(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        for p in packets:
            if not _is_can_family(p):
                continue
            prof = self.profile_mgr.get_profile(p.msg_id)
            if not prof or not prof.common_dlc:
                continue
            dlc = len(p.payload_hex) // 2 if p.payload_hex else 0
            if dlc not in prof.common_dlc:
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="dlc_anomaly",
                        severity="medium",
                        confidence=0.7,
                        protocol=p.protocol,
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=f"Unexpected DLC {dlc} for {p.msg_id}, expected {prof.common_dlc}",
                        detection_method="id_behavior_dlc",
                    )
                )
        return alerts

    def _detect_burst_frequency(
        self, packets: List[UnifiedPacket]
    ) -> List[AnomalyEvent]:
        alerts = []
        can_packets = [p for p in packets if _is_can_family(p)]
        if len(can_packets) < 2:
            return alerts

        time_span = can_packets[-1].timestamp - can_packets[0].timestamp
        if time_span <= 0:
            return alerts

        id_counts = Counter(p.msg_id for p in can_packets)
        id_timestamps = defaultdict(list)
        for p in can_packets:
            id_timestamps[p.msg_id].append(p.timestamp)

        for msg_id, count in id_counts.items():
            prof = self.profile_mgr.get_profile(msg_id)
            if not prof or prof.frequency <= 0:
                continue

            current_freq = count / time_span
            current_gap = _median_gap(id_timestamps[msg_id])

            if prof.gap_median > 0 and current_gap > 0:
                burst_ratio = prof.gap_median / current_gap
                rate_ratio = current_freq / prof.frequency

                if burst_ratio >= 4.0 and rate_ratio >= 2.0 and count >= 20:
                    severity = "critical" if burst_ratio >= 6.0 else "high"
                    alerts.append(
                        AnomalyEvent(
                            timestamp=can_packets[-1].timestamp,
                            anomaly_type="frequency_anomaly",
                            severity=severity,
                            confidence=min(burst_ratio / 8.0, 1.0),
                            protocol="CAN",
                            source_node=msg_id,
                            description=f"Burst detected for {msg_id}: gap {current_gap:.6f}s vs baseline {prof.gap_median:.6f}s, burst {burst_ratio:.2f}x",
                            detection_method="id_behavior_burst",
                        )
                    )
        return alerts
