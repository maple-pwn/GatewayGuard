from collections import Counter
from typing import List
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent


class BusLoadDetector:
    """Bus-level DoS/Flooding detection"""

    def __init__(
        self,
        rate_threshold: float = 5000.0,
        concentration_threshold: float = 0.7,
        burst_threshold: float = 3.0,
    ):
        self.rate_threshold = rate_threshold
        self.concentration_threshold = concentration_threshold
        self.burst_threshold = burst_threshold

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        if len(packets) < 10:
            return []

        alerts = []
        alerts.extend(self._detect_high_rate(packets))
        alerts.extend(self._detect_id_concentration(packets))
        alerts.extend(self._detect_burstiness(packets))
        return alerts

    def _detect_high_rate(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        if len(packets) < 2:
            return []

        time_span = packets[-1].timestamp - packets[0].timestamp
        if time_span <= 0:
            return []

        rate = len(packets) / time_span
        if rate > self.rate_threshold:
            return [
                AnomalyEvent(
                    timestamp=packets[-1].timestamp,
                    anomaly_type="bus_flooding",
                    severity="high",
                    confidence=min(0.9, 0.6 + (rate / self.rate_threshold - 1) * 0.3),
                    protocol="CAN",
                    source_node="bus",
                    target_node="all",
                    description=f"High bus load: {rate:.0f} msg/s (threshold: {self.rate_threshold})",
                    detection_method="bus_load_rate",
                )
            ]
        return []

    def _detect_id_concentration(
        self, packets: List[UnifiedPacket]
    ) -> List[AnomalyEvent]:
        id_counts = Counter(p.msg_id for p in packets if p.msg_id)
        if not id_counts:
            return []

        top_id, top_count = id_counts.most_common(1)[0]
        concentration = top_count / len(packets)

        if concentration > self.concentration_threshold:
            return [
                AnomalyEvent(
                    timestamp=packets[-1].timestamp,
                    anomaly_type="id_flooding",
                    severity="high",
                    confidence=min(
                        0.95, 0.7 + (concentration - self.concentration_threshold) * 0.5
                    ),
                    protocol="CAN",
                    source_node="bus",
                    target_node=top_id,
                    description=f"ID flooding: {top_id} ({concentration:.1%} of traffic)",
                    detection_method="bus_load_concentration",
                )
            ]
        return []

    def _detect_burstiness(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        if len(packets) < 10:
            return []

        gaps = [
            packets[i + 1].timestamp - packets[i].timestamp
            for i in range(len(packets) - 1)
        ]
        if not gaps:
            return []

        mean_gap = sum(gaps) / len(gaps)
        variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        std_gap = variance**0.5

        if std_gap == 0:
            return []

        cv = std_gap / mean_gap
        if cv > self.burst_threshold:
            return [
                AnomalyEvent(
                    timestamp=packets[-1].timestamp,
                    anomaly_type="burst_traffic",
                    severity="medium",
                    confidence=min(0.85, 0.5 + (cv / self.burst_threshold - 1) * 0.35),
                    protocol="CAN",
                    source_node="bus",
                    target_node="all",
                    description=f"Bursty traffic pattern (CV: {cv:.2f})",
                    detection_method="bus_load_burst",
                )
            ]
        return []
