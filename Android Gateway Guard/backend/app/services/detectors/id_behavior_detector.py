from collections import Counter, defaultdict, deque
from typing import List
import numpy as np
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
        alerts.extend(self._detect_unknown_id_flood(packets))
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

    def _detect_unknown_id_flood(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        profile = self.profile_mgr.profile
        can_packets = [p for p in packets if _is_can_family(p)]
        if not profile or len(can_packets) < 64:
            return []

        baseline_gap = profile.time_span / max(profile.total_packets, 1)
        recent_ids: deque[str] = deque(maxlen=256)
        recent_counts: Counter[str] = Counter()
        states = defaultdict(
            lambda: {
                "count": 0,
                "last_ts": None,
                "gaps": deque(maxlen=16),
                "payloads": deque(maxlen=8),
            }
        )
        alerts: List[AnomalyEvent] = []

        for index, packet in enumerate(can_packets, start=1):
            if len(recent_ids) == recent_ids.maxlen:
                evicted = recent_ids.popleft()
                recent_counts[evicted] -= 1
                if recent_counts[evicted] <= 0:
                    recent_counts.pop(evicted, None)
            recent_ids.append(packet.msg_id)
            recent_counts[packet.msg_id] += 1

            if self.profile_mgr.is_known_id(packet.msg_id, self.policy):
                continue

            state = states[packet.msg_id]
            state["count"] += 1
            if state["last_ts"] is not None:
                gap = max(packet.timestamp - state["last_ts"], 0.0)
                if gap > 0:
                    state["gaps"].append(gap)
            state["last_ts"] = packet.timestamp
            state["payloads"].append(packet.payload_hex or "")

            if state["count"] < 64 or len(state["payloads"]) < 8:
                continue

            recent_share = recent_counts[packet.msg_id] / max(len(recent_ids), 1)
            global_share = state["count"] / max(index, 1)
            payloads = list(state["payloads"])
            stable_payload = len(set(payloads)) == 1
            constant_zero_ff = bool(payloads[0]) and len(
                {
                    payloads[0][i : i + 2].lower()
                    for i in range(0, len(payloads[0]), 2)
                }
            ) == 1 and payloads[0][:2].lower() in {"00", "ff"}
            median_gap = (
                float(np.median(list(state["gaps"]))) if state["gaps"] else 0.0
            )

            if not stable_payload:
                continue
            if recent_share < 0.15 or global_share < 0.05:
                continue
            if median_gap > 0 and baseline_gap > 0 and median_gap > baseline_gap * 1.5:
                continue

            confidence = min(
                0.99,
                0.72
                + min(recent_share, 0.5) * 0.35
                + min(global_share, 0.5) * 0.20,
            )
            payload_label = "zero/ff constant payload" if constant_zero_ff else "static payload"
            alerts.append(
                AnomalyEvent(
                    timestamp=packet.timestamp,
                    anomaly_type="unknown_id_flood",
                    severity="critical",
                    confidence=round(confidence, 3),
                    protocol=packet.protocol,
                    source_node=packet.source,
                    target_node=packet.msg_id,
                    description=(
                        f"Unknown-ID flood on {packet.msg_id}: share {recent_share:.2f}, "
                        f"global {global_share:.2f}, {payload_label}"
                    ),
                    detection_method="id_behavior_unknown_flood",
                    evidence=[
                        {
                            "rule": "unknown_id_flood",
                            "recent_share": round(recent_share, 4),
                            "global_share": round(global_share, 4),
                            "median_gap": round(median_gap, 6),
                            "baseline_gap": round(baseline_gap, 6),
                            "sample_count": int(state["count"]),
                            "payload_hex": payloads[0],
                            "constant_zero_ff": constant_zero_ff,
                        }
                    ],
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
