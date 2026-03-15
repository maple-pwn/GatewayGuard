from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Optional
import numpy as np
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.profiles.can_profile import ProfileManager, _is_can_family


def _payload_bytes(payload_hex: str) -> List[int]:
    if not payload_hex:
        return []
    return [int(payload_hex[i : i + 2], 16) for i in range(0, len(payload_hex), 2)]


def _first_word(payload_bytes: List[int]) -> int:
    if len(payload_bytes) < 2:
        return 0
    return payload_bytes[0] << 8 | payload_bytes[1]


def _payload_change_ratio(current: List[int], previous: List[int]) -> float:
    if not current or not previous:
        return 0.0
    compare_len = min(len(current), len(previous))
    if compare_len <= 0:
        return 0.0
    changed = sum(1 for i in range(compare_len) if current[i] != previous[i])
    return changed / compare_len


@dataclass
class TemporalState:
    prev_ts: Optional[float] = None
    prev_payload: Optional[List[int]] = None
    prev_word: Optional[int] = None
    gaps: deque = field(default_factory=lambda: deque(maxlen=8))
    payload_changes: deque = field(default_factory=lambda: deque(maxlen=8))
    value_deltas: deque = field(default_factory=lambda: deque(maxlen=8))
    repeat_flags: deque = field(default_factory=lambda: deque(maxlen=8))


class TimingProfileDetector:
    def __init__(
        self,
        profile_manager: ProfileManager,
        window_size: int = 8,
        burst_z_threshold: float = 4.0,
        gap_z_threshold: float = 3.0,
    ):
        self.profile_mgr = profile_manager
        self.window_size = window_size
        self.burst_z = burst_z_threshold
        self.gap_z = gap_z_threshold
        self.load_factor_threshold = 2.0
        self.mad_epsilon = 1e-6

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        states: defaultdict[str, TemporalState] = defaultdict(TemporalState)
        can_packets: List[UnifiedPacket] = []

        for packet in packets:
            if not _is_can_family(packet):
                continue
            can_packets.append(packet)
            prof = self.profile_mgr.get_profile(packet.msg_id)
            if not prof:
                continue

            state = states[packet.msg_id]
            payload = _payload_bytes(packet.payload_hex)
            word = _first_word(payload)

            if (
                state.prev_ts is not None
                and state.prev_payload is not None
                and state.prev_word is not None
            ):
                gap = max(packet.timestamp - state.prev_ts, 0.0)
                state.gaps.append(gap)
                state.payload_changes.append(
                    _payload_change_ratio(payload, state.prev_payload)
                )
                state.value_deltas.append(abs(word - state.prev_word) / 65535.0)
                state.repeat_flags.append(1.0 if payload == state.prev_payload else 0.0)

            state.prev_ts = packet.timestamp
            state.prev_payload = payload
            state.prev_word = word

            if len(state.gaps) < self.window_size:
                continue

            gap_median = float(np.median(list(state.gaps)))
            repeat_ratio = float(np.mean(list(state.repeat_flags)))
            payload_change_mean = float(np.mean(list(state.payload_changes)))
            value_delta_mean = float(np.mean(list(state.value_deltas)))
            gaps_np = np.asarray(list(state.gaps), dtype=float)
            mad = (
                float(np.median(np.abs(gaps_np - gap_median)))
                if len(gaps_np) > 0
                else 0.0
            )

            reasons = []
            evidence = []
            score = 0.0

            baseline_gap = max(prof.gap_median, 1e-6)
            if gap_median > 0:
                gap_ratio = baseline_gap / gap_median
                if gap_ratio >= self.burst_z and gap_median <= max(prof.gap_p10, 1e-6):
                    reasons.append(f"burst {gap_ratio:.2f}x")
                    evidence.append(
                        {
                            "rule": "burst_ratio",
                            "gap_ratio": round(gap_ratio, 3),
                            "gap_median": round(gap_median, 6),
                            "baseline_gap": round(baseline_gap, 6),
                        }
                    )
                    score = max(score, gap_ratio / 6.0)

                baseline_rate = 1.0 / baseline_gap
                current_rate = 1.0 / max(gap_median, 1e-6)
                load_factor = current_rate / baseline_rate
                if load_factor >= self.load_factor_threshold:
                    reasons.append(f"load {load_factor:.2f}x")
                    evidence.append(
                        {
                            "rule": "bus_load_factor",
                            "load_factor": round(load_factor, 3),
                            "current_rate": round(current_rate, 3),
                            "baseline_rate": round(baseline_rate, 3),
                        }
                    )
                    score = max(score, load_factor / 4.0)

                if mad > self.mad_epsilon:
                    robust_z = abs(gap_median - baseline_gap) / (1.4826 * mad)
                    if gap_median < baseline_gap and robust_z >= self.gap_z:
                        reasons.append(f"mad_z {robust_z:.2f}")
                        evidence.append(
                            {
                                "rule": "robust_gap_mad",
                                "robust_z": round(robust_z, 3),
                                "mad": round(mad, 6),
                            }
                        )
                        score = max(score, robust_z / 6.0)

            if repeat_ratio >= 0.85 and repeat_ratio - prof.repeat_ratio >= 0.45:
                reasons.append(f"repeat {repeat_ratio:.2f}")
                evidence.append(
                    {
                        "rule": "repeat_ratio",
                        "current_repeat": round(repeat_ratio, 3),
                        "baseline_repeat": round(prof.repeat_ratio, 3),
                    }
                )
                score = max(score, repeat_ratio)

            if (
                prof.payload_change_mean > 0
                and payload_change_mean < prof.payload_change_mean * 0.35
            ):
                reasons.append("payload_stall")
                evidence.append(
                    {
                        "rule": "payload_change_drop",
                        "current_payload_change": round(payload_change_mean, 4),
                        "baseline_payload_change": round(prof.payload_change_mean, 4),
                    }
                )
                score = max(score, 0.7)

            if (
                prof.value_delta_mean > 0
                and value_delta_mean < prof.value_delta_mean * 0.3
            ):
                reasons.append("value_delta_drop")
                evidence.append(
                    {
                        "rule": "value_delta_drop",
                        "current_value_delta": round(value_delta_mean, 4),
                        "baseline_value_delta": round(prof.value_delta_mean, 4),
                    }
                )
                score = max(score, 0.65)

            if reasons:
                alerts.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="temporal_anomaly",
                        severity="high" if score >= 0.8 else "medium",
                        confidence=round(min(max(score, 0.6), 1.0), 3),
                        protocol=packet.protocol,
                        source_node=packet.source,
                        target_node=packet.msg_id,
                        description=f"Temporal anomaly for {packet.msg_id}: {', '.join(reasons)}",
                        detection_method="timing_profile",
                        vehicle_profile=self.profile_mgr.profile.vehicle_name
                        if self.profile_mgr.profile
                        else None,
                        evidence=evidence,
                    )
                )

        alerts.extend(self._detect_bus_load_anomaly(can_packets))
        return alerts

    def _detect_bus_load_anomaly(
        self, can_packets: List[UnifiedPacket]
    ) -> List[AnomalyEvent]:
        profile = self.profile_mgr.profile
        if not profile or profile.time_span <= 0 or profile.total_packets <= 1:
            return []
        if len(can_packets) < max(self.window_size * 2, 32):
            return []

        window_span = max(can_packets[-1].timestamp - can_packets[0].timestamp, 1e-6)
        current_rate = len(can_packets) / window_span
        baseline_rate = profile.total_packets / max(profile.time_span, 1e-6)

        id_counts = Counter(p.msg_id for p in can_packets)
        dominant_id, dominant_count = id_counts.most_common(1)[0]
        dominant_share = dominant_count / len(can_packets)
        baseline_top_count = max(
            (id_prof.packet_count for id_prof in profile.id_profiles.values()),
            default=0,
        )
        baseline_dominant_share = baseline_top_count / max(profile.total_packets, 1)

        current_unique_ratio = len(id_counts) / len(can_packets)
        baseline_unique_ratio = len(profile.id_profiles) / max(profile.total_packets, 1)

        gaps = [
            max(can_packets[i].timestamp - can_packets[i - 1].timestamp, 0.0)
            for i in range(1, len(can_packets))
        ]
        positive_gaps = [g for g in gaps if g > 0]
        gap_median = float(np.median(positive_gaps)) if positive_gaps else 0.0
        baseline_global_gap = profile.time_span / max(profile.total_packets, 1)

        reasons = []
        evidence = []
        score = 0.0

        rate_factor = current_rate / max(baseline_rate, 1e-6)
        if rate_factor >= 2.5:
            reasons.append(f"global_rate {rate_factor:.2f}x")
            evidence.append(
                {
                    "rule": "global_bus_rate",
                    "current_rate": round(current_rate, 3),
                    "baseline_rate": round(baseline_rate, 3),
                    "rate_factor": round(rate_factor, 3),
                }
            )
            score = max(score, min(rate_factor / 4.0, 1.0))

        if (
            dominant_share >= 0.6
            and dominant_share - baseline_dominant_share >= 0.2
            and rate_factor >= 1.5
        ):
            reasons.append(f"id_share {dominant_id}:{dominant_share:.2f}")
            evidence.append(
                {
                    "rule": "dominant_id_share",
                    "dominant_id": dominant_id,
                    "current_share": round(dominant_share, 3),
                    "baseline_share": round(baseline_dominant_share, 3),
                }
            )
            score = max(score, min(dominant_share + 0.2, 1.0))

        if (
            baseline_unique_ratio > 0
            and current_unique_ratio >= baseline_unique_ratio * 2.0
        ):
            reasons.append("id_diversity_spike")
            evidence.append(
                {
                    "rule": "unique_id_ratio",
                    "current_unique_ratio": round(current_unique_ratio, 4),
                    "baseline_unique_ratio": round(baseline_unique_ratio, 4),
                }
            )
            score = max(score, 0.7)

        if gap_median > 0 and baseline_global_gap > 0:
            compression = baseline_global_gap / gap_median
            if compression >= 2.0:
                reasons.append(f"gap_compression {compression:.2f}x")
                evidence.append(
                    {
                        "rule": "global_gap_compression",
                        "current_gap_median": round(gap_median, 6),
                        "baseline_gap_median": round(baseline_global_gap, 6),
                        "compression_factor": round(compression, 3),
                    }
                )
                score = max(score, min(compression / 4.0, 1.0))

        if not reasons:
            return []

        return [
            AnomalyEvent(
                timestamp=can_packets[-1].timestamp,
                anomaly_type="bus_load_anomaly",
                severity="critical" if score >= 0.9 else "high",
                confidence=round(min(max(score, 0.72), 1.0), 3),
                protocol="CAN",
                source_node="CAN_BUS",
                target_node=dominant_id,
                description="Bus-level traffic anomaly: " + ", ".join(reasons),
                detection_method="timing_profile_bus",
                vehicle_profile=profile.vehicle_name,
                evidence=evidence,
            )
        ]
