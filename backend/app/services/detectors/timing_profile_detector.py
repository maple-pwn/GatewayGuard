from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List
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
    prev_ts: float | None = None
    prev_payload: List[int] | None = None
    prev_word: int | None = None
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

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        states: defaultdict[str, TemporalState] = defaultdict(TemporalState)

        for packet in packets:
            if not _is_can_family(packet):
                continue
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

            reasons = []
            score = 0.0

            baseline_gap = max(prof.gap_median, 1e-6)
            if gap_median > 0:
                gap_ratio = baseline_gap / gap_median
                if gap_ratio >= self.burst_z and gap_median <= max(prof.gap_p10, 1e-6):
                    reasons.append(f"burst {gap_ratio:.2f}x")
                    score = max(score, gap_ratio / 6.0)

            if repeat_ratio >= 0.85 and repeat_ratio - prof.repeat_ratio >= 0.45:
                reasons.append(f"repeat {repeat_ratio:.2f}")
                score = max(score, repeat_ratio)

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
                    )
                )

        return alerts
