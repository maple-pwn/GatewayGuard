"""
Replay Sequence Detector for CAN bus replay attack detection.

Detects:
- Repeated subsequences (rolling hash)
- Counter rollback/stagnation
- Stale pattern reuse
- Sequence freshness violations
"""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import hashlib
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent


@dataclass
class SequenceState:
    """Track sequence history for replay detection."""

    msg_id: str
    seen_packets: int = 0
    recent_hashes: deque = field(default_factory=lambda: deque(maxlen=50))
    hash_last_seen: Dict[str, float] = field(default_factory=dict)
    window_last_index: Dict[str, int] = field(default_factory=dict)
    payload_history: deque = field(default_factory=lambda: deque(maxlen=20))
    payload_last_index: Dict[str, int] = field(default_factory=dict)
    counter_positions: List[int] = field(default_factory=list)
    counter_min: Dict[int, int] = field(default_factory=dict)
    counter_max: Dict[int, int] = field(default_factory=dict)
    counter_step: Dict[int, int] = field(default_factory=dict)
    last_counter_values: Dict[int, int] = field(default_factory=dict)
    payload_reuse_ratio: float = 0.0
    payload_reuse_p95_age: float = 0.0
    gap_median: float = 0.0
    window_reuse_ratio: float = 0.0
    window_reuse_p95_age: float = 0.0
    window_reuse_p95_gap: int = 0


class ReplaySequenceDetector:
    """Detect replay attacks via sequence analysis."""

    def __init__(
        self,
        window_size: int = 10,
        freshness_threshold: float = 5.0,
        subsequence_min_age: float = 0.25,
    ):
        self.window_size = window_size
        self.freshness_threshold = freshness_threshold  # seconds
        self.subsequence_min_age = subsequence_min_age
        self.states: Dict[str, SequenceState] = {}
        self.trained = False

    def fit(self, packets: List[UnifiedPacket]):
        """Learn normal sequence patterns."""
        if not packets:
            return

        # Group by ID
        id_packets = defaultdict(list)
        for p in packets:
            if p.payload_hex:
                id_packets[p.msg_id].append(p)

        # Detect counter positions for each ID
        for msg_id, pkts in id_packets.items():
            if len(pkts) < 10:
                continue

            state = SequenceState(msg_id=msg_id)
            state.payload_reuse_ratio, state.payload_reuse_p95_age = (
                self._learn_payload_reuse_profile(pkts)
            )
            state.gap_median = self._median_positive_gap(pkts)
            (
                state.window_reuse_ratio,
                state.window_reuse_p95_age,
                state.window_reuse_p95_gap,
            ) = self._learn_window_reuse_profile(pkts)
            candidate_positions = self._detect_counter_positions(pkts)
            for pos in candidate_positions:
                values = []
                for packet in pkts:
                    if not packet.payload_hex:
                        continue
                    bytes_list = [
                        int(packet.payload_hex[i : i + 2], 16)
                        for i in range(0, len(packet.payload_hex), 2)
                    ]
                    if pos < len(bytes_list):
                        values.append(bytes_list[pos])
                summary = self._summarize_counter_behavior(values)
                if not summary["is_counter"]:
                    continue

                state.counter_positions.append(pos)
                state.counter_min[pos] = int(summary["min"])
                state.counter_max[pos] = int(summary["max"])
                state.counter_step[pos] = int(summary["dominant_step"])
            self.states[msg_id] = state

        self.trained = True

    @staticmethod
    def _learn_payload_reuse_profile(packets: List[UnifiedPacket]) -> tuple[float, float]:
        if not packets:
            return 0.0, 0.0

        last_seen: Dict[str, float] = {}
        reuse_ages: List[float] = []
        reuse_count = 0
        total = 0

        for packet in packets:
            if not packet.payload_hex:
                continue
            total += 1
            payload_hash = hashlib.md5(packet.payload_hex.encode()).hexdigest()[:16]
            if payload_hash in last_seen:
                reuse_count += 1
                reuse_ages.append(packet.timestamp - last_seen[payload_hash])
            last_seen[payload_hash] = packet.timestamp

        if total <= 0:
            return 0.0, 0.0
        if not reuse_ages:
            return reuse_count / total, 0.0

        reuse_ages.sort()
        p95_idx = min(len(reuse_ages) - 1, int(len(reuse_ages) * 0.95))
        return reuse_count / total, float(reuse_ages[p95_idx])

    def _learn_window_reuse_profile(
        self, packets: List[UnifiedPacket]
    ) -> tuple[float, float, int]:
        if len(packets) < self.window_size:
            return 0.0, 0.0, 0

        payloads = [packet.payload_hex for packet in packets if packet.payload_hex]
        timestamps = [packet.timestamp for packet in packets if packet.payload_hex]
        if len(payloads) < self.window_size:
            return 0.0, 0.0, 0

        seen: Dict[str, tuple[int, float]] = {}
        reuse_ages: List[float] = []
        reuse_gaps: List[int] = []
        total_windows = len(payloads) - self.window_size + 1
        reuse_count = 0

        for idx in range(self.window_size - 1, len(payloads)):
            window_hash = hashlib.md5(
                "".join(payloads[idx - self.window_size + 1 : idx + 1]).encode()
            ).hexdigest()[:16]
            if window_hash in seen:
                reuse_count += 1
                prev_idx, prev_ts = seen[window_hash]
                reuse_ages.append(timestamps[idx] - prev_ts)
                reuse_gaps.append(idx - prev_idx)
            seen[window_hash] = (idx, timestamps[idx])

        if total_windows <= 0:
            return 0.0, 0.0, 0
        if not reuse_ages:
            return reuse_count / total_windows, 0.0, 0

        reuse_ages.sort()
        reuse_gaps.sort()
        p95_age_idx = min(len(reuse_ages) - 1, int(len(reuse_ages) * 0.95))
        p95_gap_idx = min(len(reuse_gaps) - 1, int(len(reuse_gaps) * 0.95))
        return (
            reuse_count / total_windows,
            float(reuse_ages[p95_age_idx]),
            int(reuse_gaps[p95_gap_idx]),
        )

    @staticmethod
    def _median_positive_gap(packets: List[UnifiedPacket]) -> float:
        if len(packets) < 2:
            return 0.0

        gaps = [
            packets[idx].timestamp - packets[idx - 1].timestamp
            for idx in range(1, len(packets))
            if packets[idx].timestamp > packets[idx - 1].timestamp
        ]
        if not gaps:
            return 0.0

        gaps.sort()
        return float(gaps[len(gaps) // 2])

    @staticmethod
    def _summarize_counter_behavior(values: List[int]) -> Dict[str, float | int | bool]:
        if len(values) < 10:
            return {"is_counter": False}

        lower = min(values)
        upper = max(values)
        span = max(upper - lower, 0)
        modulus = max(span + 1, 1)
        wrap_margin = max(2, min(16, int(span * 0.1))) if span > 0 else 2

        raw_steps = [values[i] - values[i - 1] for i in range(1, len(values))]
        negative_steps = [
            (values[i - 1], values[i]) for i in range(1, len(values)) if values[i] < values[i - 1]
        ]
        valid_wraps = sum(
            1
            for prev_val, curr_val in negative_steps
            if prev_val >= upper - wrap_margin and curr_val <= lower + wrap_margin
        )
        wrap_valid_ratio = (
            valid_wraps / len(negative_steps) if negative_steps else 1.0
        )

        positive_mod_steps = [
            step
            for step in (((values[i] - values[i - 1]) % modulus) for i in range(1, len(values)))
            if step > 0
        ]
        if not positive_mod_steps:
            return {"is_counter": False}

        step_counts = Counter(positive_mod_steps)
        dominant_step, dominant_count = step_counts.most_common(1)[0]
        dominant_ratio = dominant_count / len(positive_mod_steps)
        is_counter = (
            dominant_step <= 4
            and dominant_ratio >= 0.5
            and wrap_valid_ratio >= 0.8
        )
        return {
            "is_counter": is_counter,
            "min": lower,
            "max": upper,
            "dominant_step": dominant_step,
            "dominant_ratio": dominant_ratio,
            "wrap_valid_ratio": wrap_valid_ratio,
            "negative_steps": len(negative_steps),
            "raw_step_count": len(raw_steps),
        }

    def _detect_counter_positions(self, packets: List[UnifiedPacket]) -> List[int]:
        """Detect byte positions that behave like counters."""
        if len(packets) < 10:
            return []

        # Extract payload bytes
        byte_series = []
        for p in packets:
            if not p.payload_hex or len(p.payload_hex) < 2:
                continue
            bytes_list = [
                int(p.payload_hex[i : i + 2], 16)
                for i in range(0, len(p.payload_hex), 2)
            ]
            byte_series.append(bytes_list)

        if not byte_series:
            return []

        max_len = max(len(b) for b in byte_series)
        counter_positions = []

        # Check each byte position
        for pos in range(max_len):
            values = [b[pos] for b in byte_series if len(b) > pos]
            if len(values) < 10:
                continue

            # Check monotonicity
            increases = sum(
                1 for i in range(1, len(values)) if values[i] > values[i - 1]
            )
            decreases = sum(
                1 for i in range(1, len(values)) if values[i] < values[i - 1]
            )

            monotonic_ratio = max(increases, decreases) / (len(values) - 1)
            if monotonic_ratio > 0.7:  # 70% monotonic
                counter_positions.append(pos)

        return counter_positions[:3]  # Max 3 counter positions

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Detect replay attacks in packet sequence."""
        if not self.trained or not packets:
            return []

        alerts = []

        for p in packets:
            if not p.payload_hex:
                continue

            # Get or create state
            if p.msg_id not in self.states:
                self.states[p.msg_id] = SequenceState(msg_id=p.msg_id)

            state = self.states[p.msg_id]

            # Check subsequence repetition
            alert = self._check_subsequence_repeat(p, state)
            if alert:
                alerts.append(alert)

            # Check counter rollback
            if state.counter_positions:
                alert = self._check_counter_anomaly(p, state)
                if alert:
                    alerts.append(alert)

            alert = self._check_exact_payload_reuse(p, state)
            if alert:
                alerts.append(alert)

            # Check freshness
            alert = self._check_freshness(p, state)
            if alert:
                alerts.append(alert)

            self._update_state(p, state)

        return alerts

    def _check_subsequence_repeat(
        self, packet: UnifiedPacket, state: SequenceState
    ) -> Optional[AnomalyEvent]:
        """Check for repeated subsequences using rolling hash."""
        if state.counter_positions:
            return None

        if len(state.payload_history) < self.window_size - 1:
            return None

        window = list(state.payload_history)[-(self.window_size - 1) :] + [
            packet.payload_hex
        ]
        unique_payloads = len(set(window))
        dominant_ratio = max(window.count(payload) for payload in set(window)) / len(
            window
        )
        transitions = sum(1 for i in range(1, len(window)) if window[i] != window[i - 1])

        min_unique_payloads = 2 if self.window_size <= 3 else min(3, self.window_size)
        min_transitions = 1 if self.window_size <= 3 else max(2, self.window_size // 3)
        if (
            unique_payloads < min_unique_payloads
            or dominant_ratio > 0.7
            or transitions < min_transitions
        ):
            return None

        window_hash = hashlib.md5("".join(window).encode()).hexdigest()[:16]

        if window_hash in state.recent_hashes:
            last_seen = state.hash_last_seen.get(window_hash, 0)
            last_index = state.window_last_index.get(window_hash, 0)
            age = packet.timestamp - last_seen
            packet_gap = (state.seen_packets + 1) - last_index
            learned_gap = max(
                int(state.window_reuse_p95_gap * 1.25),
                self.window_size,
            )
            learned_age = max(
                self.subsequence_min_age,
                state.window_reuse_p95_age * 1.5
                if state.window_reuse_p95_age > 0
                else 0.0,
            )

            if (
                state.window_reuse_ratio >= 0.05
                and age <= learned_age
                and packet_gap <= learned_gap
            ):
                return None

            if packet_gap >= self.window_size and self.subsequence_min_age <= age < 1.0:
                return AnomalyEvent(
                    timestamp=packet.timestamp,
                    anomaly_type="replay_suspected",
                    protocol=packet.protocol,
                    source_node=packet.source,
                    target_node=packet.msg_id,
                    detection_method="replay_sequence",
                    confidence=0.85,
                    evidence=[
                        f"repeated_subsequence",
                        f"window_size={self.window_size}",
                        f"packet_gap={packet_gap}",
                        f"age_seconds={age:.3f}",
                        f"unique_payloads={unique_payloads}",
                        f"dominant_ratio={dominant_ratio:.2f}",
                    ],
                )

        return None

    def _check_counter_anomaly(
        self, packet: UnifiedPacket, state: SequenceState
    ) -> Optional[AnomalyEvent]:
        """Check for counter rollback or stagnation."""
        if not packet.payload_hex or len(packet.payload_hex) < 2:
            return None

        bytes_list = [
            int(packet.payload_hex[i : i + 2], 16)
            for i in range(0, len(packet.payload_hex), 2)
        ]

        for pos in state.counter_positions:
            if pos >= len(bytes_list):
                continue

            current_val = bytes_list[pos]

            if pos in state.last_counter_values:
                prev_val = state.last_counter_values[pos]
                counter_min = state.counter_min.get(pos, 0)
                counter_max = state.counter_max.get(pos, 255)
                wrap_margin = max(
                    2, min(16, int((counter_max - counter_min) * 0.1))
                )
                near_wrap = (
                    prev_val >= counter_max - wrap_margin
                    and current_val <= counter_min + wrap_margin
                )

                if (
                    current_val < prev_val
                    and not near_wrap
                    and (prev_val - current_val) > 10
                ):
                    return AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="replay_suspected",
                        protocol=packet.protocol,
                        source_node=packet.source,
                        target_node=packet.msg_id,
                        detection_method="replay_sequence",
                        confidence=0.80,
                        evidence=[
                            f"counter_rollback",
                            f"position={pos}",
                            f"prev={prev_val}",
                            f"current={current_val}",
                        ],
                    )

                if current_val == prev_val and len(state.payload_history) > 5:
                    recent_payloads = list(state.payload_history)[-5:] + [
                        packet.payload_hex
                    ]
                    recent_same = sum(
                        1
                        for p in list(state.payload_history)[-5:]
                        if p == packet.payload_hex
                    )
                    if recent_same >= 4 and len(set(recent_payloads)) >= 2:
                        return AnomalyEvent(
                            timestamp=packet.timestamp,
                            anomaly_type="replay_suspected",
                            protocol=packet.protocol,
                            source_node=packet.source,
                            target_node=packet.msg_id,
                            detection_method="replay_sequence",
                            confidence=0.70,
                            evidence=[
                                f"counter_stagnation",
                                f"position={pos}",
                                f"value={current_val}",
                            ],
                        )

            state.last_counter_values[pos] = current_val

        return None

    def _check_freshness(
        self, packet: UnifiedPacket, state: SequenceState
    ) -> Optional[AnomalyEvent]:
        """Check if payload pattern is stale."""
        payload_hash = hashlib.md5(packet.payload_hex.encode()).hexdigest()[:16]
        if state.payload_reuse_ratio >= 0.05 or state.payload_reuse_p95_age <= 0:
            return None

        if payload_hash in state.hash_last_seen:
            last_seen = state.hash_last_seen[payload_hash]
            age = packet.timestamp - last_seen
            adaptive_threshold = max(
                self.freshness_threshold * 6.0,
                state.payload_reuse_p95_age * 5.0,
            )

            if age > adaptive_threshold and len(state.payload_history) > 10:
                return AnomalyEvent(
                    timestamp=packet.timestamp,
                    anomaly_type="replay_suspected",
                    protocol=packet.protocol,
                    source_node=packet.source,
                    target_node=packet.msg_id,
                    detection_method="replay_sequence",
                    confidence=0.65,
                    evidence=[
                        f"stale_pattern_reuse",
                        f"age_seconds={age:.3f}",
                        f"threshold_seconds={adaptive_threshold:.3f}",
                    ],
                )

        return None

    def _check_exact_payload_reuse(
        self, packet: UnifiedPacket, state: SequenceState
    ) -> Optional[AnomalyEvent]:
        """Flag rapid exact-payload reuse on dynamic IDs."""
        if not packet.payload_hex or state.payload_reuse_ratio >= 0.02:
            return None
        if state.gap_median <= 0 or state.seen_packets < 4:
            return None

        payload_hash = hashlib.md5(packet.payload_hex.encode()).hexdigest()[:16]
        if payload_hash not in state.hash_last_seen:
            return None

        last_seen = state.hash_last_seen[payload_hash]
        last_index = state.payload_last_index.get(payload_hash, 0)
        packet_gap = (state.seen_packets + 1) - last_index
        age = packet.timestamp - last_seen

        if packet_gap <= 0:
            return None

        min_reuse_age = max(state.gap_median * 0.1, 0.001)
        if age < min_reuse_age:
            return None

        rapid_age_threshold = max(0.004, min(state.gap_median * 0.75, 0.05))
        if age > rapid_age_threshold and packet_gap > 2:
            return None

        recent_payloads = list(state.payload_history)[-6:]
        if recent_payloads and recent_payloads[-1] == packet.payload_hex:
            if len(set(recent_payloads)) <= 1:
                return None

        confidence = 0.68
        if age <= rapid_age_threshold:
            confidence += 0.10
        if packet_gap <= 2:
            confidence += 0.08
        confidence += min(0.12, max(0.02 - state.payload_reuse_ratio, 0.0) * 4.0)

        return AnomalyEvent(
            timestamp=packet.timestamp,
            anomaly_type="replay_suspected",
            protocol=packet.protocol,
            source_node=packet.source,
            target_node=packet.msg_id,
            detection_method="replay_sequence",
            confidence=round(min(confidence, 0.92), 3),
            evidence=[
                "exact_payload_reuse",
                f"age_seconds={age:.3f}",
                f"packet_gap={packet_gap}",
                f"baseline_gap_seconds={state.gap_median:.3f}",
                f"baseline_reuse_ratio={state.payload_reuse_ratio:.4f}",
            ],
        )

    def _update_state(self, packet: UnifiedPacket, state: SequenceState):
        """Update sequence state with new packet."""
        if not packet.payload_hex:
            return

        state.payload_history.append(packet.payload_hex)
        state.seen_packets += 1

        if len(state.payload_history) >= self.window_size:
            window = list(state.payload_history)[-self.window_size :]
            window_hash = hashlib.md5("".join(window).encode()).hexdigest()[:16]
            state.recent_hashes.append(window_hash)
            state.hash_last_seen[window_hash] = packet.timestamp
            state.window_last_index[window_hash] = state.seen_packets

        payload_hash = hashlib.md5(packet.payload_hex.encode()).hexdigest()[:16]
        state.hash_last_seen[payload_hash] = packet.timestamp
        state.payload_last_index[payload_hash] = state.seen_packets
