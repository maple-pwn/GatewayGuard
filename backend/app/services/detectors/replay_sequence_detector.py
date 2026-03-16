"""
Replay Sequence Detector for CAN bus replay attack detection.

Detects:
- Repeated subsequences (rolling hash)
- Counter rollback/stagnation
- Stale pattern reuse
- Sequence freshness violations
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import hashlib
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent


@dataclass
class SequenceState:
    """Track sequence history for replay detection."""

    msg_id: str
    recent_hashes: deque = field(default_factory=lambda: deque(maxlen=50))
    hash_last_seen: Dict[str, float] = field(default_factory=dict)
    payload_history: deque = field(default_factory=lambda: deque(maxlen=20))
    counter_positions: List[int] = field(default_factory=list)
    last_counter_values: Dict[int, int] = field(default_factory=dict)


class ReplaySequenceDetector:
    """Detect replay attacks via sequence analysis."""

    def __init__(self, window_size: int = 10, freshness_threshold: float = 5.0):
        self.window_size = window_size
        self.freshness_threshold = freshness_threshold  # seconds
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
            counter_pos = self._detect_counter_positions(pkts)
            state.counter_positions = counter_pos
            self.states[msg_id] = state

        self.trained = True

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
        if len(state.payload_history) < self.window_size:
            return None

        window = list(state.payload_history)[-self.window_size :]
        window_hash = hashlib.md5("".join(window).encode()).hexdigest()[:16]

        if window_hash in state.recent_hashes:
            last_seen = state.hash_last_seen.get(window_hash, 0)
            age = packet.timestamp - last_seen

            if age < 1.0:
                return AnomalyEvent(
                    timestamp=packet.timestamp,
                    anomaly_type="replay_suspected",
                    detection_method="replay_sequence",
                    confidence=0.85,
                    evidence=[
                        f"repeated_subsequence",
                        f"window_size={self.window_size}",
                        f"age_seconds={age:.3f}",
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

                if current_val < prev_val and (prev_val - current_val) > 10:
                    return AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="replay_suspected",
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
                    recent_same = sum(
                        1
                        for p in list(state.payload_history)[-5:]
                        if p == packet.payload_hex
                    )
                    if recent_same >= 4:
                        return AnomalyEvent(
                            timestamp=packet.timestamp,
                            anomaly_type="replay_suspected",
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

        if payload_hash in state.hash_last_seen:
            last_seen = state.hash_last_seen[payload_hash]
            age = packet.timestamp - last_seen

            if age > self.freshness_threshold and len(state.payload_history) > 10:
                return AnomalyEvent(
                    timestamp=packet.timestamp,
                    anomaly_type="replay_suspected",
                    detection_method="replay_sequence",
                    confidence=0.65,
                    evidence=[f"stale_pattern_reuse", f"age_seconds={age:.3f}"],
                )

        return None

    def _update_state(self, packet: UnifiedPacket, state: SequenceState):
        """Update sequence state with new packet."""
        if not packet.payload_hex:
            return

        state.payload_history.append(packet.payload_hex)

        if len(state.payload_history) >= self.window_size:
            window = list(state.payload_history)[-self.window_size :]
            window_hash = hashlib.md5("".join(window).encode()).hexdigest()[:16]
            state.recent_hashes.append(window_hash)
            state.hash_last_seen[window_hash] = packet.timestamp

        payload_hash = hashlib.md5(packet.payload_hex.encode()).hexdigest()[:16]
        state.hash_last_seen[payload_hash] = packet.timestamp
