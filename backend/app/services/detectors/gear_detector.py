"""GEAR state anomaly detector for CAN bus."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

from app.models.anomaly import AnomalyEvent
from app.models.packet import UnifiedPacket
from app.services.detectors.powertrain_signal_utils import (
    extract_gear_state,
    extract_rpm_value,
    gear_order,
    infer_gear_state_model,
    infer_rpm_decode_model,
)


@dataclass
class GearProfile:
    sample_count: int = 0
    seen_gears: Set[str] = field(default_factory=set)
    allowed_transitions: Set[Tuple[str, str]] = field(default_factory=set)
    gear_rpm_ranges: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    seen_components: Dict[int, Set[str]] = field(default_factory=dict)
    state_positions: Tuple[int, ...] = field(default_factory=tuple)
    fast_shift_gap: float = 0.05
    canonical_mode: bool = True


class GearDetector:
    """Detect invalid and semantically inconsistent gear states."""

    def __init__(
        self,
        gear_can_id: str = "0x130",
        rpm_can_id: str = "0x0C0",
        context_window_s: float = 0.15,
    ):
        self.gear_can_id = gear_can_id
        self.rpm_can_id = rpm_can_id
        self.context_window_s = context_window_s
        self.profile: Optional[GearProfile] = None
        self.is_trained = False
        self.state_model = infer_gear_state_model([])
        self.rpm_decode_model = infer_rpm_decode_model([])

    @staticmethod
    def _is_hex_byte(value: str) -> bool:
        return len(value) == 2 and all(ch in "0123456789ABCDEF" for ch in value.upper())

    def _canonicalize_symbolic_state(self, gear: str) -> str:
        if (
            not self.profile
            or self.profile.canonical_mode
            or not self.profile.state_positions
            or "|" not in gear
        ):
            return gear

        parts = gear.split("|")
        normalized = []
        for index, component in zip(self.profile.state_positions, parts):
            seen = sorted(self.profile.seen_components.get(index, set()))
            if component in seen or not seen or not self._is_hex_byte(component):
                normalized.append(component)
                continue

            if not all(self._is_hex_byte(value) for value in seen):
                normalized.append(component)
                continue

            seen_numeric = [int(value, 16) for value in seen]
            span = max(seen_numeric) - min(seen_numeric)
            tolerance = 2 if len(seen_numeric) >= 2 and span <= 8 else 0
            value = int(component, 16)
            nearest = min(seen_numeric, key=lambda candidate: abs(candidate - value))
            if abs(nearest - value) <= tolerance:
                normalized.append(f"{nearest:02X}")
            else:
                normalized.append(component)

        return "|".join(normalized)

    def fit(self, packets: List[UnifiedPacket]) -> None:
        """Learn observed gear states, transition graph, and RPM context."""
        sorted_packets = sorted(packets, key=lambda packet: packet.timestamp)
        gear_payloads = [
            packet.payload_hex
            for packet in sorted_packets
            if packet.msg_id == self.gear_can_id and packet.payload_hex
        ]
        rpm_payloads = [
            packet.payload_hex
            for packet in sorted_packets
            if packet.msg_id == self.rpm_can_id and packet.payload_hex
        ]
        self.state_model = infer_gear_state_model(gear_payloads)
        self.rpm_decode_model = infer_rpm_decode_model(rpm_payloads)
        gear_sequence: List[Tuple[float, str]] = []
        gear_rpm_samples: Dict[str, List[float]] = defaultdict(list)
        shift_gaps: List[float] = []

        latest_rpm: Optional[float] = None
        latest_rpm_ts: Optional[float] = None
        prev_gear: Optional[str] = None
        prev_ts: Optional[float] = None

        for packet in sorted_packets:
            if packet.msg_id == self.rpm_can_id and packet.payload_hex:
                rpm = extract_rpm_value(packet.payload_hex, self.rpm_decode_model)
                if rpm is not None:
                    latest_rpm = rpm
                    latest_rpm_ts = packet.timestamp
                continue

            if packet.msg_id != self.gear_can_id or not packet.payload_hex:
                continue

            gear = extract_gear_state(packet.payload_hex, self.state_model)
            if gear is None:
                continue

            gear_sequence.append((packet.timestamp, gear))

            if (
                latest_rpm is not None
                and latest_rpm_ts is not None
                and packet.timestamp - latest_rpm_ts <= self.context_window_s
            ):
                gear_rpm_samples[gear].append(latest_rpm)

            if prev_gear is not None:
                if gear != prev_gear and prev_ts is not None:
                    delta_t = max(packet.timestamp - prev_ts, 0.0)
                    if delta_t > 0:
                        shift_gaps.append(delta_t)

            prev_gear = gear
            prev_ts = packet.timestamp

        if len(gear_sequence) < 6:
            self.profile = None
            self.is_trained = False
            return

        seen_gears = {gear for _, gear in gear_sequence}
        allowed_transitions = {(gear, gear) for gear in seen_gears}
        for i in range(1, len(gear_sequence)):
            allowed_transitions.add((gear_sequence[i - 1][1], gear_sequence[i][1]))

        ordered_gears = sorted(seen_gears, key=gear_order)
        for i in range(1, len(ordered_gears)):
            prev = ordered_gears[i - 1]
            curr = ordered_gears[i]
            if gear_order(prev) >= 0 and gear_order(curr) - gear_order(prev) == 1:
                allowed_transitions.add((prev, curr))
                allowed_transitions.add((curr, prev))

        profile = GearProfile(
            sample_count=len(gear_sequence),
            seen_gears=seen_gears,
            allowed_transitions=allowed_transitions,
            state_positions=self.state_model.positions,
            canonical_mode=self.state_model.mode == "canonical",
        )
        if self.state_model.mode == "symbolic":
            component_map: Dict[int, Set[str]] = defaultdict(set)
            for gear in seen_gears:
                for index, component in zip(self.state_model.positions, gear.split("|")):
                    component_map[index].add(component)
            profile.seen_components = dict(component_map)

        if shift_gaps:
            profile.fast_shift_gap = max(
                0.005, float(np.percentile(np.asarray(shift_gaps, dtype=float), 10)) * 0.5
            )

        for gear, samples in gear_rpm_samples.items():
            if len(samples) < 4:
                continue
            sample_np = np.asarray(samples, dtype=float)
            margin = max(150.0, float(np.std(sample_np)) * 2.5)
            low = max(0.0, float(np.percentile(sample_np, 1)) - margin)
            high = float(np.percentile(sample_np, 99)) + margin
            profile.gear_rpm_ranges[gear] = (low, high)

        self.profile = profile
        self.is_trained = True

    def _decode_gear(self, payload_hex: str) -> str:
        return extract_gear_state(payload_hex, self.state_model) or "INVALID"

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Detect gear anomalies."""
        anomalies = []
        sorted_packets = sorted(packets, key=lambda packet: packet.timestamp)

        latest_rpm: Optional[float] = None
        latest_rpm_ts: Optional[float] = None
        prev_gear: Optional[str] = None
        prev_ts: Optional[float] = None

        for packet in sorted_packets:
            if packet.msg_id == self.rpm_can_id and packet.payload_hex:
                rpm = extract_rpm_value(packet.payload_hex, self.rpm_decode_model)
                if rpm is not None:
                    latest_rpm = rpm
                    latest_rpm_ts = packet.timestamp
                continue

            if packet.msg_id != self.gear_can_id or not packet.payload_hex:
                continue

            gear = self._canonicalize_symbolic_state(self._decode_gear(packet.payload_hex))

            if self.state_model.mode == "canonical" and gear == "INVALID":
                anomalies.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="invalid_gear_state",
                        detection_method="gear_state_validation",
                        severity="high",
                        confidence=0.90,
                        protocol=packet.protocol,
                        source_node=packet.source,
                        target_node=packet.msg_id,
                        description=f"Invalid gear state: {gear}",
                        evidence=[
                            f"gear={gear}",
                            "valid_gears=D,N,P,R,1,2,3,4,5,6",
                        ],
                    )
                )
                continue

            current_rpm: Optional[float] = None
            if (
                latest_rpm is not None
                and latest_rpm_ts is not None
                and packet.timestamp - latest_rpm_ts <= self.context_window_s
            ):
                current_rpm = latest_rpm

            semantic_alert = self._build_semantic_alert(
                packet=packet,
                gear=gear,
                rpm=current_rpm,
                prev_gear=prev_gear,
                prev_ts=prev_ts,
            )
            if semantic_alert:
                anomalies.append(semantic_alert)

            prev_gear = gear
            prev_ts = packet.timestamp

        return anomalies

    def _build_semantic_alert(
        self,
        packet: UnifiedPacket,
        gear: str,
        rpm: Optional[float],
        prev_gear: Optional[str],
        prev_ts: Optional[float],
    ) -> Optional[AnomalyEvent]:
        if not self.is_trained or not self.profile:
            return None

        reasons: List[str] = []
        evidence = []
        primary_type = "gear_state_out_of_profile"
        severity = "medium"
        confidence = 0.0
        profile = self.profile

        if gear not in profile.seen_gears and len(profile.seen_gears) >= 4:
            if profile.canonical_mode:
                reasons.append(f"gear {gear} never observed during training")
                evidence.append(
                    {
                        "rule": "gear_seen_profile",
                        "gear": gear,
                        "seen_gears": sorted(profile.seen_gears),
                    }
                )
                confidence = max(confidence, 0.74)
            else:
                unseen_components = []
                for index, component in zip(profile.state_positions, gear.split("|")):
                    if component not in profile.seen_components.get(index, set()):
                        unseen_components.append({"byte": index, "value": component})
                if unseen_components:
                    reasons.append(f"state {gear} contains unseen symbolic components")
                    evidence.append(
                        {
                            "rule": "gear_symbolic_components",
                            "gear": gear,
                            "unseen_components": unseen_components,
                        }
                    )
                    confidence = max(confidence, 0.78)

        if prev_gear is not None and gear != prev_gear:
            transition = (prev_gear, gear)
            jump_size = abs(gear_order(gear) - gear_order(prev_gear))
            is_unexpected = transition not in profile.allowed_transitions and (
                jump_size >= 2 or not profile.canonical_mode
            )
            if is_unexpected:
                if profile.canonical_mode:
                    reasons.append(f"unexpected gear jump {prev_gear}->{gear}")
                else:
                    reasons.append(f"unexpected gear-state transition {prev_gear}->{gear}")
                evidence.append(
                    {
                        "rule": "gear_transition_profile",
                        "previous_gear": prev_gear,
                        "current_gear": gear,
                        "jump_size": jump_size,
                    }
                )
                primary_type = "gear_shift_anomaly"
                severity = "high" if jump_size >= 4 or not profile.canonical_mode else "medium"
                confidence = max(
                    confidence,
                    0.82 if not profile.canonical_mode else min(0.94, 0.64 + jump_size * 0.06),
                )

            if prev_ts is not None:
                delta_t = max(packet.timestamp - prev_ts, 0.0)
                min_jump = 1 if profile.canonical_mode else 0
                if delta_t > 0 and delta_t < profile.fast_shift_gap and jump_size >= min_jump:
                    reasons.append(
                        f"gear changed in {delta_t:.3f}s, faster than learned shift gap"
                    )
                    evidence.append(
                        {
                            "rule": "gear_shift_gap",
                            "delta_t": round(delta_t, 4),
                            "fast_shift_gap": round(profile.fast_shift_gap, 4),
                        }
                    )
                    primary_type = "gear_shift_anomaly"
                    confidence = max(confidence, 0.78)

        if rpm is not None and gear in profile.gear_rpm_ranges:
            low, high = profile.gear_rpm_ranges[gear]
            if rpm < low or rpm > high:
                subject = "gear" if profile.canonical_mode else "state"
                reasons.append(
                    f"{subject} {gear} inconsistent with RPM profile [{low:.0f}, {high:.0f}]"
                )
                evidence.append(
                    {
                        "rule": "gear_rpm_consistency",
                        "gear": gear,
                        "rpm": round(rpm, 2),
                        "gear_profile_low": round(low, 2),
                        "gear_profile_high": round(high, 2),
                    }
                )
                primary_type = "gear_rpm_mismatch"
                severity = "high"
                confidence = max(confidence, 0.82)

        if reasons:
            return AnomalyEvent(
                timestamp=packet.timestamp,
                anomaly_type=primary_type,
                detection_method="gear_semantic_profile",
                severity=severity,
                confidence=round(min(max(confidence, 0.62), 0.99), 3),
                protocol=packet.protocol,
                source_node=packet.source,
                target_node=packet.msg_id,
                description=f"Gear semantic anomaly: {', '.join(reasons)}",
                evidence=evidence,
            )

        return None
