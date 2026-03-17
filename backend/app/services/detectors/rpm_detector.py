"""RPM anomaly detector for CAN bus."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from app.models.anomaly import AnomalyEvent
from app.models.packet import UnifiedPacket
from app.services.detectors.powertrain_signal_utils import (
    extract_gear_state,
    extract_rpm_flag,
    extract_rpm_value,
    infer_gear_state_model,
    infer_rpm_decode_model,
)


@dataclass
class RPMProfile:
    sample_count: int = 0
    min_rpm: float = 0.0
    max_rpm: float = 0.0
    median_rpm: float = 0.0
    std_rpm: float = 0.0
    p01_rpm: float = 0.0
    p99_rpm: float = 0.0
    rate_limit: float = 0.0
    median_rate: float = 0.0
    gear_rpm_ranges: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    gear_sample_counts: Dict[str, int] = field(default_factory=dict)


class RPMDetector:
    """Detect RPM anomalies including semantic tampering on legal CAN frames."""

    def __init__(
        self,
        rpm_can_id: str = "0x0C0",
        gear_can_id: str = "0x130",
        max_rpm: float = 8000.0,
        spike_threshold: float = 2000.0,
        carry_state: bool = False,
        context_window_s: float = 0.15,
    ):
        self.rpm_can_id = rpm_can_id
        self.gear_can_id = gear_can_id
        self.max_rpm = max_rpm
        self.spike_threshold = spike_threshold
        self.carry_state = carry_state
        self.context_window_s = context_window_s
        self.profile_margin_rpm = 350.0
        self.profile: Optional[RPMProfile] = None
        self.is_trained = False
        self.last_rpm: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.gear_state_model = infer_gear_state_model([])
        self.rpm_decode_model = infer_rpm_decode_model([])

    def reset(self) -> None:
        """Reset cross-batch state."""
        self.last_rpm = None
        self.last_ts = None

    def fit(self, packets: List[UnifiedPacket]) -> None:
        """Learn RPM value/rate baselines and gear-conditioned ranges."""
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
        self.gear_state_model = infer_gear_state_model(gear_payloads)
        self.rpm_decode_model = infer_rpm_decode_model(rpm_payloads)
        rpm_values: List[float] = []
        rpm_rates: List[float] = []
        gear_rpm_samples: Dict[str, List[float]] = defaultdict(list)

        latest_gear: Optional[str] = None
        latest_gear_ts: Optional[float] = None
        prev_rpm: Optional[float] = None
        prev_ts: Optional[float] = None

        for packet in sorted_packets:
            if packet.msg_id == self.gear_can_id and packet.payload_hex:
                gear = extract_gear_state(packet.payload_hex, self.gear_state_model)
                if gear is not None:
                    latest_gear = gear
                    latest_gear_ts = packet.timestamp
                continue

            if packet.msg_id != self.rpm_can_id or not packet.payload_hex:
                continue

            rpm = extract_rpm_value(packet.payload_hex, self.rpm_decode_model)
            if rpm is None:
                continue

            rpm_values.append(rpm)

            if prev_rpm is not None and prev_ts is not None:
                delta_t = max(packet.timestamp - prev_ts, 0.0)
                if delta_t > 0:
                    rpm_rates.append(abs(rpm - prev_rpm) / delta_t)

            if (
                latest_gear is not None
                and latest_gear_ts is not None
                and packet.timestamp - latest_gear_ts <= self.context_window_s
            ):
                gear_rpm_samples[latest_gear].append(rpm)

            prev_rpm = rpm
            prev_ts = packet.timestamp

        if len(rpm_values) < 6:
            self.profile = None
            self.is_trained = False
            return

        rpm_np = np.asarray(rpm_values, dtype=float)
        profile = RPMProfile(
            sample_count=len(rpm_values),
            min_rpm=float(np.min(rpm_np)),
            max_rpm=float(np.max(rpm_np)),
            median_rpm=float(np.median(rpm_np)),
            std_rpm=float(np.std(rpm_np)),
            p01_rpm=float(np.percentile(rpm_np, 1)),
            p99_rpm=float(np.percentile(rpm_np, 99)),
        )

        if rpm_rates:
            rate_np = np.asarray(rpm_rates, dtype=float)
            profile.median_rate = float(np.median(rate_np))
            profile.rate_limit = float(
                np.percentile(rate_np, 99)
                + max(2000.0, float(np.std(rate_np)) * 3.0)
            )

        for gear, samples in gear_rpm_samples.items():
            if len(samples) < 5:
                continue
            sample_np = np.asarray(samples, dtype=float)
            margin = max(180.0, float(np.std(sample_np)) * 2.5)
            low = max(0.0, float(np.percentile(sample_np, 1)) - margin)
            high = float(np.percentile(sample_np, 99)) + margin
            profile.gear_rpm_ranges[gear] = (low, high)
            profile.gear_sample_counts[gear] = len(samples)

        self.profile = profile
        self.is_trained = True

    def _decode_rpm(self, payload_hex: str) -> float:
        rpm = extract_rpm_value(payload_hex, self.rpm_decode_model)
        return rpm if rpm is not None else 0.0

    def _build_mode_alert(self, packet: UnifiedPacket) -> Optional[AnomalyEvent]:
        flag_value = extract_rpm_flag(packet.payload_hex, self.rpm_decode_model)
        if (
            flag_value is None
            or flag_value in self.rpm_decode_model.observed_flag_values
        ):
            return None

        return AnomalyEvent(
            timestamp=packet.timestamp,
            anomaly_type="rpm_mode_anomaly",
            detection_method="rpm_semantic_profile",
            severity="high",
            confidence=0.9,
            protocol=packet.protocol,
            source_node=packet.source,
            target_node=packet.msg_id,
            description="RPM signal uses unseen mode bits",
            evidence=[
                {
                    "rule": "rpm_mode_profile",
                    "flag_value": f"0x{flag_value:02X}",
                    "seen_flags": [f"0x{value:02X}" for value in self.rpm_decode_model.observed_flag_values],
                }
            ],
        )

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """Detect RPM anomalies."""
        anomalies = []
        sorted_packets = sorted(packets, key=lambda packet: packet.timestamp)

        prev_rpm = self.last_rpm if self.carry_state else None
        prev_ts = self.last_ts if self.carry_state else None
        latest_gear: Optional[str] = None
        latest_gear_ts: Optional[float] = None

        for packet in sorted_packets:
            if packet.msg_id == self.gear_can_id and packet.payload_hex:
                gear = extract_gear_state(packet.payload_hex, self.gear_state_model)
                if gear is not None:
                    latest_gear = gear
                    latest_gear_ts = packet.timestamp
                continue

            if packet.msg_id != self.rpm_can_id or not packet.payload_hex:
                continue

            mode_alert = self._build_mode_alert(packet)
            if mode_alert:
                anomalies.append(mode_alert)

            rpm = self._decode_rpm(packet.payload_hex)

            if rpm >= self.max_rpm:
                anomalies.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="rpm_out_of_range",
                        detection_method="rpm_range_check",
                        severity="high",
                        confidence=0.95,
                        protocol=packet.protocol,
                        source_node=packet.source,
                        target_node=packet.msg_id,
                        description=f"RPM {rpm:.1f} exceeds max {self.max_rpm}",
                        evidence=[f"rpm={rpm:.1f}", f"max={self.max_rpm}"],
                    )
                )

            if prev_rpm is not None:
                delta = abs(rpm - prev_rpm)
                if delta > self.spike_threshold:
                    anomalies.append(
                        AnomalyEvent(
                            timestamp=packet.timestamp,
                            anomaly_type="rpm_spike",
                            detection_method="rpm_spike_detection",
                            severity="medium",
                            confidence=0.85,
                            protocol=packet.protocol,
                            source_node=packet.source,
                            target_node=packet.msg_id,
                            description=f"RPM spike: {delta:.1f} RPM change",
                            evidence=[
                                f"delta={delta:.1f}",
                                f"threshold={self.spike_threshold}",
                            ],
                        )
                    )

            current_gear: Optional[str] = None
            if (
                latest_gear is not None
                and latest_gear_ts is not None
                and packet.timestamp - latest_gear_ts <= self.context_window_s
            ):
                current_gear = latest_gear

            semantic_alert = self._build_semantic_alert(
                packet=packet,
                rpm=rpm,
                gear=current_gear,
                prev_rpm=prev_rpm,
                prev_ts=prev_ts,
            )
            if semantic_alert:
                anomalies.append(semantic_alert)

            prev_rpm = rpm
            prev_ts = packet.timestamp

        if self.carry_state:
            self.last_rpm = prev_rpm
            self.last_ts = prev_ts
        else:
            self.reset()

        return anomalies

    def _build_semantic_alert(
        self,
        packet: UnifiedPacket,
        rpm: float,
        gear: Optional[str],
        prev_rpm: Optional[float],
        prev_ts: Optional[float],
    ) -> Optional[AnomalyEvent]:
        if not self.is_trained or not self.profile:
            return None

        reasons: List[str] = []
        evidence = []
        primary_type = "rpm_profile_anomaly"
        severity = "medium"
        confidence = 0.0

        profile = self.profile
        range_margin = max(self.profile_margin_rpm, profile.std_rpm * 3.0)
        low = max(0.0, min(profile.p01_rpm, profile.min_rpm) - range_margin)
        high = min(self.max_rpm, max(profile.p99_rpm, profile.max_rpm) + range_margin)

        if rpm < low or rpm > high:
            deviation = low - rpm if rpm < low else rpm - high
            reasons.append(f"outside learned RPM range [{low:.0f}, {high:.0f}]")
            evidence.append(
                {
                    "rule": "rpm_profile_range",
                    "rpm": round(rpm, 2),
                    "profile_low": round(low, 2),
                    "profile_high": round(high, 2),
                    "deviation": round(deviation, 2),
                }
            )
            confidence = max(confidence, min(0.92, 0.6 + deviation / 1800.0))

        if (
            prev_rpm is not None
            and prev_ts is not None
            and packet.timestamp > prev_ts
            and profile.rate_limit > 0
        ):
            delta_t = packet.timestamp - prev_ts
            rate = abs(rpm - prev_rpm) / max(delta_t, 1e-6)
            if rate > profile.rate_limit:
                reasons.append(f"RPM rate {rate:.0f}/s exceeds learned limit")
                evidence.append(
                    {
                        "rule": "rpm_rate_limit",
                        "rate": round(rate, 2),
                        "rate_limit": round(profile.rate_limit, 2),
                        "delta_t": round(delta_t, 4),
                    }
                )
                primary_type = "rpm_rate_anomaly"
                confidence = max(
                    confidence,
                    min(0.95, 0.64 + (rate / max(profile.rate_limit, 1.0) - 1.0) * 0.18),
                )

        if gear and gear in profile.gear_rpm_ranges:
            low_gear, high_gear = profile.gear_rpm_ranges[gear]
            if rpm < low_gear or rpm > high_gear:
                reasons.append(
                    f"RPM {rpm:.1f} inconsistent with gear {gear} profile [{low_gear:.0f}, {high_gear:.0f}]"
                )
                evidence.append(
                    {
                        "rule": "rpm_gear_consistency",
                        "gear": gear,
                        "rpm": round(rpm, 2),
                        "gear_profile_low": round(low_gear, 2),
                        "gear_profile_high": round(high_gear, 2),
                    }
                )
                primary_type = "rpm_gear_mismatch"
                severity = "high"
                confidence = max(confidence, 0.82)

        if reasons:
            return AnomalyEvent(
                timestamp=packet.timestamp,
                anomaly_type=primary_type,
                detection_method="rpm_semantic_profile",
                severity=severity,
                confidence=round(min(max(confidence, 0.62), 0.99), 3),
                protocol=packet.protocol,
                source_node=packet.source,
                target_node=packet.msg_id,
                description=f"RPM semantic anomaly: {', '.join(reasons)}",
                evidence=evidence,
            )

        return None
