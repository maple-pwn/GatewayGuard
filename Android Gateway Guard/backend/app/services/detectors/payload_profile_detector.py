from typing import List, Optional, Set
from collections import defaultdict
import numpy as np
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.profiles.can_profile import ProfileManager, _is_can_family


class PayloadProfileDetector:
    def __init__(
        self,
        profile_manager: ProfileManager,
        ignored_msg_ids: Optional[Set[str]] = None,
    ):
        self.profile_mgr = profile_manager
        self.ignored_msg_ids = set(ignored_msg_ids or ())

    @staticmethod
    def _profile_margin(profile) -> int:
        if profile.repeat_ratio >= 0.9 and profile.payload_change_mean <= 0.02:
            return 2
        if profile.repeat_ratio >= 0.75 and profile.payload_change_mean <= 0.08:
            return 1
        if (
            profile.payload_unique_ratio_mean >= 0.95
            and profile.repeat_ratio <= 0.05
            and profile.packet_count >= 128
        ):
            return 1
        return 0

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        for p in packets:
            if not _is_can_family(p) or not p.payload_hex:
                continue
            if p.msg_id in self.ignored_msg_ids:
                continue
            prof = self.profile_mgr.get_profile(p.msg_id)
            if not prof:
                continue

            byte_list = [
                p.payload_hex[i : i + 2].lower()
                for i in range(0, len(p.payload_hex), 2)
            ]
            int_bytes = [int(b, 16) for b in byte_list]
            unique_bytes = set(byte_list)

            reasons = []
            evidence = []
            compare_len = min(
                len(int_bytes), len(prof.byte_min) if prof.byte_min else 0
            )
            strong_signal_count = 0
            repeat_heavy_frame = (
                prof.repeat_ratio >= 0.8 and prof.payload_change_mean <= 0.05
            )
            profile_margin = self._profile_margin(prof)

            counts = defaultdict(int)
            for b in byte_list:
                counts[b] += 1
            probs = [c / len(byte_list) for c in counts.values() if len(byte_list) > 0]
            entropy = -sum(prob * np.log2(prob) for prob in probs if prob > 0)
            if prof.byte_entropy_std > 1e-6:
                entropy_z = (
                    abs(entropy - prof.byte_entropy_mean) / prof.byte_entropy_std
                )
                if entropy_z >= 4.0:
                    reasons.append(f"entropy_z {entropy_z:.2f}")
                    evidence.append(
                        {
                            "rule": "entropy_drift",
                            "current_entropy": round(float(entropy), 4),
                            "baseline_entropy_mean": round(prof.byte_entropy_mean, 4),
                            "baseline_entropy_std": round(prof.byte_entropy_std, 4),
                            "entropy_z": round(float(entropy_z), 3),
                        }
                    )

            if (
                prof.byte_stability_mask
                and len(prof.byte_stability_mask) == compare_len
            ):
                violations = []
                max_stable_deviation = 0
                for idx in range(compare_len):
                    if not prof.byte_stability_mask[idx]:
                        continue

                    lower = max(0, prof.byte_min[idx] - profile_margin)
                    upper = min(255, prof.byte_max[idx] + profile_margin)
                    if not (lower <= int_bytes[idx] <= upper):
                        deviation = (
                            lower - int_bytes[idx]
                            if int_bytes[idx] < lower
                            else int_bytes[idx] - upper
                        )
                        max_stable_deviation = max(max_stable_deviation, deviation)
                        violations.append(
                            f"byte[{idx}]=0x{int_bytes[idx]:02x} outside stable [{lower:#04x}, {upper:#04x}]"
                        )
                if violations:
                    reasons.append(f"stable_byte_violations({len(violations)})")
                    evidence.append(
                        {
                            "rule": "byte_stability_violation",
                            "violations": violations[:5],
                            "total_violations": len(violations),
                            "max_deviation": int(max_stable_deviation),
                            "tolerance": profile_margin,
                        }
                    )
                    stable_deviation_threshold = 16 if repeat_heavy_frame else 4
                    if (
                        len(violations) >= 2
                        or max_stable_deviation >= stable_deviation_threshold
                        or not repeat_heavy_frame
                    ):
                        strong_signal_count += 1

            if prof.byte_mean and prof.byte_std and len(prof.byte_mean) == compare_len:
                range_violations = []
                max_range_deviation = 0.0
                for idx in range(compare_len):
                    if prof.byte_std[idx] > 1e-6:
                        lower = prof.byte_mean[idx] - 3 * prof.byte_std[idx]
                        upper = prof.byte_mean[idx] + 3 * prof.byte_std[idx]
                        lower = min(lower, prof.byte_min[idx] - profile_margin)
                        upper = max(upper, prof.byte_max[idx] + profile_margin)
                        if not (lower <= int_bytes[idx] <= upper):
                            deviation = (
                                lower - int_bytes[idx]
                                if int_bytes[idx] < lower
                                else int_bytes[idx] - upper
                            )
                            max_range_deviation = max(max_range_deviation, deviation)
                            range_violations.append(
                                f"byte[{idx}]=0x{int_bytes[idx]:02x} outside [0x{int(lower):02x}, 0x{int(upper):02x}]"
                            )
                min_range_violations = (
                    1 if compare_len <= 3 else max(2, int(np.ceil(compare_len * 0.25)))
                )
                if repeat_heavy_frame:
                    min_range_violations = max(3, min_range_violations)
                if len(range_violations) >= min_range_violations:
                    reasons.append(f"byte_range_violations({len(range_violations)})")
                    evidence.append(
                        {
                            "rule": "byte_statistical_range",
                            "violations": range_violations[:5],
                            "total_violations": len(range_violations),
                            "max_deviation": round(float(max_range_deviation), 3),
                            "tolerance": profile_margin,
                        }
                    )
                    min_required_deviation = 0.0 if repeat_heavy_frame else 1.5
                    if (
                        (
                            not repeat_heavy_frame
                            and (
                                len(range_violations) >= min_range_violations + 1
                                or max_range_deviation >= min_required_deviation
                            )
                        )
                        or (repeat_heavy_frame and max_range_deviation >= 3)
                    ):
                        strong_signal_count += 1

            unique_ratio = len(unique_bytes) / len(byte_list) if byte_list else 0.0
            if prof.payload_unique_ratio_mean > 0:
                ratio_diff = abs(unique_ratio - prof.payload_unique_ratio_mean)
                if ratio_diff >= 0.4:
                    reasons.append(f"unique_ratio_drift({ratio_diff:.2f})")
                    evidence.append(
                        {
                            "rule": "payload_unique_ratio_drift",
                            "current_ratio": round(unique_ratio, 4),
                            "baseline_ratio": round(prof.payload_unique_ratio_mean, 4),
                            "drift": round(ratio_diff, 4),
                        }
                    )

            if len(unique_bytes) == 1 and len(p.payload_hex) >= 8:
                byte_val = list(unique_bytes)[0]

                if prof.payload_constant_ratio >= 0.2:
                    continue
                if byte_val in ("00", "ff") and prof.payload_zero_ff_ratio >= 0.05:
                    continue

                reasons.append(f"constant_0x{byte_val}")
                evidence.append(
                    {
                        "rule": "constant_payload",
                        "byte_value": byte_val,
                        "baseline_constant_ratio": round(
                            prof.payload_constant_ratio, 4
                        ),
                        "baseline_zero_ff_ratio": round(prof.payload_zero_ff_ratio, 4),
                    }
                )
                strong_signal_count += 1

            high_signal = strong_signal_count > 0

            if reasons and high_signal:
                evidence.insert(
                    0,
                    {
                        "rule": "byte_profile_context",
                        "observed_payload_bytes": len(int_bytes),
                        "profiled_byte_dimensions": compare_len,
                        "baseline_entropy_mean": round(prof.byte_entropy_mean, 4),
                        "baseline_unique_ratio": round(
                            prof.payload_unique_ratio_mean, 4
                        ),
                        "baseline_repeat_ratio": round(prof.repeat_ratio, 4),
                        "baseline_payload_change": round(
                            prof.payload_change_mean, 4
                        ),
                        "profile_margin": profile_margin,
                    },
                )
                severity = "high" if strong_signal_count >= 2 else "medium"
                confidence = min(
                    1.0,
                    0.58 + 0.12 * strong_signal_count + 0.04 * len(reasons),
                )
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="payload_anomaly",
                        severity=severity,
                        confidence=round(confidence, 3),
                        protocol=p.protocol,
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=(
                            f"Payload anomaly for {p.msg_id}: " + ", ".join(reasons)
                        ),
                        detection_method="payload_profile",
                        vehicle_profile=self.profile_mgr.profile.vehicle_name
                        if self.profile_mgr.profile
                        else None,
                        evidence=evidence,
                    )
                )
        return alerts
