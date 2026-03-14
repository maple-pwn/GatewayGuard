from typing import List
from collections import defaultdict
import numpy as np
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.profiles.can_profile import ProfileManager, _is_can_family


class PayloadProfileDetector:
    def __init__(self, profile_manager: ProfileManager):
        self.profile_mgr = profile_manager

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        for p in packets:
            if not _is_can_family(p) or not p.payload_hex:
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

            counts = defaultdict(int)
            for b in byte_list:
                counts[b] += 1
            probs = [c / len(byte_list) for c in counts.values() if len(byte_list) > 0]
            entropy = -sum(prob * np.log2(prob) for prob in probs if prob > 0)
            if prof.byte_entropy_std > 1e-6:
                entropy_z = (
                    abs(entropy - prof.byte_entropy_mean) / prof.byte_entropy_std
                )
                if entropy_z >= 3.0:
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

            if len(int_bytes) > 0 and prof.payload_unique_ratio_mean > 0:
                unique_ratio = len(set(int_bytes)) / len(int_bytes)
                if abs(unique_ratio - prof.payload_unique_ratio_mean) > 0.45:
                    reasons.append("unique_ratio_drift")
                    evidence.append(
                        {
                            "rule": "unique_ratio_drift",
                            "current_unique_ratio": round(unique_ratio, 4),
                            "baseline_unique_ratio": round(
                                prof.payload_unique_ratio_mean, 4
                            ),
                        }
                    )

            compare_len = min(
                len(int_bytes),
                len(prof.byte_min),
                len(prof.byte_max),
                len(prof.byte_std),
                len(prof.byte_mean),
            )
            for idx in range(compare_len):
                value = int_bytes[idx]
                std = max(prof.byte_std[idx], 1.0)
                margin = max(3.0 * std, 2.0)
                min_allowed = prof.byte_min[idx] - margin
                max_allowed = prof.byte_max[idx] + margin
                if value < min_allowed or value > max_allowed:
                    reasons.append(f"byte_{idx}_out_of_range")
                    evidence.append(
                        {
                            "rule": "byte_range",
                            "byte_index": idx,
                            "value": value,
                            "min_allowed": round(min_allowed, 2),
                            "max_allowed": round(max_allowed, 2),
                            "baseline_mean": round(prof.byte_mean[idx], 3),
                            "baseline_std": round(prof.byte_std[idx], 3),
                        }
                    )
                    break

            if len(unique_bytes) == 1 and len(p.payload_hex) >= 8:
                byte_val = list(unique_bytes)[0]

                if prof.payload_constant_ratio >= 0.2:
                    continue
                if byte_val in ("00", "ff") and prof.payload_zero_ff_ratio >= 0.15:
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

            if reasons:
                severity = "high" if any("0x" in r for r in reasons) else "medium"
                confidence = min(1.0, 0.55 + 0.1 * len(reasons))
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
