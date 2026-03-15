from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import numpy as np
from app.models.packet import UnifiedPacket


def _is_can_family(packet: UnifiedPacket) -> bool:
    return packet.protocol.upper().startswith("CAN")


def _median_gap(timestamps: List[float]) -> float:
    if len(timestamps) < 2:
        return 0.0
    gaps = [
        max(timestamps[i] - timestamps[i - 1], 0.0) for i in range(1, len(timestamps))
    ]
    positive = [g for g in gaps if g > 0]
    return float(np.median(positive)) if positive else 0.0


@dataclass
class IDProfile:
    msg_id: str
    packet_count: int = 0
    common_dlc: Set[int] = field(default_factory=set)
    gap_median: float = 0.0
    gap_std: float = 0.0
    gap_p10: float = 0.0
    gap_p90: float = 0.0
    frequency: float = 0.0
    payload_constant_ratio: float = 0.0
    payload_zero_ff_ratio: float = 0.0
    byte_stability_mask: List[bool] = field(default_factory=list)
    byte_min: List[int] = field(default_factory=list)
    byte_max: List[int] = field(default_factory=list)
    byte_mean: List[float] = field(default_factory=list)
    byte_std: List[float] = field(default_factory=list)
    byte_entropy_mean: float = 0.0
    byte_entropy_std: float = 0.0
    payload_unique_ratio_mean: float = 0.0
    repeat_ratio: float = 0.0
    payload_change_mean: float = 0.0
    payload_change_std: float = 0.0
    value_delta_mean: float = 0.0
    value_delta_std: float = 0.0
    is_common: bool = False


@dataclass
class CANProfile:
    vehicle_name: str = "default"
    total_packets: int = 0
    id_profiles: Dict[str, IDProfile] = field(default_factory=dict)
    common_ids: Set[str] = field(default_factory=set)
    time_span: float = 0.0


class ProfileManager:
    def __init__(self, min_packets_for_common: int = 10):
        self.min_packets = min_packets_for_common
        self.profile: Optional[CANProfile] = None

    def learn_from_normal(
        self, packets: List[UnifiedPacket], vehicle_name: str = "default"
    ):
        can_packets = [p for p in packets if _is_can_family(p)]
        if not can_packets:
            return

        profile = CANProfile(vehicle_name=vehicle_name, total_packets=len(can_packets))
        id_data = defaultdict(lambda: {"timestamps": [], "dlcs": [], "payloads": []})

        for p in can_packets:
            id_data[p.msg_id]["timestamps"].append(p.timestamp)
            id_data[p.msg_id]["dlcs"].append(
                len(p.payload_hex) // 2 if p.payload_hex else 0
            )
            id_data[p.msg_id]["payloads"].append(p.payload_hex or "")

        profile.time_span = can_packets[-1].timestamp - can_packets[0].timestamp

        for msg_id, data in id_data.items():
            count = len(data["timestamps"])
            if count < 2:
                continue

            id_prof = IDProfile(msg_id=msg_id, packet_count=count)
            id_prof.common_dlc = set(data["dlcs"])
            id_prof.is_common = count >= self.min_packets

            gaps = [
                max(data["timestamps"][i] - data["timestamps"][i - 1], 0.0)
                for i in range(1, len(data["timestamps"]))
            ]
            positive_gaps = [g for g in gaps if g > 0]

            if positive_gaps:
                id_prof.gap_median = float(np.median(positive_gaps))
                id_prof.gap_std = float(np.std(positive_gaps))
                id_prof.gap_p10 = float(np.percentile(positive_gaps, 10))
                id_prof.gap_p90 = float(np.percentile(positive_gaps, 90))

            if profile.time_span > 0:
                id_prof.frequency = count / profile.time_span

            const_count = 0
            zero_ff_count = 0
            entropy_values: List[float] = []
            unique_ratio_values: List[float] = []
            payload_bytes_series: List[List[int]] = []
            for payload in data["payloads"]:
                if not payload or len(payload) < 2:
                    continue
                bytes_list = [
                    payload[i : i + 2].lower() for i in range(0, len(payload), 2)
                ]
                int_bytes = [int(b, 16) for b in bytes_list]
                payload_bytes_series.append(int_bytes)

                if len(set(bytes_list)) == 1:
                    const_count += 1
                    if bytes_list[0] in ("00", "ff"):
                        zero_ff_count += 1

                unique_ratio_values.append(len(set(bytes_list)) / len(bytes_list))

                counts = defaultdict(int)
                for b in bytes_list:
                    counts[b] += 1
                total = len(bytes_list)
                probs = [c / total for c in counts.values()]
                entropy = -sum(p * np.log2(p) for p in probs if p > 0)
                entropy_values.append(float(entropy))

            id_prof.payload_constant_ratio = const_count / count if count > 0 else 0.0
            id_prof.payload_zero_ff_ratio = zero_ff_count / count if count > 0 else 0.0
            if entropy_values:
                id_prof.byte_entropy_mean = float(np.mean(entropy_values))
                id_prof.byte_entropy_std = float(np.std(entropy_values))
            if unique_ratio_values:
                id_prof.payload_unique_ratio_mean = float(np.mean(unique_ratio_values))

            if payload_bytes_series:
                max_len = max(len(v) for v in payload_bytes_series)
                stable_mask: List[bool] = []
                for idx in range(max_len):
                    position_values = [
                        v[idx] for v in payload_bytes_series if len(v) > idx
                    ]
                    if not position_values:
                        id_prof.byte_min.append(0)
                        id_prof.byte_max.append(255)
                        id_prof.byte_mean.append(0.0)
                        id_prof.byte_std.append(0.0)
                        stable_mask.append(False)
                        continue
                    id_prof.byte_min.append(int(min(position_values)))
                    id_prof.byte_max.append(int(max(position_values)))
                    id_prof.byte_mean.append(float(np.mean(position_values)))
                    id_prof.byte_std.append(float(np.std(position_values)))
                    stable_mask.append(len(set(position_values)) <= 2)
                id_prof.byte_stability_mask = stable_mask

            if len(data["payloads"]) > 1:
                repeat_count = sum(
                    1
                    for i in range(1, len(data["payloads"]))
                    if data["payloads"][i] == data["payloads"][i - 1]
                )
                id_prof.repeat_ratio = repeat_count / (len(data["payloads"]) - 1)

            if len(payload_bytes_series) > 1:
                payload_change_values: List[float] = []
                value_delta_values: List[float] = []
                for i in range(1, len(payload_bytes_series)):
                    prev_b = payload_bytes_series[i - 1]
                    curr_b = payload_bytes_series[i]
                    compare_len = min(len(prev_b), len(curr_b))
                    if compare_len <= 0:
                        continue
                    changed = sum(
                        1 for j in range(compare_len) if prev_b[j] != curr_b[j]
                    )
                    payload_change_values.append(changed / compare_len)
                    prev_word = (
                        ((prev_b[0] << 8) | prev_b[1]) if len(prev_b) >= 2 else 0
                    )
                    curr_word = (
                        ((curr_b[0] << 8) | curr_b[1]) if len(curr_b) >= 2 else 0
                    )
                    value_delta_values.append(abs(curr_word - prev_word) / 65535.0)

                if payload_change_values:
                    id_prof.payload_change_mean = float(np.mean(payload_change_values))
                    id_prof.payload_change_std = float(np.std(payload_change_values))
                if value_delta_values:
                    id_prof.value_delta_mean = float(np.mean(value_delta_values))
                    id_prof.value_delta_std = float(np.std(value_delta_values))

            profile.id_profiles[msg_id] = id_prof
            if id_prof.is_common:
                profile.common_ids.add(msg_id)

        self.profile = profile

    def get_profile(self, msg_id: str) -> Optional[IDProfile]:
        if not self.profile:
            return None
        return self.profile.id_profiles.get(msg_id)

    def is_known_id(self, msg_id: str, policy: str = "strict") -> bool:
        if not self.profile:
            return policy == "open_world"

        if policy == "strict_profile":
            return msg_id in self.profile.id_profiles
        elif policy == "warmup_profile":
            return msg_id in self.profile.common_ids
        else:
            return True

    def get_all_known_ids(self) -> Set[str]:
        if not self.profile:
            return set()
        return set(self.profile.id_profiles.keys())
