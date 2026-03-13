from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set
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
    repeat_ratio: float = 0.0
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
        self.profile: CANProfile | None = None

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
            for payload in data["payloads"]:
                if not payload or len(payload) < 2:
                    continue
                bytes_list = [
                    payload[i : i + 2].lower() for i in range(0, len(payload), 2)
                ]
                if len(set(bytes_list)) == 1:
                    const_count += 1
                    if bytes_list[0] in ("00", "ff"):
                        zero_ff_count += 1

            id_prof.payload_constant_ratio = const_count / count if count > 0 else 0.0
            id_prof.payload_zero_ff_ratio = zero_ff_count / count if count > 0 else 0.0

            if len(data["payloads"]) > 1:
                repeat_count = sum(
                    1
                    for i in range(1, len(data["payloads"]))
                    if data["payloads"][i] == data["payloads"][i - 1]
                )
                id_prof.repeat_ratio = repeat_count / (len(data["payloads"]) - 1)

            profile.id_profiles[msg_id] = id_prof
            if id_prof.is_common:
                profile.common_ids.add(msg_id)

        self.profile = profile

    def get_profile(self, msg_id: str) -> IDProfile | None:
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
