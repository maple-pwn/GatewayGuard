"""Shared helpers for RPM/gear signal semantics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import median, pstdev
from typing import Dict, Optional, Sequence, Tuple

from app.models.packet import UnifiedPacket


GEAR_MAP = {
    0: "P",
    1: "R",
    2: "N",
    3: "D",
    4: "1",
    5: "2",
    6: "3",
    7: "4",
    8: "5",
    9: "6",
}
VALID_GEARS = set(GEAR_MAP.values())
PARKING_GEARS = {"P", "R", "N"}
DRIVE_GEARS = {"D", "1", "2", "3", "4", "5", "6"}
AUTO_SIGNAL_ID = "auto"
DEFAULT_RPM_CAN_ID = "0x0C0"
DEFAULT_GEAR_CAN_ID = "0x130"
GEAR_ORDER = {
    "P": 0,
    "R": 1,
    "N": 2,
    "D": 3,
    "1": 4,
    "2": 5,
    "3": 6,
    "4": 7,
    "5": 8,
    "6": 9,
}


def decode_rpm(payload_hex: str) -> Optional[float]:
    if not payload_hex or len(payload_hex) < 4:
        return None
    try:
        high = int(payload_hex[0:2], 16)
        low = int(payload_hex[2:4], 16)
    except ValueError:
        return None
    return ((high << 8) | low) * 0.25


def decode_gear(payload_hex: str) -> str:
    if not payload_hex or len(payload_hex) < 2:
        return "UNKNOWN"
    try:
        return GEAR_MAP.get(int(payload_hex[0:2], 16), "INVALID")
    except ValueError:
        return "UNKNOWN"


def gear_order(gear: str) -> int:
    return GEAR_ORDER.get(gear, -1)


def is_parking_gear(gear: str) -> bool:
    return gear in PARKING_GEARS


def is_drive_gear(gear: str) -> bool:
    return gear in DRIVE_GEARS


@dataclass(frozen=True)
class GearStateModel:
    mode: str = "canonical"
    positions: Tuple[int, ...] = (0,)


@dataclass(frozen=True)
class RPMDecodeModel:
    mode: str = "canonical"
    value_mask: int = 0xFF
    observed_flag_values: Tuple[int, ...] = ()


def is_auto_signal_id(value: Optional[str]) -> bool:
    if value is None:
        return True
    normalized = str(value).strip().lower()
    return normalized in {"", AUTO_SIGNAL_ID, "detect", "learned"}


def normalize_can_id(value: Optional[str], fallback: str) -> str:
    if is_auto_signal_id(value):
        return fallback

    raw = str(value).strip().replace("0x", "").replace("0X", "")
    if not raw:
        return fallback
    try:
        return f"0x{int(raw, 16):03X}"
    except ValueError:
        return fallback


def infer_gear_state_model(payloads: Sequence[str]) -> GearStateModel:
    clean_payloads = [payload.upper() for payload in payloads if payload]
    if not clean_payloads:
        return GearStateModel()

    canonical_states = [
        decode_gear(payload)
        for payload in clean_payloads
        if decode_gear(payload) in VALID_GEARS
    ]
    valid_ratio = len(canonical_states) / len(clean_payloads)
    if valid_ratio >= 0.98 and canonical_states:
        return GearStateModel(mode="canonical", positions=(0,))

    candidates = []
    max_bytes = min(max(len(payload) for payload in clean_payloads) // 2, 8)
    for index in range(max_bytes):
        values = [
            payload[index * 2 : (index + 1) * 2]
            for payload in clean_payloads
            if len(payload) >= (index + 1) * 2
        ]
        unique_count = len(set(values))
        if 1 < unique_count <= 16:
            transitions = sum(1 for prev, curr in zip(values, values[1:]) if prev != curr)
            transition_ratio = transitions / max(1, len(values) - 1)
            candidates.append((index, unique_count, transition_ratio))

    if not candidates:
        positions = [0]
    else:
        chosen = sorted(
            candidates,
            key=lambda item: (item[1], item[2], item[0]),
        )[:2]
        positions = sorted(index for index, _, _ in chosen)

    return GearStateModel(mode="symbolic", positions=tuple(positions[:3]))


def infer_rpm_decode_model(payloads: Sequence[str]) -> RPMDecodeModel:
    clean_payloads = [payload.upper() for payload in payloads if len(payload or "") >= 4]
    if len(clean_payloads) < 8:
        return RPMDecodeModel()

    first_bytes = [int(payload[0:2], 16) for payload in clean_payloads]
    unique_first = set(first_bytes)
    low_nibbles = {value & 0x0F for value in unique_first}
    high_nibbles = {value & 0xF0 for value in unique_first}

    if len(unique_first) <= 4 and len(low_nibbles) == 1 and len(high_nibbles) >= 2:
        return RPMDecodeModel(
            mode="masked_high_nibble",
            value_mask=0x0F,
            observed_flag_values=tuple(sorted(high_nibbles)),
        )

    return RPMDecodeModel()


def extract_rpm_value(
    payload_hex: str,
    model: Optional[RPMDecodeModel] = None,
) -> Optional[float]:
    if not payload_hex or len(payload_hex) < 4:
        return None

    active_model = model or RPMDecodeModel()
    try:
        high = int(payload_hex[0:2], 16)
        low = int(payload_hex[2:4], 16)
    except ValueError:
        return None

    masked_high = high & active_model.value_mask
    return ((masked_high << 8) | low) * 0.25


def extract_rpm_flag(
    payload_hex: str,
    model: Optional[RPMDecodeModel] = None,
) -> Optional[int]:
    if not payload_hex or len(payload_hex) < 2:
        return None

    active_model = model or RPMDecodeModel()
    if active_model.mode != "masked_high_nibble":
        return None

    try:
        high = int(payload_hex[0:2], 16)
    except ValueError:
        return None
    return high & (~active_model.value_mask & 0xFF)


def extract_gear_state(
    payload_hex: str,
    model: Optional[GearStateModel] = None,
) -> Optional[str]:
    if not payload_hex:
        return None

    active_model = model or GearStateModel()
    if active_model.mode == "canonical":
        gear = decode_gear(payload_hex)
        return gear if gear in VALID_GEARS else None

    parts = []
    for index in active_model.positions:
        start = index * 2
        end = start + 2
        if len(payload_hex) < end:
            return None
        parts.append(payload_hex[start:end].upper())
    return "|".join(parts) if parts else None


@dataclass
class _SignalStats:
    sample_count: int
    unique_first_byte: int
    unique_small_first_byte: int
    small_first_ratio: float
    first_byte_transition_ratio: float
    unique_prefix16: int
    prefix16_transition_ratio: float
    rpm_in_range_ratio: float
    rpm_std: float
    tail_unique_mean: float


def discover_powertrain_ids(
    packets: Sequence[UnifiedPacket],
    rpm_hint: Optional[str] = None,
    gear_hint: Optional[str] = None,
    *,
    max_rpm: float = 8000.0,
    context_window_s: float = 0.15,
) -> Tuple[str, str]:
    resolved_rpm = normalize_can_id(rpm_hint, DEFAULT_RPM_CAN_ID)
    resolved_gear = normalize_can_id(gear_hint, DEFAULT_GEAR_CAN_ID)

    if not is_auto_signal_id(rpm_hint) and not is_auto_signal_id(gear_hint):
        return resolved_rpm, resolved_gear

    grouped: Dict[str, list[UnifiedPacket]] = defaultdict(list)
    for packet in sorted(packets, key=lambda item: item.timestamp):
        if packet.payload_hex:
            grouped[packet.msg_id].append(packet)

    stats_map = {
        msg_id: _build_signal_stats(sequence, max_rpm=max_rpm)
        for msg_id, sequence in grouped.items()
    }

    if is_auto_signal_id(gear_hint):
        best_gear_score = 0.0
        best_gear_id = resolved_gear
        for msg_id, sequence in grouped.items():
            score = _score_gear_candidate(sequence, stats_map[msg_id])
            if score > best_gear_score:
                best_gear_score = score
                best_gear_id = msg_id
        resolved_gear = best_gear_id

    if is_auto_signal_id(rpm_hint):
        best_rpm_score = 0.0
        best_rpm_id = resolved_rpm
        gear_model = infer_gear_state_model(
            [packet.payload_hex for packet in grouped.get(resolved_gear, [])]
        )
        for msg_id, sequence in grouped.items():
            stats = stats_map[msg_id]
            score = _score_rpm_candidate(stats)
            if score <= 0:
                continue
            score *= _rpm_pair_bonus(
                packets=packets,
                rpm_can_id=msg_id,
                gear_can_id=resolved_gear,
                gear_model=gear_model,
                context_window_s=context_window_s,
            )
            if score > best_rpm_score:
                best_rpm_score = score
                best_rpm_id = msg_id
        resolved_rpm = best_rpm_id

    return resolved_rpm, resolved_gear


def _build_signal_stats(
    packets: Sequence[UnifiedPacket],
    *,
    max_rpm: float,
) -> _SignalStats:
    first_bytes = []
    prefix16 = []
    rpm_values = []
    byte_uniques = [set() for _ in range(8)]

    for packet in packets:
        payload = (packet.payload_hex or "").upper()
        if len(payload) >= 2:
            first_bytes.append(int(payload[0:2], 16))
        if len(payload) >= 4:
            prefix16.append(int(payload[0:4], 16))
            rpm = decode_rpm(payload)
            if rpm is not None:
                rpm_values.append(rpm)
        for index in range(min(len(payload) // 2, 8)):
            byte_uniques[index].add(payload[index * 2 : (index + 1) * 2])

    first_transitions = sum(
        1 for prev, curr in zip(first_bytes, first_bytes[1:]) if prev != curr
    )
    prefix_transitions = sum(
        1 for prev, curr in zip(prefix16, prefix16[1:]) if prev != curr
    )
    small_first_values = [value for value in first_bytes if value < 0x10]
    in_range_ratio = (
        sum(1 for value in rpm_values if 0.0 <= value <= max_rpm) / len(rpm_values)
        if rpm_values
        else 0.0
    )
    tail_unique_values = [
        len(values) for values in byte_uniques[2:] if values
    ]

    return _SignalStats(
        sample_count=len(packets),
        unique_first_byte=len(set(first_bytes)),
        unique_small_first_byte=len(set(small_first_values)),
        small_first_ratio=(
            len(small_first_values) / len(first_bytes) if first_bytes else 0.0
        ),
        first_byte_transition_ratio=(
            first_transitions / max(1, len(first_bytes) - 1) if first_bytes else 0.0
        ),
        unique_prefix16=len(set(prefix16)),
        prefix16_transition_ratio=(
            prefix_transitions / max(1, len(prefix16) - 1) if prefix16 else 0.0
        ),
        rpm_in_range_ratio=in_range_ratio,
        rpm_std=pstdev(rpm_values) if len(rpm_values) >= 2 else 0.0,
        tail_unique_mean=(
            sum(tail_unique_values) / len(tail_unique_values)
            if tail_unique_values
            else 0.0
        ),
    )


def _score_gear_candidate(
    packets: Sequence[UnifiedPacket],
    stats: _SignalStats,
) -> float:
    if stats.sample_count < 20:
        return 0.0

    model = infer_gear_state_model([packet.payload_hex for packet in packets])
    states = [
        state
        for state in (extract_gear_state(packet.payload_hex, model) for packet in packets)
        if state is not None
    ]
    unique_states = len(set(states))
    if unique_states < 2 or unique_states > 16:
        return 0.0

    sample_factor = min(stats.sample_count / 300.0, 12.0)
    state_factor = min(unique_states, 8) / 8.0
    low_cardinality = max(stats.small_first_ratio, 0.25 if model.mode == "symbolic" else 0.0)
    stability = 1.0 / (1.0 + stats.first_byte_transition_ratio * 6.0)
    mode_bonus = 1.15 if model.mode == "symbolic" and len(model.positions) > 1 else 1.05
    return sample_factor * state_factor * low_cardinality * stability * mode_bonus


def _score_rpm_candidate(stats: _SignalStats) -> float:
    if (
        stats.sample_count < 20
        or stats.rpm_in_range_ratio < 0.65
        or stats.unique_prefix16 < 16
        or stats.prefix16_transition_ratio < 0.05
        or stats.rpm_std < 80.0
    ):
        return 0.0

    sample_factor = min(stats.sample_count / 300.0, 12.0)
    std_factor = min(stats.rpm_std / 400.0, 4.0)
    dynamic_factor = min(stats.unique_prefix16 / 64.0, 4.0)
    small_first_factor = max(stats.small_first_ratio, 0.15)
    transition_factor = max(
        0.2,
        1.0 - abs(stats.prefix16_transition_ratio - 0.3) / 0.7,
    )
    first_byte_penalty = 1.0 / (
        1.0 + max(0.0, stats.unique_first_byte - 16.0) / 24.0
    )
    tail_penalty = 1.0 / (
        1.0 + max(0.0, stats.tail_unique_mean - 48.0) / 96.0
    )
    return (
        sample_factor
        * std_factor
        * dynamic_factor
        * small_first_factor
        * transition_factor
        * first_byte_penalty
        * tail_penalty
    )


def _rpm_pair_bonus(
    *,
    packets: Sequence[UnifiedPacket],
    rpm_can_id: str,
    gear_can_id: str,
    gear_model: GearStateModel,
    context_window_s: float,
) -> float:
    if not packets or rpm_can_id == gear_can_id:
        return 1.0

    latest_state: Optional[str] = None
    latest_state_ts: Optional[float] = None
    state_rpm_values: Dict[str, list[float]] = defaultdict(list)

    for packet in sorted(packets, key=lambda item: item.timestamp):
        if packet.msg_id == gear_can_id:
            state = extract_gear_state(packet.payload_hex, gear_model)
            if state is not None:
                latest_state = state
                latest_state_ts = packet.timestamp
            continue

        if packet.msg_id != rpm_can_id:
            continue

        rpm = decode_rpm(packet.payload_hex)
        if (
            rpm is None
            or latest_state is None
            or latest_state_ts is None
            or packet.timestamp - latest_state_ts > context_window_s
        ):
            continue

        state_rpm_values[latest_state].append(rpm)

    usable = [values for values in state_rpm_values.values() if len(values) >= 20]
    if len(usable) < 2:
        return 1.0

    medians = [median(values) for values in usable]
    within_std = sum(pstdev(values) for values in usable) / len(usable)
    between_std = pstdev(medians) if len(medians) >= 2 else 0.0
    coverage = sum(len(values) for values in usable)

    coverage_bonus = 1.0 + min(coverage, 2000) / 2000.0
    state_bonus = 1.0 + min(len(usable), 6) / 6.0
    separation_bonus = 1.0 + min(2.0, between_std / (within_std + 1.0))
    return coverage_bonus * state_bonus * separation_bonus
