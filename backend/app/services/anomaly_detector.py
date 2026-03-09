"""异常检测引擎

两级检测架构：
1. 规则引擎：频率异常、ID越界、负载异常
2. ML模型：时序画像 + Isolation Forest 无监督异常检测
"""

from collections import Counter, defaultdict
from collections import deque
from dataclasses import dataclass, field
from typing import List

import numpy as np

from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.config import settings


def _is_can_family(packet: UnifiedPacket) -> bool:
    return packet.protocol.upper().startswith("CAN")


def _median_gap(timestamps: List[float]) -> float:
    if len(timestamps) < 2:
        return 0.0
    gaps = [
        max(timestamps[idx] - timestamps[idx - 1], 0.0)
        for idx in range(1, len(timestamps))
    ]
    positive_gaps = [gap for gap in gaps if gap > 0]
    if not positive_gaps:
        return 0.0
    return float(np.median(positive_gaps))


def _payload_bytes(payload_hex: str) -> List[int]:
    if not payload_hex:
        return []
    return [int(payload_hex[i : i + 2], 16) for i in range(0, len(payload_hex), 2)]


def _payload_change_ratio(current: List[int], previous: List[int]) -> float:
    if not current or not previous:
        return 0.0
    compare_len = min(len(current), len(previous))
    if compare_len <= 0:
        return 0.0
    changed = sum(1 for idx in range(compare_len) if current[idx] != previous[idx])
    return changed / compare_len


def _first_word(payload_bytes: List[int]) -> int:
    if len(payload_bytes) < 2:
        return 0
    return payload_bytes[0] << 8 | payload_bytes[1]


@dataclass
class TemporalState:
    prev_ts: float | None = None
    prev_payload: List[int] | None = None
    prev_word: int | None = None
    gaps: deque[float] = field(default_factory=lambda: deque(maxlen=8))
    payload_changes: deque[float] = field(default_factory=lambda: deque(maxlen=8))
    value_deltas: deque[float] = field(default_factory=lambda: deque(maxlen=8))
    repeat_flags: deque[float] = field(default_factory=lambda: deque(maxlen=8))


class RuleBasedDetector:
    """基于规则的快速异常检测"""

    VALID_CAN_IDS = {
        "0x0C0",
        "0x0C8",
        "0x130",
        "0x180",
        "0x1A0",
        "0x200",
        "0x260",
        "0x280",
        "0x320",
        "0x3E0",
        "0x7DF",
        "0x7E0",
    }

    def __init__(self):
        self.freq_threshold = settings.detector.frequency_threshold
        self.id_rate_baseline = {}
        self.id_gap_baseline = {}
        self.learned_can_ids = set()
        self.id_payload_baseline = defaultdict(
            lambda: {"constant": 0.0, "zero_ff": 0.0}
        )

    def check(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        alerts = []
        alerts.extend(self._check_frequency(packets))
        alerts.extend(self._check_unknown_id(packets))
        alerts.extend(self._check_payload(packets))
        return alerts

    def fit(self, normal_packets: List[UnifiedPacket]):
        can_packets = [p for p in normal_packets if _is_can_family(p)]
        if not can_packets:
            return

        id_counts = Counter(p.msg_id for p in can_packets)
        id_timestamps = defaultdict(list)
        min_count = max(3, len(can_packets) // 10000)
        self.learned_can_ids = {
            msg_id for msg_id, cnt in id_counts.items() if cnt >= min_count
        }

        time_span = can_packets[-1].timestamp - can_packets[0].timestamp
        if time_span > 0:
            self.id_rate_baseline = {
                msg_id: cnt / time_span for msg_id, cnt in id_counts.items()
            }

        const_counts = Counter()
        zero_ff_counts = Counter()
        for p in can_packets:
            id_timestamps[p.msg_id].append(p.timestamp)
            if not p.payload_hex:
                continue
            byte_list = [
                p.payload_hex[i : i + 2].lower()
                for i in range(0, len(p.payload_hex), 2)
            ]
            if not byte_list:
                continue
            if len(set(byte_list)) == 1:
                const_counts[p.msg_id] += 1
                if byte_list[0] in ("00", "ff"):
                    zero_ff_counts[p.msg_id] += 1

        for msg_id, cnt in id_counts.items():
            const_ratio = const_counts[msg_id] / cnt
            zero_ff_ratio = zero_ff_counts[msg_id] / cnt
            self.id_gap_baseline[msg_id] = _median_gap(id_timestamps[msg_id])
            self.id_payload_baseline[msg_id] = {
                "constant": const_ratio,
                "zero_ff": zero_ff_ratio,
            }

    def _check_frequency(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测报文频率异常（DoS特征）"""
        alerts = []
        if len(packets) < 2:
            return alerts

        time_span = packets[-1].timestamp - packets[0].timestamp
        if time_span <= 0:
            return alerts

        can_packets = [p for p in packets if _is_can_family(p)]
        id_counts = Counter(p.msg_id for p in can_packets)
        if not id_counts:
            return alerts
        avg_per_id_freq = sum(id_counts.values()) / len(id_counts) / time_span
        id_timestamps = defaultdict(list)
        for packet in can_packets:
            id_timestamps[packet.msg_id].append(packet.timestamp)

        for msg_id, count in id_counts.items():
            freq = count / time_span
            threshold = avg_per_id_freq * self.freq_threshold
            if msg_id in self.id_rate_baseline:
                threshold = max(threshold, self.id_rate_baseline[msg_id] * 2.0)
            if threshold <= 0:
                continue
            ratio = freq / threshold
            baseline_gap = self.id_gap_baseline.get(msg_id, 0.0)
            current_gap = _median_gap(id_timestamps[msg_id])
            burst_ratio = 0.0
            baseline_rate = self.id_rate_baseline.get(msg_id, 0.0)
            rate_ratio = freq / baseline_rate if baseline_rate > 0 else 0.0
            if baseline_gap > 0 and current_gap > 0:
                burst_ratio = baseline_gap / current_gap

            burst_detected = burst_ratio >= 3.0 and rate_ratio >= 1.5 and count >= 20
            if ratio > 1.0 or burst_detected:
                ratio = max(ratio, burst_ratio, rate_ratio)
                if ratio > 3.0:
                    severity = "critical"
                elif ratio > 1.5:
                    severity = "high"
                else:
                    severity = "medium"
                description = (
                    f"报文 {msg_id} 频率异常: {freq:.1f} pkt/s, "
                    f"每ID均值 {avg_per_id_freq:.1f} pkt/s, "
                    f"超出阈值 {self.freq_threshold}x"
                )
                detection_method = "rule_frequency"
                if burst_detected:
                    description = (
                        f"报文 {msg_id} 疑似DoS/Flooding: 当前中位间隔 {current_gap:.6f}s, "
                        f"训练基线 {baseline_gap:.6f}s, 突发倍率 {burst_ratio:.2f}x"
                    )
                    detection_method = "rule_burst_frequency"
                alerts.append(
                    AnomalyEvent(
                        timestamp=packets[-1].timestamp,
                        anomaly_type="frequency_anomaly",
                        severity=severity,
                        confidence=min(ratio, 1.0),
                        protocol="CAN",
                        source_node=msg_id,
                        description=description,
                        detection_method=detection_method,
                    )
                )
        return alerts

    def _check_unknown_id(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测未知CAN ID（Fuzzy攻击特征）"""
        alerts = []
        seen_unknown = set()
        for p in packets:
            if not _is_can_family(p):
                continue
            known_ids = self.learned_can_ids or self.VALID_CAN_IDS
            if p.msg_id not in known_ids and p.msg_id not in seen_unknown:
                seen_unknown.add(p.msg_id)
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="unknown_can_id",
                        severity="high" if self.learned_can_ids else "medium",
                        confidence=0.8 if self.learned_can_ids else 0.6,
                        protocol="CAN",
                        source_node=p.source,
                        description=f"检测到未知CAN ID: {p.msg_id}, 来源: {p.source}",
                        detection_method="rule_id_whitelist",
                    )
                )
        return alerts

    def _check_payload(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测负载异常（全FF等Spoofing特征）"""
        alerts = []
        for p in packets:
            if not _is_can_family(p) or not p.payload_hex:
                continue
            byte_list = [
                p.payload_hex[i : i + 2].lower()
                for i in range(0, len(p.payload_hex), 2)
            ]
            unique_bytes = set(byte_list)
            if len(unique_bytes) == 1 and len(p.payload_hex) >= 8:
                byte_val = list(unique_bytes)[0]
                baseline = self.id_payload_baseline.get(
                    p.msg_id, {"constant": 0.0, "zero_ff": 0.0}
                )
                if baseline["constant"] >= 0.2:
                    continue
                if byte_val in ("00", "ff") and baseline["zero_ff"] >= 0.15:
                    continue

                if byte_val in ("ff", "00"):
                    severity = "high"
                    confidence = 0.7
                else:
                    severity = "low"
                    confidence = 0.5
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="payload_anomaly",
                        severity=severity,
                        confidence=confidence,
                        protocol="CAN",
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=f"报文 {p.msg_id} 负载全为 0x{byte_val}, "
                        f"疑似Spoofing攻击",
                        detection_method="rule_payload",
                    )
                )
        return alerts


class IsolationForestDetector:
    """基于Isolation Forest的无监督异常检测"""

    def __init__(self):
        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(
            contamination="auto",
            random_state=42,
            n_estimators=100,
        )
        self.model.set_params(
            contamination=float(settings.detector.iforest_contamination)
        )
        self.is_fitted = False

    def extract_features(self, packets: List[UnifiedPacket]) -> np.ndarray:
        """从报文列表提取数值特征向量"""
        if not packets:
            return np.array([]).reshape(0, 8)

        features = []
        last_by_id = {}
        for p in packets:
            try:
                if "." not in p.msg_id and p.msg_id.startswith("0x"):
                    msg_id_num = int(p.msg_id, 16)
                else:
                    msg_id_num = hash(p.msg_id) % 0xFFF
            except ValueError:
                msg_id_num = hash(p.msg_id) % 0xFFF
            payload_len = len(p.payload_hex) // 2 if p.payload_hex else 0
            payload_entropy = self._byte_entropy(p.payload_hex)
            if p.protocol.upper().startswith("CAN"):
                proto_num = 0
            else:
                proto_num = {"ETH": 1, "V2X": 2}.get(p.protocol, 3)
            domain_num = {
                "powertrain": 0,
                "chassis": 1,
                "body": 2,
                "infotainment": 3,
                "v2x": 4,
            }.get(p.domain, 5)

            payload_bytes = _payload_bytes(p.payload_hex)
            first_word = _first_word(payload_bytes)

            delta_t = 0.0
            payload_delta = 0.0
            value_delta = 0.0
            prev_state = last_by_id.get(p.msg_id)
            if prev_state:
                prev_ts, prev_bytes, prev_word = prev_state
                delta_t = max(p.timestamp - prev_ts, 0.0)
                if payload_bytes and prev_bytes:
                    compare_len = min(len(payload_bytes), len(prev_bytes))
                    if compare_len > 0:
                        payload_delta = _payload_change_ratio(payload_bytes, prev_bytes)
                value_delta = abs(first_word - prev_word) / 65535.0

            last_by_id[p.msg_id] = (p.timestamp, payload_bytes, first_word)

            features.append(
                [
                    msg_id_num,
                    payload_len,
                    payload_entropy,
                    proto_num,
                    domain_num,
                    delta_t,
                    payload_delta,
                    value_delta,
                ]
            )
        return np.array(features)

    @staticmethod
    def _byte_entropy(hex_str: str) -> float:
        if not hex_str or len(hex_str) < 2:
            return 0.0
        byte_vals = [int(hex_str[i : i + 2], 16) for i in range(0, len(hex_str), 2)]
        counts = Counter(byte_vals)
        total = len(byte_vals)
        entropy = 0.0
        for c in counts.values():
            p = c / total
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy

    def fit(self, normal_packets: List[UnifiedPacket]):
        """用正常流量训练模型"""
        features = self.extract_features(normal_packets)
        if len(features) > 0:
            self.model.fit(features)
            self.is_fitted = True

    def predict(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """检测异常报文"""
        if not self.is_fitted or not packets:
            return []

        features = self.extract_features(packets)
        scores = self.model.decision_function(features)
        preds = self.model.predict(features)

        alerts = []
        for i, (pred, score) in enumerate(zip(preds, scores)):
            if pred == -1 and score < -0.02:
                p = packets[i]
                if score < -0.05:
                    ml_severity = "critical"
                elif score < -0.03:
                    ml_severity = "high"
                elif score < -0.02:
                    ml_severity = "medium"
                else:
                    ml_severity = "low"
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="ml_anomaly",
                        severity=ml_severity,
                        confidence=round(min(abs(score), 1.0), 3),
                        protocol=p.protocol,
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=(
                            f"ML模型检测到异常: {p.protocol} "
                            f"报文 {p.msg_id}, 异常分数 {score:.3f}"
                        ),
                        detection_method="isolation_forest",
                    )
                )
        return alerts


class TemporalProfileDetector:
    def __init__(self):
        self.window_size = 8
        self.id_profiles = {}
        self.is_fitted = False

    def fit(self, normal_packets: List[UnifiedPacket]):
        grouped = defaultdict(list)
        for packet in normal_packets:
            if _is_can_family(packet):
                grouped[packet.msg_id].append(packet)

        profiles = {}
        for msg_id, packets in grouped.items():
            packets.sort(key=lambda packet: packet.timestamp)
            gaps = []
            value_deltas = []
            payload_changes = []
            repeat_flags = []
            prev_ts = None
            prev_payload = None
            prev_word = None
            for packet in packets:
                payload = _payload_bytes(packet.payload_hex)
                word = _first_word(payload)
                if (
                    prev_ts is not None
                    and prev_payload is not None
                    and prev_word is not None
                ):
                    gaps.append(max(packet.timestamp - prev_ts, 0.0))
                    payload_changes.append(_payload_change_ratio(payload, prev_payload))
                    value_deltas.append(abs(word - prev_word) / 65535.0)
                    repeat_flags.append(1.0 if payload == prev_payload else 0.0)
                prev_ts = packet.timestamp
                prev_payload = payload
                prev_word = word

            if not gaps:
                continue

            profiles[msg_id] = {
                "gap_median": float(np.median(gaps)),
                "gap_p10": float(np.percentile(gaps, 10)),
                "payload_change_median": float(np.median(payload_changes))
                if payload_changes
                else 0.0,
                "value_delta_p90": float(np.percentile(value_deltas, 90))
                if value_deltas
                else 0.0,
                "repeat_ratio": float(np.mean(repeat_flags)) if repeat_flags else 0.0,
            }

        self.id_profiles = profiles
        self.is_fitted = bool(self.id_profiles)

    def predict(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        if not self.is_fitted or not packets:
            return []

        states: defaultdict[str, TemporalState] = defaultdict(TemporalState)
        alerts = []

        for packet in packets:
            if not _is_can_family(packet):
                continue
            profile = self.id_profiles.get(packet.msg_id)
            if not profile:
                continue

            state = states[packet.msg_id]
            if state.gaps.maxlen != self.window_size:
                state.gaps = deque(state.gaps, maxlen=self.window_size)
                state.payload_changes = deque(
                    state.payload_changes, maxlen=self.window_size
                )
                state.value_deltas = deque(state.value_deltas, maxlen=self.window_size)
                state.repeat_flags = deque(state.repeat_flags, maxlen=self.window_size)
            payload = _payload_bytes(packet.payload_hex)
            word = _first_word(payload)
            prev_ts = state.prev_ts
            prev_payload = state.prev_payload
            prev_word = state.prev_word

            if (
                prev_ts is not None
                and prev_payload is not None
                and prev_word is not None
            ):
                gap = max(packet.timestamp - prev_ts, 0.0)
                state.gaps.append(gap)
                state.payload_changes.append(
                    _payload_change_ratio(payload, prev_payload)
                )
                state.value_deltas.append(abs(word - prev_word) / 65535.0)
                state.repeat_flags.append(1.0 if payload == prev_payload else 0.0)

            state.prev_ts = packet.timestamp
            state.prev_payload = payload
            state.prev_word = word

            if len(state.gaps) < self.window_size:
                continue

            gap_median = float(np.median(list(state.gaps)))
            repeat_ratio = float(np.mean(list(state.repeat_flags)))
            payload_change_mean = float(np.mean(list(state.payload_changes)))
            value_delta_mean = float(np.mean(list(state.value_deltas)))

            reasons = []
            score = 0.0

            baseline_gap = max(profile["gap_median"], 1e-6)
            if gap_median > 0:
                gap_ratio = baseline_gap / gap_median
                if gap_ratio >= 4.0 and gap_median <= max(profile["gap_p10"], 1e-6):
                    reasons.append(f"突发倍率 {gap_ratio:.2f}x")
                    score = max(score, gap_ratio / 6.0)

            if (
                repeat_ratio >= 0.85
                and repeat_ratio - profile["repeat_ratio"] >= 0.45
                and payload_change_mean <= profile["payload_change_median"] + 0.05
            ):
                reasons.append(f"重复率 {repeat_ratio:.2f}")
                score = max(score, repeat_ratio)

            baseline_value = max(profile["value_delta_p90"], 0.01)
            if (
                value_delta_mean >= baseline_value * 3.0
                and payload_change_mean >= profile["payload_change_median"] + 0.2
            ):
                reasons.append(f"值变化倍率 {(value_delta_mean / baseline_value):.2f}x")
                score = max(score, min(value_delta_mean / baseline_value, 1.0))

            if reasons:
                alerts.append(
                    AnomalyEvent(
                        timestamp=packet.timestamp,
                        anomaly_type="ml_anomaly",
                        severity="high" if score >= 0.8 else "medium",
                        confidence=round(min(max(score, 0.6), 1.0), 3),
                        protocol=packet.protocol,
                        source_node=packet.source,
                        target_node=packet.msg_id,
                        description=(
                            f"时序画像检测到异常: 报文 {packet.msg_id}, "
                            + ", ".join(reasons)
                        ),
                        detection_method="temporal_profile",
                    )
                )

        return alerts


class AnomalyDetectorService:
    """统一异常检测入口"""

    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.temporal_detector = TemporalProfileDetector()
        self.ml_detector = IsolationForestDetector()

    def train(self, normal_packets: List[UnifiedPacket]):
        """用正常流量训练ML模型"""
        self.rule_detector.fit(normal_packets)
        self.temporal_detector.fit(normal_packets)
        self.ml_detector.fit(normal_packets)

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        """执行两级检测"""
        alerts = []

        if settings.detector.rule_enabled:
            alerts.extend(self.rule_detector.check(packets))

        if settings.detector.ml_enabled and self.ml_detector.is_fitted:
            alerts.extend(self.temporal_detector.predict(packets))
            alerts.extend(self.ml_detector.predict(packets))

        # 按置信度降序排列
        alerts.sort(key=lambda a: a.confidence, reverse=True)
        return alerts
