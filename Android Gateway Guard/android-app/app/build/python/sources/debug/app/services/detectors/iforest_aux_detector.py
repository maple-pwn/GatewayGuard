from collections import Counter, defaultdict, deque
import logging
from typing import Deque, Dict, List, Tuple

import numpy as np

from app.models.anomaly import AnomalyEvent
from app.models.packet import UnifiedPacket

logger = logging.getLogger(__name__)


def _payload_bytes(payload_hex: str) -> List[int]:
    if not payload_hex:
        return []
    return [int(payload_hex[i : i + 2], 16) for i in range(0, len(payload_hex), 2)]


def _first_word(payload_bytes: List[int]) -> int:
    if len(payload_bytes) < 2:
        return 0
    return payload_bytes[0] << 8 | payload_bytes[1]


def _payload_change_ratio(current: List[int], previous: List[int]) -> float:
    if not current or not previous:
        return 0.0
    compare_len = min(len(current), len(previous))
    if compare_len <= 0:
        return 0.0
    changed = sum(1 for i in range(compare_len) if current[i] != previous[i])
    return changed / compare_len


def _is_zero_ff_constant(payload_hex: str) -> bool:
    if not payload_hex or len(payload_hex) < 2:
        return False
    bytes_list = [payload_hex[i : i + 2].lower() for i in range(0, len(payload_hex), 2)]
    return len(set(bytes_list)) == 1 and bytes_list[0] in ("00", "ff")


class IForestAuxDetector:
    def __init__(self, contamination: float = 0.05, enabled: bool = False):
        self.contamination = contamination
        self.model = None
        self.is_fitted = False
        self.enabled = enabled
        self.score_threshold = -0.02
        self.unknown_score_threshold = 0.05

        # Learned normal baselines used to build rate-aware ML features.
        self.window_seconds = 0.05
        self.global_rate_baseline = 0.0
        self.id_gap_baseline: Dict[str, float] = {}
        self.id_freq_baseline: Dict[str, float] = {}
        self.id_repeat_baseline: Dict[str, float] = {}
        self.id_zero_ff_baseline: Dict[str, float] = {}

        if self.enabled:
            self._ensure_model()

    def _ensure_model(self):
        if self.model is not None:
            return
        try:
            from sklearn.ensemble import IsolationForest
        except Exception as exc:
            self.enabled = False
            self.is_fitted = False
            logger.warning("Disable IForest auxiliary detector: %s", exc)
            return

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )

    def fit(self, normal_packets: List[UnifiedPacket]):
        if not self.enabled:
            return

        self._ensure_model()
        if self.model is None:
            return
        sorted_packets = sorted(normal_packets, key=lambda packet: packet.timestamp)
        self._learn_baselines(sorted_packets)
        features, _ = self._extract_features(sorted_packets)
        if len(features) > 0:
            self.model.fit(features)
            train_scores = self.model.decision_function(features)
            if len(train_scores) > 0:
                self.score_threshold = min(
                    -0.02,
                    float(np.percentile(train_scores, 0.5)),
                )
            self.is_fitted = True

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        if not self.enabled or not self.is_fitted or not packets or self.model is None:
            return []

        features, contexts = self._extract_features(packets)
        scores = self.model.decision_function(features)

        alerts = []
        for i, (score, context) in enumerate(zip(scores, contexts)):
            known_id = context["known_id"] >= 1.0
            score_trigger = score <= self.score_threshold
            relaxed_unknown_trigger = (
                not known_id and score <= self.unknown_score_threshold
            )
            burst_trigger, burst_confidence, reasons = self._burst_signal(context)

            if not score_trigger and not relaxed_unknown_trigger and not burst_trigger:
                continue

            # Known IDs are noisy under score-only IF decisions; require an explicit
            # burst/flood signature before surfacing them as ML alerts.
            if known_id and not burst_trigger:
                continue

            packet = packets[i]
            confidence = 0.0
            reason_parts: List[str] = []

            if score_trigger:
                # Map score distance to a bounded confidence.
                margin = max(self.score_threshold - score, 0.0)
                confidence = max(confidence, min(0.95, 0.45 + margin * 6.0))
                reason_parts.append(
                    f"iforest score {score:.3f} <= threshold {self.score_threshold:.3f}"
                )

            if relaxed_unknown_trigger:
                margin = max(self.unknown_score_threshold - score, 0.0)
                confidence = max(confidence, min(0.92, 0.58 + margin * 3.0))
                reason_parts.append(
                    f"unknown-id score {score:.3f} <= relaxed threshold {self.unknown_score_threshold:.3f}"
                )

            if burst_trigger:
                confidence = max(confidence, burst_confidence)
                reason_parts.extend(reasons)

            severity = "low"
            if confidence >= 0.8:
                severity = "high"
            elif confidence >= 0.6:
                severity = "medium"

            evidence = [
                {
                    "rule": "iforest_context",
                    "known_id": bool(known_id),
                    "burst_signal": bool(burst_trigger),
                    "score_trigger": bool(score_trigger),
                    "relaxed_unknown_trigger": bool(relaxed_unknown_trigger),
                    "score": round(float(score), 4),
                    "gap_ratio": round(float(context["gap_ratio"]), 4),
                    "id_rate_ratio": round(float(context["id_rate_ratio"]), 4),
                    "global_rate_ratio": round(float(context["global_rate_ratio"]), 4),
                    "id_window_share": round(float(context["id_window_share"]), 4),
                    "repeat_run": int(context["repeat_run"]),
                    "zero_ff_flag": bool(context["zero_ff_flag"] >= 1.0),
                }
            ]

            alerts.append(
                AnomalyEvent(
                    timestamp=packet.timestamp,
                    anomaly_type="ml_auxiliary",
                    severity=severity,
                    confidence=round(min(max(confidence, 0.35), 1.0), 3),
                    protocol=packet.protocol,
                    source_node=packet.source,
                    target_node=packet.msg_id,
                    description=(
                        f"ML auxiliary anomaly: {packet.protocol} {packet.msg_id}; "
                        + "; ".join(reason_parts[:3])
                    ),
                    detection_method="iforest_auxiliary",
                    evidence=evidence,
                )
            )
        return alerts

    def _learn_baselines(self, packets: List[UnifiedPacket]) -> None:
        can_packets = [packet for packet in packets if packet.protocol.upper().startswith("CAN")]
        if len(can_packets) < 2:
            return

        time_span = can_packets[-1].timestamp - can_packets[0].timestamp
        if time_span > 0:
            self.global_rate_baseline = len(can_packets) / time_span

        timestamps_by_id: Dict[str, List[float]] = defaultdict(list)
        payloads_by_id: Dict[str, List[str]] = defaultdict(list)
        for packet in can_packets:
            timestamps_by_id[packet.msg_id].append(packet.timestamp)
            payloads_by_id[packet.msg_id].append(packet.payload_hex or "")

        self.id_gap_baseline.clear()
        self.id_freq_baseline.clear()
        self.id_repeat_baseline.clear()
        self.id_zero_ff_baseline.clear()

        for msg_id, timestamps in timestamps_by_id.items():
            if len(timestamps) < 2:
                continue

            gaps = [
                max(timestamps[i] - timestamps[i - 1], 0.0)
                for i in range(1, len(timestamps))
            ]
            positive_gaps = [gap for gap in gaps if gap > 0]
            if positive_gaps:
                self.id_gap_baseline[msg_id] = float(np.median(positive_gaps))

            if time_span > 0:
                self.id_freq_baseline[msg_id] = len(timestamps) / time_span

            payloads = payloads_by_id[msg_id]
            if len(payloads) > 1:
                repeat_count = sum(
                    1
                    for i in range(1, len(payloads))
                    if payloads[i] == payloads[i - 1]
                )
                self.id_repeat_baseline[msg_id] = repeat_count / (len(payloads) - 1)
            else:
                self.id_repeat_baseline[msg_id] = 0.0

            zero_ff_count = sum(1 for payload in payloads if _is_zero_ff_constant(payload))
            self.id_zero_ff_baseline[msg_id] = (
                zero_ff_count / len(payloads) if payloads else 0.0
            )

    def _extract_features(
        self, packets: List[UnifiedPacket]
    ) -> Tuple[np.ndarray, List[Dict[str, float]]]:
        if not packets:
            return np.array([]).reshape(0, 15), []

        features = []
        contexts: List[Dict[str, float]] = []
        last_by_id: Dict[str, Tuple[float, List[int], int, str, int]] = {}
        recent_by_id: Dict[str, Deque[float]] = defaultdict(deque)
        recent_global: Deque[float] = deque()

        for packet in packets:
            try:
                if "." not in packet.msg_id and packet.msg_id.startswith("0x"):
                    msg_id_num = int(packet.msg_id, 16)
                else:
                    msg_id_num = hash(packet.msg_id) % 0xFFF
            except ValueError:
                msg_id_num = hash(packet.msg_id) % 0xFFF

            payload_len = len(packet.payload_hex) // 2 if packet.payload_hex else 0
            payload_entropy = self._byte_entropy(packet.payload_hex)
            proto_num = (
                0
                if packet.protocol.upper().startswith("CAN")
                else {"ETH": 1, "V2X": 2}.get(packet.protocol, 3)
            )
            domain_num = {
                "powertrain": 0,
                "chassis": 1,
                "body": 2,
                "infotainment": 3,
                "v2x": 4,
            }.get(packet.domain, 5)

            while recent_global and packet.timestamp - recent_global[0] > self.window_seconds:
                recent_global.popleft()
            recent_global.append(packet.timestamp)

            id_window = recent_by_id[packet.msg_id]
            while id_window and packet.timestamp - id_window[0] > self.window_seconds:
                id_window.popleft()
            id_window.append(packet.timestamp)

            payload_bytes = _payload_bytes(packet.payload_hex)
            first_word = _first_word(payload_bytes)

            delta_t = 0.0
            payload_delta = 0.0
            value_delta = 0.0
            repeat_run = 0
            prev_state = last_by_id.get(packet.msg_id)
            if prev_state:
                prev_ts, prev_bytes, prev_word, prev_hex, prev_repeat_run = prev_state
                delta_t = max(packet.timestamp - prev_ts, 0.0)
                if payload_bytes and prev_bytes:
                    payload_delta = _payload_change_ratio(payload_bytes, prev_bytes)
                value_delta = abs(first_word - prev_word) / 65535.0
                repeat_run = prev_repeat_run + 1 if packet.payload_hex == prev_hex else 0

            baseline_gap = self.id_gap_baseline.get(packet.msg_id, 0.0)
            known_id = 1.0 if packet.msg_id in self.id_freq_baseline else 0.0
            gap_ratio = (
                baseline_gap / max(delta_t, 1e-6)
                if baseline_gap > 0 and delta_t > 0
                else 1.0
            )

            id_rate = len(id_window) / max(self.window_seconds, 1e-6)
            baseline_freq = self.id_freq_baseline.get(packet.msg_id, 0.0)
            id_rate_ratio = (
                id_rate / max(baseline_freq, 1e-6) if baseline_freq > 0 else 1.0
            )

            global_rate = len(recent_global) / max(self.window_seconds, 1e-6)
            global_rate_ratio = (
                global_rate / max(self.global_rate_baseline, 1e-6)
                if self.global_rate_baseline > 0
                else 1.0
            )
            id_window_share = len(id_window) / max(len(recent_global), 1)

            zero_ff_flag = 1.0 if _is_zero_ff_constant(packet.payload_hex) else 0.0
            repeat_run_norm = min(repeat_run, 20) / 20.0

            last_by_id[packet.msg_id] = (
                packet.timestamp,
                payload_bytes,
                first_word,
                packet.payload_hex,
                repeat_run,
            )

            features.append(
                [
                    np.log1p(msg_id_num),
                    payload_len,
                    payload_entropy,
                    proto_num,
                    domain_num,
                    np.log1p(delta_t * 1_000_000.0) if delta_t > 0 else 0.0,
                    payload_delta,
                    value_delta,
                    min(gap_ratio, 100.0),
                    min(id_rate_ratio, 100.0),
                    min(global_rate_ratio, 100.0),
                    min(id_window_share, 1.0),
                    repeat_run_norm,
                    zero_ff_flag,
                    known_id,
                ]
            )
            contexts.append(
                {
                    "gap_ratio": min(gap_ratio, 100.0),
                    "id_rate_ratio": min(id_rate_ratio, 100.0),
                    "global_rate_ratio": min(global_rate_ratio, 100.0),
                    "id_window_share": min(id_window_share, 1.0),
                    "repeat_run": float(repeat_run),
                    "payload_delta": payload_delta,
                    "zero_ff_flag": zero_ff_flag,
                    "baseline_zero_ff_ratio": self.id_zero_ff_baseline.get(packet.msg_id, 0.0),
                    "known_id": known_id,
                }
            )

        return np.array(features), contexts

    def _burst_signal(self, context: Dict[str, float]) -> Tuple[bool, float, List[str]]:
        reasons: List[str] = []
        confidence = 0.0

        gap_ratio = context["gap_ratio"]
        id_rate_ratio = context["id_rate_ratio"]
        global_rate_ratio = context["global_rate_ratio"]
        id_window_share = context["id_window_share"]
        repeat_run = context["repeat_run"]
        zero_ff_flag = context["zero_ff_flag"]
        baseline_zero_ff_ratio = context["baseline_zero_ff_ratio"]
        known_id = context["known_id"] >= 1.0

        if (
            not known_id
            and zero_ff_flag >= 1.0
            and repeat_run >= 1
            and id_rate_ratio >= 2.5
            and (global_rate_ratio >= 1.5 or gap_ratio >= 3.0)
        ):
            confidence = max(
                confidence,
                min(
                    0.98,
                    0.66
                    + 0.04 * min(id_rate_ratio, 10.0)
                    + 0.05 * min(global_rate_ratio, 6.0)
                    + 0.03 * min(gap_ratio, 8.0),
                ),
            )
            reasons.append(
                f"unknown zero-payload flood: bus {global_rate_ratio:.2f}x, id rate {id_rate_ratio:.2f}x, burst {gap_ratio:.2f}x"
            )

        if (
            not known_id
            and id_window_share >= 0.45
            and gap_ratio >= 4.0
            and id_rate_ratio >= 4.0
            and repeat_run >= 2
            and (zero_ff_flag >= 1.0 or context["payload_delta"] <= 0.05)
        ):
            confidence = max(
                confidence,
                min(
                    0.98,
                    0.62
                    + 0.04 * min(gap_ratio, 10.0)
                    + 0.04 * min(id_rate_ratio, 10.0)
                    + 0.20 * min(id_window_share, 1.0),
                ),
            )
            reasons.append(
                f"unknown-id flood pattern: share {id_window_share:.2f}, burst {gap_ratio:.2f}x, id rate {id_rate_ratio:.2f}x"
            )

        if (
            known_id
            and id_window_share >= 0.55
            and global_rate_ratio >= 2.5
            and id_rate_ratio >= 6.0
            and gap_ratio >= 6.0
            and repeat_run >= 4
            and (zero_ff_flag >= 1.0 or context["payload_delta"] <= 0.02)
        ):
            confidence = max(
                confidence,
                min(
                    0.95,
                    0.58
                    + 0.05 * min(global_rate_ratio, 8.0)
                    + 0.03 * min(id_rate_ratio, 10.0)
                    + 0.02 * min(gap_ratio, 10.0),
                ),
            )
            reasons.append(
                f"known-id flood pattern: share {id_window_share:.2f}, bus rate {global_rate_ratio:.2f}x, id rate {id_rate_ratio:.2f}x"
            )

        if (
            not known_id
            and id_window_share >= 0.60
            and repeat_run >= 3
            and id_rate_ratio >= 5.0
            and context["payload_delta"] <= 0.02
        ):
            confidence = max(confidence, 0.82)
            reasons.append(f"repeat run {int(repeat_run)} with static payload")

        if (
            zero_ff_flag >= 1.0
            and baseline_zero_ff_ratio < 0.2
            and id_window_share >= 0.50
            and repeat_run >= 3
            and id_rate_ratio >= 4.0
        ):
            confidence = max(confidence, 0.82)
            reasons.append("repeated all-00/FF payload above learned baseline")

        return confidence >= 0.72, confidence, reasons

    @staticmethod
    def _byte_entropy(hex_str: str) -> float:
        if not hex_str or len(hex_str) < 2:
            return 0.0
        byte_vals = [int(hex_str[i : i + 2], 16) for i in range(0, len(hex_str), 2)]
        counts = Counter(byte_vals)
        total = len(byte_vals)
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)
        return entropy
