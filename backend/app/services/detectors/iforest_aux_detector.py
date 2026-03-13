from collections import Counter
from typing import List
import numpy as np
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent


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


class IForestAuxDetector:
    def __init__(self, contamination: float = 0.05, enabled: bool = False):
        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(
            contamination=contamination, random_state=42, n_estimators=100
        )
        self.is_fitted = False
        self.enabled = enabled

    def fit(self, normal_packets: List[UnifiedPacket]):
        if not self.enabled:
            return
        features = self._extract_features(normal_packets)
        if len(features) > 0:
            self.model.fit(features)
            self.is_fitted = True

    def detect(self, packets: List[UnifiedPacket]) -> List[AnomalyEvent]:
        if not self.enabled or not self.is_fitted or not packets:
            return []

        features = self._extract_features(packets)
        scores = self.model.decision_function(features)
        preds = self.model.predict(features)

        alerts = []
        for i, (pred, score) in enumerate(zip(preds, scores)):
            if pred == -1 and score < -0.02:
                p = packets[i]
                severity = "low"
                if score < -0.05:
                    severity = "medium"
                alerts.append(
                    AnomalyEvent(
                        timestamp=p.timestamp,
                        anomaly_type="ml_auxiliary",
                        severity=severity,
                        confidence=round(min(abs(score), 1.0), 3),
                        protocol=p.protocol,
                        source_node=p.source,
                        target_node=p.msg_id,
                        description=f"IForest auxiliary: {p.protocol} {p.msg_id}, score {score:.3f}",
                        detection_method="iforest_auxiliary",
                    )
                )
        return alerts

    def _extract_features(self, packets: List[UnifiedPacket]) -> np.ndarray:
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
            proto_num = (
                0
                if p.protocol.upper().startswith("CAN")
                else {"ETH": 1, "V2X": 2}.get(p.protocol, 3)
            )
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
