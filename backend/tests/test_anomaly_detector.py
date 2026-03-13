from app.models.packet import UnifiedPacket
from app.services.anomaly_detector import AnomalyDetectorService
from app.services.detectors.iforest_aux_detector import IForestAuxDetector


def _make_packet(
    timestamp: float,
    msg_id: str,
    payload_hex: str = "0102030405060708",
    protocol: str = "CAN",
) -> UnifiedPacket:
    return UnifiedPacket(
        timestamp=timestamp,
        protocol=protocol,
        source="ECM",
        destination="BROADCAST",
        msg_id=msg_id,
        payload_hex=payload_hex,
        domain="powertrain",
    )


def _baseline_packets() -> list[UnifiedPacket]:
    return [
        _make_packet(timestamp=1000.0 + i * 0.02, msg_id="0x120") for i in range(60)
    ]


class TestProfileFirstAnomalyDetectorService:
    def setup_method(self):
        self.service = AnomalyDetectorService()

    def test_detect_without_training_returns_empty(self):
        packets = _baseline_packets()
        alerts = self.service.detect(packets)
        assert alerts == []

    def test_train_then_detect_unknown_can_id(self):
        self.service.train(_baseline_packets())
        eval_packets = [_make_packet(timestamp=2000.0, msg_id="0x999")]
        alerts = self.service.detect(eval_packets)

        assert len(alerts) >= 1
        assert any(a.anomaly_type == "unknown_can_id" for a in alerts)
        assert self.service.is_trained is True

    def test_detect_with_aggregation_returns_events(self):
        self.service.train(_baseline_packets())
        eval_packets = [
            _make_packet(timestamp=2000.0 + i * 0.01, msg_id="0x999") for i in range(3)
        ]

        alerts, events = self.service.detect_with_aggregation(eval_packets)
        assert len(alerts) >= 1
        assert len(events) >= 1
        assert events[0].packet_count >= 1
        assert any(a.event_id is not None for a in alerts)
        assert any((a.packet_count or 0) >= 1 for a in alerts)

    def test_alerts_sorted_by_confidence_desc(self):
        self.service.train(_baseline_packets())
        eval_packets = [_make_packet(timestamp=2000.0, msg_id="0x999")]
        alerts = self.service.detect(eval_packets)

        for i in range(1, len(alerts)):
            assert alerts[i - 1].confidence >= alerts[i].confidence


class TestIForestAuxDetector:
    def test_feature_shape_matches_expected_dimensions(self):
        detector = IForestAuxDetector(enabled=False)
        features = detector._extract_features(_baseline_packets())
        assert features.shape == (60, 8)

    def test_feature_shape_for_empty_packets(self):
        detector = IForestAuxDetector(enabled=False)
        features = detector._extract_features([])
        assert features.shape == (0, 8)

    def test_byte_entropy_for_uniform_bytes(self):
        assert IForestAuxDetector._byte_entropy("FFFFFFFF") == 0.0

    def test_byte_entropy_for_varied_bytes(self):
        assert IForestAuxDetector._byte_entropy("0102030405") > 0.0
