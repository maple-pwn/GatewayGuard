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

    def test_detect_without_training_raises_error(self):
        packets = _baseline_packets()
        try:
            self.service.detect(packets)
            assert False, "Expected RuntimeError"
        except RuntimeError as e:
            assert "not trained" in str(e).lower()

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


class TestRPMDetector:
    def test_rpm_out_of_range(self):
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector(max_rpm=8000)
        # RPM = (0x23 << 8 | 0x28) * 0.25 = 9000 * 0.25 = 2250 (within range)
        # RPM = (0xFF << 8 | 0xFF) * 0.25 = 65535 * 0.25 = 16383.75 (exceeds 8000)
        packets = [_make_packet(1.0, "0x0C0", "FFFF000000000000")]
        alerts = detector.detect(packets)
        assert len(alerts) == 1
        assert alerts[0].anomaly_type == "rpm_out_of_range"

    def test_rpm_spike(self):
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector(spike_threshold=2000)
        # First: RPM = (0x0F << 8 | 0xA0) * 0.25 = 4000 * 0.25 = 1000
        # Second: RPM = (0x2F << 8 | 0xA0) * 0.25 = 12192 * 0.25 = 3048 (spike = 2048)
        packets = [
            _make_packet(1.0, "0x0C0", "0FA0000000000000"),
            _make_packet(1.1, "0x0C0", "2FA0000000000000"),
        ]
        alerts = detector.detect(packets)
        assert any(a.anomaly_type == "rpm_spike" for a in alerts)


class TestGearDetector:
    def test_invalid_gear_state(self):
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector()
        # Gear byte 0xFF is invalid (valid: P/R/N/D/1-6)
        packets = [_make_packet(1.0, "0x130", "FF00000000000000")]
        alerts = detector.detect(packets)
        assert len(alerts) == 1
        assert alerts[0].anomaly_type == "invalid_gear_state"


class TestReplaySequenceDetector:
    def test_replay_detection(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=3)
        # Train with normal packets first
        training = [_make_packet(0.5, "0x100", "AAAAAAAAAAAAAAAA")]
        detector.fit(training)
        # Repeated sequence should trigger replay - need 6 packets:
        # First 3 build window, next 3 repeat it within 1.0s
        packets = [
            _make_packet(1.0, "0x100", "0102030405060708"),
            _make_packet(1.1, "0x100", "0102030405060708"),
            _make_packet(1.2, "0x100", "0102030405060708"),
            _make_packet(1.3, "0x100", "0102030405060708"),
            _make_packet(1.4, "0x100", "0102030405060708"),
            _make_packet(1.5, "0x100", "0102030405060708"),
        ]
        alerts = detector.detect(packets)
        assert len(alerts) >= 1
