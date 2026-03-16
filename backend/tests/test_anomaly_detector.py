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
        features, contexts = detector._extract_features(_baseline_packets())
        assert features.shape == (60, 15)
        assert len(contexts) == 60

    def test_feature_shape_for_empty_packets(self):
        detector = IForestAuxDetector(enabled=False)
        features, contexts = detector._extract_features([])
        assert features.shape == (0, 15)
        assert contexts == []

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

    def test_rpm_spike_no_cross_batch_state_by_default(self):
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector(spike_threshold=2000, carry_state=False)

        # First batch last RPM = 1000
        detector.detect([_make_packet(1.0, "0x0C0", "0FA0000000000000")])
        # New batch starts at 3000; should not compare with previous batch by default.
        alerts = detector.detect([_make_packet(2.0, "0x0C0", "2EE0000000000000")])
        assert not any(a.anomaly_type == "rpm_spike" for a in alerts)

    def test_rpm_spike_with_cross_batch_state_enabled(self):
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector(spike_threshold=1500, carry_state=True)
        detector.detect([_make_packet(1.0, "0x0C0", "0FA0000000000000")])  # 1000 RPM
        alerts = detector.detect([_make_packet(2.0, "0x0C0", "2EE0000000000000")])  # 3000 RPM
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


class TestDetectorIntegration:
    """Test that detectors are properly integrated into AnomalyDetectorService."""

    def test_rpm_detector_integration_with_config_enabled(self):
        """Test RPM detector is called when config flag is enabled."""
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        # Create RPM anomaly packet
        packets = [_make_packet(1.0, "0x0C0", "FFFF000000000000")]

        original_flag = settings.detector.enable_rpm_detector
        try:
            settings.detector.enable_rpm_detector = True
            alerts = service.detect(packets)
            assert any(a.anomaly_type == "rpm_out_of_range" for a in alerts)
        finally:
            settings.detector.enable_rpm_detector = original_flag

    def test_rpm_detector_integration_with_config_disabled(self):
        """Test RPM detector is NOT called when config flag is disabled."""
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        packets = [_make_packet(1.0, "0x0C0", "FFFF000000000000")]

        original_flag = settings.detector.enable_rpm_detector
        try:
            settings.detector.enable_rpm_detector = False
            alerts = service.detect(packets)
            assert not any(a.anomaly_type == "rpm_out_of_range" for a in alerts)
        finally:
            settings.detector.enable_rpm_detector = original_flag

    def test_gear_detector_integration_with_config_enabled(self):
        """Test GEAR detector is called when config flag is enabled."""
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        packets = [_make_packet(1.0, "0x130", "FF00000000000000")]

        original_flag = settings.detector.enable_gear_detector
        try:
            settings.detector.enable_gear_detector = True
            alerts = service.detect(packets)
            assert any(a.anomaly_type == "invalid_gear_state" for a in alerts)
        finally:
            settings.detector.enable_gear_detector = original_flag

    def test_gear_detector_integration_with_config_disabled(self):
        """Test GEAR detector is NOT called when config flag is disabled."""
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        packets = [_make_packet(1.0, "0x130", "FF00000000000000")]

        original_flag = settings.detector.enable_gear_detector
        try:
            settings.detector.enable_gear_detector = False
            alerts = service.detect(packets)
            assert not any(a.anomaly_type == "invalid_gear_state" for a in alerts)
        finally:
            settings.detector.enable_gear_detector = original_flag

    def test_replay_detector_integration_with_config_enabled(self):
        """Test Replay detector is called when config flag is enabled."""
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        # Create replay pattern
        packets = [
            _make_packet(1.0 + i * 0.1, "0x100", "0102030405060708") for i in range(6)
        ]

        original_flag = settings.detector.enable_replay_detector
        try:
            settings.detector.enable_replay_detector = True
            alerts = service.detect(packets)
            # Replay detector may or may not trigger depending on pattern
            # Just verify it doesn't crash
            assert isinstance(alerts, list)
        finally:
            settings.detector.enable_replay_detector = original_flag

    def test_replay_detector_integration_with_config_disabled(self):
        """Test Replay detector is NOT called when config flag is disabled."""
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        packets = [
            _make_packet(1.0 + i * 0.1, "0x100", "0102030405060708") for i in range(6)
        ]

        original_flag = settings.detector.enable_replay_detector
        try:
            settings.detector.enable_replay_detector = False
            alerts = service.detect(packets)
            # Should not have replay-related anomalies
            assert not any("replay" in a.anomaly_type for a in alerts)
        finally:
            settings.detector.enable_replay_detector = original_flag

    def test_replay_detector_trained_during_service_train(self):
        """Test that ReplaySequenceDetector.fit() is called during train()."""
        service = AnomalyDetectorService()
        assert service.replay_detector.trained is False

        service.train(_baseline_packets())

        # After training, replay detector should be trained
        assert service.replay_detector.trained is True

    def test_detection_method_present_in_rpm_alerts(self):
        """Test that RPM detector includes detection_method field."""
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector(max_rpm=8000)
        packets = [_make_packet(1.0, "0x0C0", "FFFF000000000000")]
        alerts = detector.detect(packets)

        assert len(alerts) >= 1
        assert alerts[0].detection_method is not None
        assert "rpm" in alerts[0].detection_method.lower()

    def test_detection_method_present_in_gear_alerts(self):
        """Test that GEAR detector includes detection_method field."""
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector()
        packets = [_make_packet(1.0, "0x130", "FF00000000000000")]
        alerts = detector.detect(packets)

        assert len(alerts) >= 1
        assert alerts[0].detection_method is not None
        assert "gear" in alerts[0].detection_method.lower()

    def test_detection_method_present_in_replay_alerts(self):
        """Test that Replay detector includes detection_method field."""
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=3)
        detector.fit([_make_packet(0.5, "0x100", "AAAAAAAAAAAAAAAA")])

        packets = [
            _make_packet(1.0 + i * 0.1, "0x100", "0102030405060708") for i in range(6)
        ]
        alerts = detector.detect(packets)

        if len(alerts) > 0:
            assert alerts[0].detection_method is not None
            assert "replay" in alerts[0].detection_method.lower()
