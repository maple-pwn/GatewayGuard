"""异常检测引擎单元测试"""

import time
import pytest
from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.anomaly_detector import (
    RuleBasedDetector, IsolationForestDetector, AnomalyDetectorService,
)
from app.simulators.can_simulator import (
    generate_normal_can, generate_dos_attack,
    generate_fuzzy_attack, generate_spoofing_attack,
)


def _make_packet(**kwargs) -> UnifiedPacket:
    defaults = dict(
        timestamp=1000.0, protocol="CAN", source="ECM",
        destination="BROADCAST", msg_id="0x0C0",
        payload_hex="1A2B3C4D5E6F7A8B", domain="powertrain",
    )
    defaults.update(kwargs)
    return UnifiedPacket(**defaults)


class TestRuleBasedDetector:
    """规则引擎测试"""

    def setup_method(self):
        self.detector = RuleBasedDetector()

    def test_no_alerts_on_normal_traffic(self):
        packets = generate_normal_can(20, base_time=1000.0)
        alerts = self.detector.check(packets)
        # normal traffic may trigger some rules but should not be all critical
        for a in alerts:
            assert isinstance(a, AnomalyEvent)

    def test_frequency_anomaly_on_dos(self):
        # After fix: compares per-ID freq against per-ID average freq * threshold.
        # DoS floods one ID far above the per-ID average, so it should trigger.
        normal = generate_normal_can(50, base_time=1000.0)
        dos = generate_dos_attack(500, base_time=1000.0)
        packets = sorted(normal + dos, key=lambda p: p.timestamp)
        alerts = self.detector.check(packets)
        freq_alerts = [a for a in alerts if a.anomaly_type == "frequency_anomaly"]
        assert len(freq_alerts) > 0

    def test_unknown_id_on_fuzzy(self):
        packets = generate_fuzzy_attack(50, base_time=1000.0)
        alerts = self.detector.check(packets)
        id_alerts = [a for a in alerts if a.anomaly_type == "unknown_can_id"]
        assert len(id_alerts) > 0

    def test_payload_anomaly_on_spoofing(self):
        packets = generate_spoofing_attack(20, base_time=1000.0)
        alerts = self.detector.check(packets)
        payload_alerts = [a for a in alerts if a.anomaly_type == "payload_anomaly"]
        assert len(payload_alerts) > 0

    def test_empty_input(self):
        alerts = self.detector.check([])
        assert alerts == []

    def test_single_packet(self):
        alerts = self.detector.check([_make_packet()])
        assert isinstance(alerts, list)


class TestIsolationForestDetector:
    """Isolation Forest 检测器测试"""

    def setup_method(self):
        self.detector = IsolationForestDetector()

    def test_not_fitted_returns_empty(self):
        packets = generate_normal_can(10, base_time=1000.0)
        assert self.detector.predict(packets) == []

    def test_fit_and_predict(self):
        normal = generate_normal_can(200, base_time=1000.0)
        self.detector.fit(normal)
        assert self.detector.is_fitted is True
        results = self.detector.predict(normal)
        assert isinstance(results, list)

    def test_extract_features_shape(self):
        packets = generate_normal_can(10, base_time=1000.0)
        features = self.detector.extract_features(packets)
        assert features.shape == (10, 5)

    def test_extract_features_empty(self):
        features = self.detector.extract_features([])
        assert features.shape == (0, 5)

    def test_byte_entropy_uniform(self):
        entropy = IsolationForestDetector._byte_entropy("FFFFFFFF")
        assert entropy == 0.0

    def test_byte_entropy_varied(self):
        entropy = IsolationForestDetector._byte_entropy("0102030405")
        assert entropy > 0.0


class TestAnomalyDetectorService:
    """统一检测服务测试"""

    def setup_method(self):
        self.service = AnomalyDetectorService()

    def test_detect_without_training(self):
        packets = generate_normal_can(30, base_time=1000.0)
        alerts = self.service.detect(packets)
        assert isinstance(alerts, list)

    def test_train_then_detect(self):
        normal = generate_normal_can(200, base_time=1000.0)
        self.service.train(normal)
        assert self.service.ml_detector.is_fitted
        dos = generate_dos_attack(100, base_time=2000.0)
        mixed = normal[:50] + dos
        alerts = self.service.detect(mixed)
        assert len(alerts) > 0

    def test_alerts_sorted_by_confidence(self):
        normal = generate_normal_can(100, base_time=1000.0)
        dos = generate_dos_attack(100, base_time=1000.0)
        alerts = self.service.detect(normal + dos)
        for i in range(1, len(alerts)):
            assert alerts[i].confidence <= alerts[i - 1].confidence
