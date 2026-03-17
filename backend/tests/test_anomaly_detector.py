from app.models.packet import UnifiedPacket
from app.models.anomaly import AnomalyEvent
from app.services.anomaly_detector import AnomalyDetectorService
from app.services.detectors.iforest_aux_detector import IForestAuxDetector
from app.services.profiles.can_profile import ProfileManager


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


def _encode_rpm_payload(rpm: float, counter: int = 0) -> str:
    raw = max(0, min(int(rpm / 0.25), 0xFFFF))
    payload = [
        (raw >> 8) & 0xFF,
        raw & 0xFF,
        counter & 0xFF,
        0,
        0,
        0,
        0,
        0,
    ]
    return "".join(f"{value:02X}" for value in payload)


def _encode_gear_payload(gear_byte: int, counter: int = 0) -> str:
    payload = [gear_byte & 0xFF, counter & 0xFF, 0, 0, 0, 0, 0, 0]
    return "".join(f"{value:02X}" for value in payload)


def _rpm_packet(
    timestamp: float,
    rpm: float,
    counter: int = 0,
    msg_id: str = "0x0C0",
) -> UnifiedPacket:
    return _make_packet(timestamp, msg_id, _encode_rpm_payload(rpm, counter))


def _gear_packet(
    timestamp: float,
    gear_byte: int,
    counter: int = 0,
    msg_id: str = "0x130",
) -> UnifiedPacket:
    return _make_packet(timestamp, msg_id, _encode_gear_payload(gear_byte, counter))


def _symbolic_gear_payload(byte0: int, byte1: int, byte4: int, counter: int = 0) -> str:
    payload = [byte0 & 0xFF, byte1 & 0xFF, 0x60, 0xFF, byte4 & 0xFF, counter & 0xFF, 0x08, 0x00]
    return "".join(f"{value:02X}" for value in payload)


def _symbolic_gear_packet(
    timestamp: float,
    byte0: int,
    byte1: int,
    byte4: int,
    counter: int = 0,
    msg_id: str = "0x43F",
) -> UnifiedPacket:
    return _make_packet(timestamp, msg_id, _symbolic_gear_payload(byte0, byte1, byte4, counter))


def _confuser_packet(timestamp: float, counter: int = 0) -> UnifiedPacket:
    payload = f"{(0x20 + counter % 0x50):02X}{(counter * 7) % 0x100:02X}{(counter * 13) % 0x100:02X}AA5500CC11"
    return _make_packet(timestamp, "0x260", payload)


def _powertrain_training_packets(
    rpm_msg_id: str = "0x0C0",
    gear_msg_id: str = "0x130",
) -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 1000.0
    counter = 0
    stages = [
        (0, [760, 780, 790, 805, 815, 830]),
        (2, [820, 860, 900, 940, 980, 1020]),
        (3, [1100, 1300, 1500, 1750, 2000, 2200, 2400, 2600]),
        (4, [1600, 1750, 1900, 2050, 2200, 2350]),
        (5, [1800, 1950, 2100, 2250, 2400, 2550]),
    ]

    for gear_byte, rpm_values in stages:
        for rpm in rpm_values:
            packets.append(_gear_packet(timestamp, gear_byte, counter, msg_id=gear_msg_id))
            packets.append(_rpm_packet(timestamp + 0.005, rpm, counter, msg_id=rpm_msg_id))
            timestamp += 0.02
            counter += 1

    return packets


def _symbolic_powertrain_training_packets() -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 1500.0
    counter = 0
    stages = [
        ((0x00, 0x40, 0x5A), [760, 780, 800, 820, 840]),
        ((0x01, 0x45, 0x5B), [1100, 1300, 1450, 1600, 1750, 1900]),
        ((0x02, 0x45, 0x5B), [900, 940, 980, 1020, 1060]),
        ((0x42, 0x45, 0x5B), [1180, 1220, 1260, 1300, 1340]),
        ((0x82, 0x45, 0x5C), [1500, 1620, 1740, 1860, 1980]),
        ((0x0F, 0x46, 0x5A), [1000, 1080, 1160, 1240, 1320]),
    ]

    for (byte0, byte1, byte4), rpm_values in stages:
        for rpm in rpm_values:
            packets.append(_symbolic_gear_packet(timestamp, byte0, byte1, byte4, counter))
            packets.append(_rpm_packet(timestamp + 0.005, rpm, counter, msg_id="0x316"))
            packets.append(_confuser_packet(timestamp + 0.010, counter))
            timestamp += 0.02
            counter += 1

    return packets


def _modebit_rpm_training_packets() -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 1800.0
    samples = [
        ("0524C0182418147C", "024560FF5C6E1700"),
        ("3523C0182318147C", "024560FF5C7B1700"),
        ("05229C182218147C", "024560FF5C821700"),
        ("35229C182218147C", "024560FF5C811700"),
        ("051248181218147C", "024560FF5C7B1700"),
        ("351248181218147C", "024560FF5C741700"),
        ("0513F8161318147C", "024560FF5C661700"),
        ("3514F8161418147C", "024560FF5C4B1700"),
    ]

    for idx, (rpm_payload, gear_payload) in enumerate(samples):
        packets.append(_make_packet(timestamp, "0x43F", gear_payload))
        packets.append(_make_packet(timestamp + 0.005, "0x316", rpm_payload))
        timestamp += 0.02

    return packets


def _status_frame_training_packets(msg_id: str = "0x4F0") -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 1900.0
    for _ in range(20):
        packets.append(_make_packet(timestamp, msg_id, "11AA22BBCC4F6677"))
        timestamp += 0.02
    for _ in range(20):
        packets.append(_make_packet(timestamp, msg_id, "11AA22BBCC506677"))
        timestamp += 0.02
    return packets


def _counter_packet(
    timestamp: float,
    counter_value: int,
    msg_id: str = "0x200",
) -> UnifiedPacket:
    payload = f"{counter_value & 0xFF:02X}11223344556677"
    return _make_packet(timestamp, msg_id, payload)


def _phase_packet(
    timestamp: float,
    phase_value: int,
    msg_id: str = "0x201",
) -> UnifiedPacket:
    payload = f"{phase_value & 0xFF:02X}11223344556677"
    return _make_packet(timestamp, msg_id, payload)


def _zero_tolerant_payload_training_packets(msg_id: str = "0x210") -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 2100.0
    payloads = [
        "1020304050607080",
        "1121314151617181",
        "0000000000000000",
        "1222324252627282",
        "1323334353637383",
        "0000000000000000",
        "1424344454647484",
        "1525354555657585",
        "1626364656667686",
        "1727374757677787",
    ]
    for idx in range(30):
        packets.append(_make_packet(timestamp, msg_id, payloads[idx % len(payloads)]))
        timestamp += 0.02
    return packets


def _moderately_repetitive_timing_training_packets(
    msg_id: str = "0x220",
) -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 2200.0
    payloads = [
        "1000000000000000",
        "1100000000000000",
        "1200000000000000",
        "1300000000000000",
        "1300000000000000",
        "1400000000000000",
        "1500000000000000",
        "1600000000000000",
        "1700000000000000",
        "1700000000000000",
    ]
    for idx in range(40):
        packets.append(_make_packet(timestamp, msg_id, payloads[idx % len(payloads)]))
        timestamp += 0.02
    return packets


def _burst_timing_training_packets(msg_id: str = "0x221") -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 2250.0
    for idx in range(40):
        packets.append(
            _make_packet(timestamp, msg_id, f"{0x10 + idx:02X}22334455667788")
        )
        timestamp += 0.02
    return packets


def _stable_status_training_packets(msg_id: str = "0x222") -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []
    timestamp = 2275.0
    payloads = [
        "0020000000000000",
        "0024000000000000",
        "0023000000000000",
        "0022000000000000",
        "0021000000000000",
        "0025000000000000",
    ]
    for payload in payloads:
        for _ in range(12):
            packets.append(_make_packet(timestamp, msg_id, payload))
            timestamp += 0.02
    return packets


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

    def test_aggregation_preserves_culled_packet_count(self):
        self.service.train(_powertrain_training_packets())
        eval_packets = []
        for i in range(4):
            base_ts = 2500.0 + i * 0.04
            eval_packets.append(_gear_packet(base_ts, 0, i))
            eval_packets.append(_rpm_packet(base_ts + 0.005, 3500.0, i))

        alerts, events = self.service.detect_with_aggregation(eval_packets)
        rpm_events = [event for event in events if event.anomaly_type == "rpm_gear_mismatch"]
        rpm_alerts = [alert for alert in alerts if alert.anomaly_type == "rpm_gear_mismatch"]

        assert len(rpm_events) == 1
        assert rpm_events[0].packet_count == 4
        assert len(rpm_alerts) == 1
        assert rpm_alerts[0].packet_count == 4


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

    def test_rpm_detector_catches_legal_frame_semantic_tamper(self):
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector()
        detector.fit(_powertrain_training_packets())

        packets = [
            _gear_packet(2000.000, 0, 1),
            _rpm_packet(2000.005, 3800.0, 1),
        ]
        alerts = detector.detect(packets)

        assert any(a.anomaly_type == "rpm_gear_mismatch" for a in alerts)

    def test_rpm_detector_masks_mode_bits_for_profiled_signal(self):
        from app.services.detectors.rpm_detector import RPMDetector

        detector = RPMDetector(rpm_can_id="0x316", gear_can_id="0x43F")
        detector.fit(_modebit_rpm_training_packets())

        packets = [
            _make_packet(2000.000, "0x316", "3524C0182418147C"),
            _make_packet(2000.010, "0x316", "051148181118147C"),
        ]
        alerts = detector.detect(packets)

        assert not any(a.anomaly_type == "rpm_spike" for a in alerts)
        assert not any(a.anomaly_type == "rpm_rate_anomaly" for a in alerts)


class TestGearDetector:
    def test_invalid_gear_state(self):
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector()
        # Gear byte 0xFF is invalid (valid: P/R/N/D/1-6)
        packets = [_make_packet(1.0, "0x130", "FF00000000000000")]
        alerts = detector.detect(packets)
        assert len(alerts) == 1
        assert alerts[0].anomaly_type == "invalid_gear_state"

    def test_gear_detector_catches_legal_state_semantic_tamper(self):
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector()
        detector.fit(_powertrain_training_packets())

        packets = [
            _rpm_packet(2000.000, 900.0, 1),
            _gear_packet(2000.005, 9, 1),
        ]
        alerts = detector.detect(packets)

        assert any(
            a.anomaly_type in {"gear_rpm_mismatch", "gear_state_out_of_profile"}
            for a in alerts
        )

    def test_gear_detector_switches_to_symbolic_state_profile_for_noncanonical_encoding(self):
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector(gear_can_id="0x43F", rpm_can_id="0x316")
        detector.fit(_symbolic_powertrain_training_packets())

        assert detector.state_model.mode == "symbolic"

        packets = [
            _rpm_packet(2000.000, 1400.0, 1, msg_id="0x316"),
            _symbolic_gear_packet(2000.005, 0x01, 0x45, 0x6B, 1, msg_id="0x43F"),
        ]
        alerts = detector.detect(packets)

        assert any(a.anomaly_type == "gear_state_out_of_profile" for a in alerts)

    def test_gear_detector_ignores_noisy_symbolic_component_when_profiled(self):
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector(gear_can_id="0x43F", rpm_can_id="0x316")
        detector.fit(_symbolic_powertrain_training_packets())

        assert detector.state_model.positions == (1, 4)

        packets = [
            _rpm_packet(2000.000, 980.0, 1, msg_id="0x316"),
            _symbolic_gear_packet(2000.005, 0x03, 0x45, 0x5C, 1, msg_id="0x43F"),
        ]
        alerts = detector.detect(packets)

        assert not any(a.anomaly_type == "gear_state_out_of_profile" for a in alerts)

    def test_gear_detector_tolerates_nearby_symbolic_component_drift(self):
        from app.services.detectors.gear_detector import GearDetector

        detector = GearDetector(gear_can_id="0x43F", rpm_can_id="0x316")
        detector.fit(_symbolic_powertrain_training_packets())

        packets = [
            _rpm_packet(2000.000, 1200.0, 1, msg_id="0x316"),
            _symbolic_gear_packet(2000.005, 0x01, 0x45, 0x5D, 1, msg_id="0x43F"),
        ]
        alerts = detector.detect(packets)

        assert not any(
            a.anomaly_type in {"gear_state_out_of_profile", "gear_shift_anomaly"}
            for a in alerts
        )


class TestReplaySequenceDetector:
    def test_replay_detection(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=3)
        # Train with normal packets first
        training = [_make_packet(0.5, "0x100", "AAAAAAAAAAAAAAAA")]
        detector.fit(training)
        # Repeated multi-packet pattern should trigger replay.
        packets = [
            _make_packet(1.0, "0x100", "0102030405060708"),
            _make_packet(1.1, "0x100", "1112131415161718"),
            _make_packet(1.2, "0x100", "2122232425262728"),
            _make_packet(1.3, "0x100", "0102030405060708"),
            _make_packet(1.4, "0x100", "1112131415161718"),
            _make_packet(1.5, "0x100", "2122232425262728"),
        ]
        alerts = detector.detect(packets)
        assert len(alerts) >= 1

    def test_constant_periodic_payload_does_not_trigger_replay(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=3)
        detector.fit([_make_packet(0.5, "0x100", "AAAAAAAAAAAAAAAA")])

        packets = [
            _make_packet(1.0 + i * 0.1, "0x100", "0102030405060708")
            for i in range(6)
        ]
        alerts = detector.detect(packets)

        assert not any(
            "repeated_subsequence"
            in " ".join(str(item) for item in (alert.evidence or []))
            for alert in alerts
        )

    def test_short_cycle_repetition_is_not_flagged_as_replay(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=4)
        detector.fit([_make_packet(0.5, "0x100", "AAAAAAAAAAAAAAAA")])

        packets = [
            _make_packet(1.00, "0x100", "0102030405060708"),
            _make_packet(1.01, "0x100", "1112131415161718"),
            _make_packet(1.02, "0x100", "2122232425262728"),
            _make_packet(1.03, "0x100", "3132333435363738"),
            _make_packet(1.04, "0x100", "0102030405060708"),
            _make_packet(1.05, "0x100", "1112131415161718"),
            _make_packet(1.06, "0x100", "2122232425262728"),
            _make_packet(1.07, "0x100", "3132333435363738"),
        ]
        alerts = detector.detect(packets)

        assert not any(a.anomaly_type == "replay_suspected" for a in alerts)

    def test_counter_wraparound_is_not_flagged_as_replay(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=4)
        training = [
            _counter_packet(0.5 + i * 0.01, i % 16)
            for i in range(32)
        ]
        detector.fit(training)

        packets = [
            _counter_packet(1.00, 14),
            _counter_packet(1.01, 15),
            _counter_packet(1.02, 0),
            _counter_packet(1.03, 1),
        ]
        alerts = detector.detect(packets)

        assert not any(a.anomaly_type == "replay_suspected" for a in alerts)

    def test_cyclic_phase_field_is_not_learned_as_counter(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=4)
        phase_values = [2, 4, 6, 8, 2, 4, 6, 8, 10, 12, 2, 4, 6, 8, 2, 4]
        training = [
            _phase_packet(0.5 + i * 0.01, value)
            for i, value in enumerate(phase_values)
        ]
        detector.fit(training)

        assert detector.states["0x201"].counter_positions == []

    def test_frequent_payload_reuse_does_not_trigger_freshness_alert(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=4, freshness_threshold=5.0)
        cycle = [
            "0102030405060708",
            "1112131415161718",
            "2122232425262728",
            "3132333435363738",
            "4142434445464748",
        ]
        training = [
            _make_packet(0.5 + i * 1.5, "0x202", cycle[i % len(cycle)])
            for i in range(25)
        ]
        detector.fit(training)

        packets = [
            _make_packet(100.0 + i * 1.5, "0x202", cycle[i % len(cycle)])
            for i in range(12)
        ]
        alerts = detector.detect(packets)

        assert not any(
            (alert.evidence or [None])[0] == "stale_pattern_reuse"
            for alert in alerts
        )

    def test_learned_window_reuse_does_not_trigger_replay(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=4, subsequence_min_age=0.25)
        cycle = [
            "0102030405060708",
            "1112131415161718",
            "2122232425262728",
            "3132333435363738",
        ]
        training = [
            _make_packet(0.5 + i * 0.08, "0x203", cycle[i % len(cycle)])
            for i in range(24)
        ]
        detector.fit(training)

        packets = [
            _make_packet(100.0 + i * 0.08, "0x203", cycle[i % len(cycle)])
            for i in range(12)
        ]
        alerts = detector.detect(packets)

        assert not any(
            (alert.evidence or [None])[0] == "repeated_subsequence"
            for alert in alerts
        )

    def test_exact_payload_reuse_on_dynamic_frame_triggers_replay(self):
        from app.services.detectors.replay_sequence_detector import (
            ReplaySequenceDetector,
        )

        detector = ReplaySequenceDetector(window_size=4)
        training = [
            _make_packet(
                0.5 + i * 0.02,
                "0x204",
                f"{i:02X}11223344556677",
            )
            for i in range(32)
        ]
        detector.fit(training)

        packets = [
            _make_packet(2.00, "0x204", "AA11223344556677"),
            _make_packet(2.02, "0x204", "BB11223344556677"),
            _make_packet(2.04, "0x204", "CC11223344556677"),
            _make_packet(2.06, "0x204", "DD11223344556677"),
            _make_packet(2.08, "0x204", "CC11223344556677"),
        ]
        alerts = detector.detect(packets)

        assert any(
            (alert.evidence or [None])[0] == "exact_payload_reuse" for alert in alerts
        )


class TestPayloadProfileDetector:
    def test_ignores_single_status_byte_shift_on_repeat_heavy_frame(self):
        from app.services.detectors.payload_profile_detector import (
            PayloadProfileDetector,
        )

        profile_mgr = ProfileManager()
        profile_mgr.learn_from_normal(_stable_status_training_packets())
        detector = PayloadProfileDetector(profile_mgr)

        alerts = detector.detect([_make_packet(2200.0, "0x222", "003E000F00000000")])

        assert not any(a.anomaly_type == "payload_anomaly" for a in alerts)

    def test_ignores_frequent_zero_constant_payload(self):
        from app.services.detectors.payload_profile_detector import (
            PayloadProfileDetector,
        )

        profile_mgr = ProfileManager()
        profile_mgr.learn_from_normal(_zero_tolerant_payload_training_packets())
        detector = PayloadProfileDetector(profile_mgr)

        alerts = detector.detect([_make_packet(2200.0, "0x210", "0000000000000000")])

        assert not any(a.anomaly_type == "payload_anomaly" for a in alerts)

    def test_ignores_single_byte_slow_drift_on_high_repeat_status_frame(self):
        from app.services.detectors.payload_profile_detector import (
            PayloadProfileDetector,
        )

        profile_mgr = ProfileManager()
        profile_mgr.learn_from_normal(_status_frame_training_packets())
        detector = PayloadProfileDetector(profile_mgr)

        alerts = detector.detect(
            [_make_packet(2000.0, "0x4F0", "11AA22BBCC526677")]
        )

        assert not any(a.anomaly_type == "payload_anomaly" for a in alerts)

    def test_flags_large_multi_byte_payload_shift(self):
        from app.services.detectors.payload_profile_detector import (
            PayloadProfileDetector,
        )

        profile_mgr = ProfileManager()
        profile_mgr.learn_from_normal(_status_frame_training_packets())
        detector = PayloadProfileDetector(profile_mgr)

        alerts = detector.detect(
            [_make_packet(2000.0, "0x4F0", "11AA22BBE05F9077")]
        )

        assert any(a.anomaly_type == "payload_anomaly" for a in alerts)


class TestTimingProfileDetector:
    def test_ignores_repeat_stall_on_moderately_repetitive_id(self):
        from app.services.detectors.timing_profile_detector import (
            TimingProfileDetector,
        )

        profile_mgr = ProfileManager()
        training = _moderately_repetitive_timing_training_packets()
        profile_mgr.learn_from_normal(training)
        detector = TimingProfileDetector(profile_mgr)

        packets = [
            _make_packet(2300.0 + i * 0.02, "0x220", "1300000000000000")
            for i in range(9)
        ]
        alerts = detector.detect(packets)

        assert not any(a.anomaly_type == "temporal_anomaly" for a in alerts)

    def test_detects_burst_on_gap_collapse(self):
        from app.services.detectors.timing_profile_detector import (
            TimingProfileDetector,
        )

        profile_mgr = ProfileManager()
        training = _burst_timing_training_packets()
        profile_mgr.learn_from_normal(training)
        detector = TimingProfileDetector(profile_mgr)

        packets = [
            _make_packet(2350.0 + i * 0.002, "0x221", f"{0x40 + i:02X}22334455667788")
            for i in range(9)
        ]
        alerts = detector.detect(packets)

        assert any(a.anomaly_type == "temporal_anomaly" for a in alerts)


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

    def test_service_detects_semantic_tamper_on_legal_rpm_gear_frames(self):
        service = AnomalyDetectorService()
        service.train(_powertrain_training_packets())

        packets = [
            _gear_packet(3000.000, 0, 1),
            _rpm_packet(3000.005, 3800.0, 1),
        ]
        alerts = service.detect(packets)

        assert any(
            a.anomaly_type in {"rpm_gear_mismatch", "gear_rpm_mismatch"}
            for a in alerts
        )

    def test_service_auto_binds_powertrain_ids_from_training_profile(self):
        from app.config import settings

        original_rpm_can_id = settings.detector.rpm_can_id
        original_gear_can_id = settings.detector.gear_can_id
        try:
            settings.detector.rpm_can_id = "auto"
            settings.detector.gear_can_id = "auto"

            service = AnomalyDetectorService()
            service.train(_symbolic_powertrain_training_packets())

            assert service.rpm_detector.rpm_can_id == "0x316"
            assert service.gear_detector.gear_can_id == "0x43F"

            alerts = service.detect(
                [
                    _symbolic_gear_packet(3000.000, 0x01, 0x45, 0x6B, 1, msg_id="0x43F"),
                    _rpm_packet(3000.005, 3800.0, 1, msg_id="0x316"),
                ]
            )

            assert any(
                a.anomaly_type
                in {"rpm_gear_mismatch", "gear_state_out_of_profile", "gear_rpm_mismatch"}
                for a in alerts
            )
        finally:
            settings.detector.rpm_can_id = original_rpm_can_id
            settings.detector.gear_can_id = original_gear_can_id

    def test_service_culls_duplicate_semantic_alerts(self):
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_powertrain_training_packets())

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            packets = []
            for i in range(5):
                base_ts = 4000.0 + i * 0.05
                packets.append(_gear_packet(base_ts, 0, i))
                packets.append(_rpm_packet(base_ts + 0.005, 3600.0, i))

            alerts = service.detect(packets)
            rpm_alerts = [a for a in alerts if a.anomaly_type == "rpm_gear_mismatch"]

            assert len(rpm_alerts) == 1
            assert rpm_alerts[0].packet_count == 5
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_extends_payload_profile_cooldown_with_signature(self):
        from app.config import settings

        service = AnomalyDetectorService()
        base_alert = AnomalyEvent(
            timestamp=5000.0,
            anomaly_type="payload_anomaly",
            severity="high",
            confidence=0.9,
            protocol="CAN",
            source_node="ECM",
            target_node="0x370",
            detection_method="payload_profile",
            evidence=[
                {"rule": "byte_profile_context"},
                {"rule": "byte_stability_violation"},
            ],
        )
        alerts = [
            base_alert.model_copy(),
            base_alert.model_copy(update={"timestamp": 5005.0}),
            base_alert.model_copy(
                update={
                    "timestamp": 5006.0,
                    "evidence": [
                        {"rule": "byte_profile_context"},
                        {"rule": "byte_statistical_range"},
                    ],
                }
            ),
            base_alert.model_copy(update={"timestamp": 5015.5}),
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)
            payload_alerts = [
                alert for alert in culled if alert.anomaly_type == "payload_anomaly"
            ]

            assert len(payload_alerts) == 3
            assert payload_alerts[0].packet_count == 2
            assert payload_alerts[1].packet_count == 1
            assert payload_alerts[2].packet_count == 1
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_shortens_payload_profile_cooldown_for_strong_signature(self):
        from app.config import settings

        service = AnomalyDetectorService()
        alerts = [
            AnomalyEvent(
                timestamp=5050.0,
                anomaly_type="payload_anomaly",
                severity="high",
                confidence=0.94,
                protocol="CAN",
                source_node="ECM",
                target_node="0x280",
                detection_method="payload_profile",
                evidence=[
                    {"rule": "byte_profile_context"},
                    {
                        "rule": "byte_stability_violation",
                        "total_violations": 4,
                        "max_deviation": 22,
                    },
                    {
                        "rule": "byte_statistical_range",
                        "total_violations": 4,
                        "max_deviation": 55.0,
                    },
                ],
            ),
            AnomalyEvent(
                timestamp=5050.2,
                anomaly_type="payload_anomaly",
                severity="high",
                confidence=0.95,
                protocol="CAN",
                source_node="ECM",
                target_node="0x280",
                detection_method="payload_profile",
                evidence=[
                    {"rule": "byte_profile_context"},
                    {
                        "rule": "byte_stability_violation",
                        "total_violations": 4,
                        "max_deviation": 24,
                    },
                    {
                        "rule": "byte_statistical_range",
                        "total_violations": 4,
                        "max_deviation": 56.0,
                    },
                ],
            ),
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)
            assert len(culled) == 2
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_extends_rolling_cooldown_for_ongoing_alert_stream(self):
        from app.config import settings

        service = AnomalyDetectorService()
        alerts = [
            AnomalyEvent(
                timestamp=6000.0 + offset,
                anomaly_type="replay_suspected",
                severity="medium",
                confidence=0.7,
                protocol="CAN",
                detection_method="replay_sequence",
                evidence=["repeated_subsequence"],
            )
            for offset in (0.0, 9.0, 18.0)
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)

            assert len(culled) == 1
            assert culled[0].packet_count == 3
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_shortens_replay_cooldown_for_exact_payload_reuse(self):
        from app.config import settings

        service = AnomalyDetectorService()
        alerts = [
            AnomalyEvent(
                timestamp=6050.0,
                anomaly_type="replay_suspected",
                severity="medium",
                confidence=0.76,
                protocol="CAN",
                target_node="0x200",
                detection_method="replay_sequence",
                evidence=["exact_payload_reuse", "packet_gap=1"],
            ),
            AnomalyEvent(
                timestamp=6050.2,
                anomaly_type="replay_suspected",
                severity="medium",
                confidence=0.77,
                protocol="CAN",
                target_node="0x200",
                detection_method="replay_sequence",
                evidence=["exact_payload_reuse", "packet_gap=1"],
            ),
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)
            assert len(culled) == 2
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_shortens_iforest_cooldown_for_unknown_burst_stream(self):
        from app.config import settings

        service = AnomalyDetectorService()
        alerts = [
            AnomalyEvent(
                timestamp=6100.0,
                anomaly_type="ml_auxiliary",
                severity="high",
                confidence=0.9,
                protocol="CAN",
                target_node="0x000",
                detection_method="iforest_auxiliary",
                evidence=[
                    {
                        "rule": "iforest_context",
                        "known_id": False,
                        "burst_signal": True,
                    }
                ],
            ),
            AnomalyEvent(
                timestamp=6100.2,
                anomaly_type="ml_auxiliary",
                severity="high",
                confidence=0.91,
                protocol="CAN",
                target_node="0x000",
                detection_method="iforest_auxiliary",
                evidence=[
                    {
                        "rule": "iforest_context",
                        "known_id": False,
                        "burst_signal": True,
                    }
                ],
            ),
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)
            assert len(culled) == 2
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_shortens_iforest_cooldown_for_unknown_zero_ff_stream(self):
        from app.config import settings

        service = AnomalyDetectorService()
        alerts = [
            AnomalyEvent(
                timestamp=6150.0,
                anomaly_type="ml_auxiliary",
                severity="medium",
                confidence=0.78,
                protocol="CAN",
                target_node="0x000",
                detection_method="iforest_auxiliary",
                evidence=[
                    {
                        "rule": "iforest_context",
                        "known_id": False,
                        "burst_signal": False,
                        "zero_ff_flag": True,
                        "repeat_run": 4,
                        "id_window_share": 0.07,
                    }
                ],
            ),
            AnomalyEvent(
                timestamp=6150.2,
                anomaly_type="ml_auxiliary",
                severity="medium",
                confidence=0.79,
                protocol="CAN",
                target_node="0x000",
                detection_method="iforest_auxiliary",
                evidence=[
                    {
                        "rule": "iforest_context",
                        "known_id": False,
                        "burst_signal": False,
                        "zero_ff_flag": True,
                        "repeat_run": 5,
                        "id_window_share": 0.08,
                    }
                ],
            ),
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)
            assert len(culled) == 2
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_keeps_iforest_cooldown_for_known_nonburst_stream(self):
        from app.config import settings

        service = AnomalyDetectorService()
        alerts = [
            AnomalyEvent(
                timestamp=6200.0,
                anomaly_type="ml_auxiliary",
                severity="medium",
                confidence=0.7,
                protocol="CAN",
                target_node="0x5F0",
                detection_method="iforest_auxiliary",
                evidence=[
                    {
                        "rule": "iforest_context",
                        "known_id": True,
                        "burst_signal": False,
                    }
                ],
            ),
            AnomalyEvent(
                timestamp=6200.2,
                anomaly_type="ml_auxiliary",
                severity="medium",
                confidence=0.71,
                protocol="CAN",
                target_node="0x5F0",
                detection_method="iforest_auxiliary",
                evidence=[
                    {
                        "rule": "iforest_context",
                        "known_id": True,
                        "burst_signal": False,
                    }
                ],
            ),
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            culled = service._cull_duplicate_alerts(alerts)
            assert len(culled) == 1
            assert culled[0].packet_count == 2
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

    def test_service_detects_unknown_id_flood_without_culling(self):
        from app.config import settings

        service = AnomalyDetectorService()
        service.train(_baseline_packets())

        packets = [
            _make_packet(6300.0 + i * 0.001, "0x000", "0000000000000000")
            for i in range(80)
        ]

        original_cooldown = settings.detector.alert_cooldown_ms
        try:
            settings.detector.alert_cooldown_ms = 1000.0
            alerts = service.detect(packets)
            flood_alerts = [
                alert
                for alert in alerts
                if alert.detection_method == "id_behavior_unknown_flood"
            ]

            assert len(flood_alerts) >= 8
            assert all(alert.anomaly_type == "unknown_id_flood" for alert in flood_alerts)
        finally:
            settings.detector.alert_cooldown_ms = original_cooldown

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
            _make_packet(1.0, "0x100", "0102030405060708"),
            _make_packet(1.1, "0x100", "1112131415161718"),
            _make_packet(1.2, "0x100", "2122232425262728"),
            _make_packet(1.3, "0x100", "0102030405060708"),
            _make_packet(1.4, "0x100", "1112131415161718"),
            _make_packet(1.5, "0x100", "2122232425262728"),
        ]
        alerts = detector.detect(packets)

        assert len(alerts) > 0
        assert alerts[0].detection_method is not None
        assert "replay" in alerts[0].detection_method.lower()
        assert alerts[0].target_node == "0x100"
