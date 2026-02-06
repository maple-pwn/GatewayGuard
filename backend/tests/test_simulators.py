"""CAN/ETH/V2X 模拟器单元测试"""

import time
import pytest
from app.models.packet import UnifiedPacket
from app.simulators.can_simulator import (
    generate_normal_can, generate_dos_attack,
    generate_fuzzy_attack, generate_spoofing_attack,
    NORMAL_CAN_MESSAGES,
)
from app.simulators.eth_simulator import generate_normal_eth
from app.simulators.v2x_simulator import generate_normal_v2x


class TestCANSimulator:
    """CAN 模拟器测试"""

    def test_normal_can_count(self):
        packets = generate_normal_can(50, base_time=1000.0)
        assert len(packets) == 50

    def test_normal_can_fields(self):
        packets = generate_normal_can(10, base_time=1000.0)
        for p in packets:
            assert isinstance(p, UnifiedPacket)
            assert p.protocol == "CAN"
            assert p.source in {m[1] for m in NORMAL_CAN_MESSAGES}
            assert p.msg_id in {m[0] for m in NORMAL_CAN_MESSAGES}
            assert p.destination == "BROADCAST"
            assert len(p.payload_hex) > 0

    def test_normal_can_timestamps_ascending(self):
        packets = generate_normal_can(20, base_time=1000.0)
        for i in range(1, len(packets)):
            assert packets[i].timestamp >= packets[i - 1].timestamp

    def test_dos_attack_high_frequency(self):
        packets = generate_dos_attack(100, base_time=1000.0)
        assert len(packets) == 100
        assert all(p.msg_id == "0x000" for p in packets)
        assert all(p.source == "ATTACKER" for p in packets)
        time_span = packets[-1].timestamp - packets[0].timestamp
        assert time_span < 0.1  # 100 packets in < 0.1s

    def test_fuzzy_attack_random_ids(self):
        packets = generate_fuzzy_attack(50, base_time=1000.0)
        assert len(packets) == 50
        ids = {p.msg_id for p in packets}
        # random IDs should produce multiple distinct values
        assert len(ids) > 1
        assert all(p.metadata.get("attack") for p in packets)

    def test_spoofing_attack_payload(self):
        packets = generate_spoofing_attack(20, base_time=1000.0)
        assert len(packets) == 20
        for p in packets:
            unique_bytes = set(
                p.payload_hex[i:i+2] for i in range(0, len(p.payload_hex), 2)
            )
            assert unique_bytes == {"FF"}


class TestETHSimulator:
    """以太网模拟器测试"""

    def test_normal_eth_count(self):
        packets = generate_normal_eth(30, base_time=1000.0)
        assert len(packets) == 30

    def test_normal_eth_protocol(self):
        packets = generate_normal_eth(10, base_time=1000.0)
        for p in packets:
            assert p.protocol == "ETH"
            assert isinstance(p, UnifiedPacket)


class TestV2XSimulator:
    """V2X 模拟器测试"""

    def test_normal_v2x_count(self):
        packets = generate_normal_v2x(20, base_time=1000.0)
        assert len(packets) == 20

    def test_normal_v2x_protocol(self):
        packets = generate_normal_v2x(10, base_time=1000.0)
        for p in packets:
            assert p.protocol == "V2X"
            assert isinstance(p, UnifiedPacket)
