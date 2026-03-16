#!/usr/bin/env python3
"""Manual QA script for RPM/GEAR/Replay detectors."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.detectors.rpm_detector import RPMDetector
from app.services.detectors.gear_detector import GearDetector
from app.services.detectors.replay_sequence_detector import ReplaySequenceDetector
from app.models.packet import UnifiedPacket


def make_packet(ts: float, can_id: str, payload: str) -> UnifiedPacket:
    return UnifiedPacket(
        timestamp=ts,
        protocol="CAN",
        msg_id=can_id,
        payload_hex=payload,
        source="test",
        destination="test",
    )


print("=== RPM Detector QA ===")
rpm_det = RPMDetector()
# Normal RPM
p1 = make_packet(1.0, "0x0C0", "0BB80000000000")  # 3000 RPM
alerts = rpm_det.detect([p1])
print(f"Normal RPM (3000): {len(alerts)} alerts")

# Out of range
p2 = make_packet(2.0, "0x0C0", "7D000000000000")  # 8000 RPM
alerts = rpm_det.detect([p2])
print(
    f"High RPM (8000): {len(alerts)} alerts - {alerts[0].anomaly_type if alerts else 'none'}"
)

# Spike
p3 = make_packet(3.0, "0x0C0", "0BB80000000000")  # 3000 RPM
p4 = make_packet(3.1, "0x0C0", "1F400000000000")  # 8000 RPM (spike)
alerts = rpm_det.detect([p3, p4])
print(
    f"RPM spike (3000->8000): {len(alerts)} alerts - {[a.anomaly_type for a in alerts]}"
)

print("\n=== GEAR Detector QA ===")
gear_det = GearDetector()
# Valid gear
p5 = make_packet(4.0, "0x130", "0400000000000000")  # D
alerts = gear_det.detect([p5])
print(f"Valid gear (D): {len(alerts)} alerts")

# Invalid gear
p6 = make_packet(5.0, "0x130", "FF00000000000000")  # Invalid
alerts = gear_det.detect([p6])
print(
    f"Invalid gear (0xFF): {len(alerts)} alerts - {alerts[0].anomaly_type if alerts else 'none'}"
)

print("\n=== Replay Detector QA ===")
replay_det = ReplaySequenceDetector(window_size=3)
# Train
train = [make_packet(0.1, "0x100", "AAAAAAAAAAAAAAAA")]
replay_det.fit(train)
# Replay sequence
replay = [
    make_packet(1.0, "0x100", "0102030405060708"),
    make_packet(1.1, "0x100", "0102030405060708"),
    make_packet(1.2, "0x100", "0102030405060708"),
    make_packet(1.3, "0x100", "0102030405060708"),
    make_packet(1.4, "0x100", "0102030405060708"),
    make_packet(1.5, "0x100", "0102030405060708"),
]
alerts = replay_det.detect(replay)
print(
    f"Replay sequence (6 identical): {len(alerts)} alerts - {[a.anomaly_type for a in alerts]}"
)

print("\n=== QA Complete ===")
