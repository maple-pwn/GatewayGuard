"""CAN总线流量模拟器

模拟车载CAN网络的正常通信和攻击流量：
- 正常流量：周期性ECU报文（发动机、变速箱、车身控制等）
- 攻击流量：DoS、Fuzzy、Spoofing
"""

import random
import time
from typing import List

from app.models.packet import UnifiedPacket

# 正常CAN报文定义：(msg_id, source_ecu, domain, period_ms, dlc)
NORMAL_CAN_MESSAGES = [
    ("0x0C0", "ECM", "powertrain", 10, 8),     # 发动机转速/扭矩
    ("0x0C8", "ECM", "powertrain", 20, 8),     # 发动机温度
    ("0x130", "TCM", "powertrain", 20, 8),     # 变速箱档位
    ("0x180", "ABS", "chassis", 10, 8),        # 轮速
    ("0x1A0", "ESP", "chassis", 20, 8),        # 横摆角速度
    ("0x200", "EPS", "chassis", 10, 8),        # 转向角
    ("0x260", "BCM", "body", 100, 8),          # 车灯/车门状态
    ("0x280", "BCM", "body", 200, 4),          # 空调状态
    ("0x320", "ICM", "infotainment", 50, 8),   # 仪表盘显示
    ("0x3E0", "HU", "infotainment", 100, 8),   # 主机指令
    ("0x7DF", "DIAG", "body", 0, 8),           # OBD诊断广播
    ("0x7E0", "DIAG", "powertrain", 0, 8),     # 诊断请求
]


def _random_payload(dlc: int) -> str:
    return "".join(f"{random.randint(0, 255):02X}" for _ in range(dlc))


def _payload_from_bytes(byte_values: list[int], dlc: int) -> str:
    return "".join(f"{b & 0xFF:02X}" for b in byte_values[:dlc])


def _decode_engine_rpm(payload_hex: str) -> dict:
    b0 = int(payload_hex[0:2], 16)
    b1 = int(payload_hex[2:4], 16)
    rpm = ((b0 << 8) | b1) * 0.25
    return {"rpm": round(rpm, 1), "raw": payload_hex}


def _decode_gear(payload_hex: str) -> dict:
    gear_map = {
        0: "P",
        1: "R",
        2: "N",
        3: "D",
        4: "1",
        5: "2",
        6: "3",
        7: "4",
        8: "5",
        9: "6",
    }
    gear = gear_map.get(int(payload_hex[0:2], 16), "INVALID")
    return {"gear": gear, "raw": payload_hex}


def _encode_engine_rpm_payload(rpm: float, dlc: int, counter: int) -> str:
    raw = max(0, min(int(rpm / 0.25), 0xFFFF))
    payload = [(raw >> 8) & 0xFF, raw & 0xFF]
    while len(payload) < dlc:
        payload.append(random.randint(0, 255))
    if dlc >= 3:
        payload[2] = counter & 0xFF
    return _payload_from_bytes(payload, dlc)


def _encode_gear_payload(gear_byte: int, dlc: int, counter: int) -> str:
    payload = [gear_byte & 0xFF]
    while len(payload) < dlc:
        payload.append(random.randint(0, 255))
    if dlc >= 2:
        payload[1] = counter & 0xFF
    return _payload_from_bytes(payload, dlc)


def _normal_period_seconds(period_ms: int) -> float:
    if period_ms > 0:
        return period_ms / 1000.0
    return 0.5


def generate_normal_can(count: int = 100, base_time: float = None) -> List[UnifiedPacket]:
    """生成正常CAN流量"""
    if base_time is None:
        base_time = time.time()

    packets = []
    schedule = [
        {
            "msg": msg,
            "next_ts": base_time + random.uniform(0.0, _normal_period_seconds(msg[3])),
        }
        for msg in NORMAL_CAN_MESSAGES
    ]
    rpm = random.uniform(700.0, 1100.0)
    gear_byte = 0

    for i in range(count):
        idx = min(range(len(schedule)), key=lambda s_idx: schedule[s_idx]["next_ts"])
        msg_id, src, domain, period_ms, dlc = schedule[idx]["msg"]
        ts = schedule[idx]["next_ts"]

        base_period_s = _normal_period_seconds(period_ms)
        jitter_s = base_period_s * random.uniform(-0.05, 0.05)
        schedule[idx]["next_ts"] = ts + max(0.001, base_period_s + jitter_s)

        if msg_id == "0x0C0":
            rpm = min(4200.0, max(650.0, rpm + random.uniform(-120.0, 180.0)))
            if gear_byte in (0, 1, 2):
                if rpm > 1800.0:
                    rpm = max(1800.0, rpm - random.uniform(80.0, 260.0))
            payload = _encode_engine_rpm_payload(rpm, dlc, i)
            decoded = _decode_engine_rpm(payload)
        elif msg_id == "0x130":
            if random.random() < 0.12:
                if gear_byte in (0, 1, 2):
                    gear_byte = random.choice([2, 3])
                elif random.random() < 0.08:
                    gear_byte = random.choice([0, 1, 2])
                else:
                    gear_byte = min(9, max(3, gear_byte + random.choice([-1, 0, 1])))
            payload = _encode_gear_payload(gear_byte, dlc, i)
            decoded = _decode_gear(payload)
        else:
            payload = _random_payload(dlc)
            decoded = {"dlc": dlc, "raw": payload}

        packets.append(UnifiedPacket(
            timestamp=ts,
            protocol="CAN",
            source=src,
            destination="BROADCAST",
            msg_id=msg_id,
            payload_hex=payload,
            payload_decoded=decoded,
            domain=domain,
            metadata={"bus": "CAN-H", "bitrate": 500000},
        ))
    return packets


def generate_dos_attack(count: int = 500, base_time: float = None) -> List[UnifiedPacket]:
    """模拟DoS攻击：高频发送同一ID报文淹没总线"""
    if base_time is None:
        base_time = time.time()

    target_id = "0x000"
    packets = []
    for i in range(count):
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.0002,  # 极高频率
            protocol="CAN",
            source="ATTACKER",
            destination="BROADCAST",
            msg_id=target_id,
            payload_hex=_random_payload(8),
            payload_decoded={"attack": "dos", "dlc": 8},
            domain="unknown",
            metadata={"bus": "CAN-H", "bitrate": 500000, "attack": True},
        ))
    return packets


def generate_fuzzy_attack(count: int = 200, base_time: float = None) -> List[UnifiedPacket]:
    """模拟Fuzzy攻击：随机ID和随机负载"""
    if base_time is None:
        base_time = time.time()

    packets = []
    for i in range(count):
        rand_id = f"0x{random.randint(0, 0x7FF):03X}"
        rand_dlc = random.randint(1, 8)
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.005,
            protocol="CAN",
            source="ATTACKER",
            destination="BROADCAST",
            msg_id=rand_id,
            payload_hex=_random_payload(rand_dlc),
            payload_decoded={"attack": "fuzzy", "dlc": rand_dlc},
            domain="unknown",
            metadata={"bus": "CAN-H", "attack": True},
        ))
    return packets


def generate_spoofing_attack(count: int = 100, base_time: float = None) -> List[UnifiedPacket]:
    """模拟Spoofing攻击：伪装合法ECU发送篡改报文"""
    if base_time is None:
        base_time = time.time()

    target = random.choice(NORMAL_CAN_MESSAGES)
    msg_id, src, domain, _, dlc = target

    packets = []
    for i in range(count):
        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.02,
            protocol="CAN",
            source=src,
            destination="BROADCAST",
            msg_id=msg_id,
            payload_hex="FF" * dlc,
            payload_decoded={"attack": "spoofing", "spoofed_ecu": src},
            domain=domain,
            metadata={"bus": "CAN-H", "attack": True},
        ))
    return packets
