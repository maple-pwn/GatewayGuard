"""多协议流量解析服务

将CAN/ETH/V2X原始数据统一解析为UnifiedPacket
"""

import json
import time
from typing import List

from app.models.packet import UnifiedPacket


class CANParser:
    """CAN报文解析器"""

    KNOWN_IDS = {
        "0x0C0": ("ECM", "powertrain", "engine_rpm_torque"),
        "0x0C8": ("ECM", "powertrain", "engine_temp"),
        "0x130": ("TCM", "powertrain", "gear_status"),
        "0x180": ("ABS", "chassis", "wheel_speed"),
        "0x1A0": ("ESP", "chassis", "yaw_rate"),
        "0x200": ("EPS", "chassis", "steering_angle"),
        "0x260": ("BCM", "body", "light_door_status"),
        "0x280": ("BCM", "body", "ac_status"),
        "0x320": ("ICM", "infotainment", "dashboard"),
        "0x3E0": ("HU", "infotainment", "head_unit_cmd"),
        "0x7DF": ("DIAG", "body", "obd_broadcast"),
        "0x7E0": ("DIAG", "powertrain", "diag_request"),
    }

    def parse(self, msg_id: str, payload_hex: str, timestamp: float = None) -> UnifiedPacket:
        if timestamp is None:
            timestamp = time.time()

        ecu, domain, signal = self.KNOWN_IDS.get(
            msg_id, ("UNKNOWN", "unknown", "unknown")
        )
        dlc = len(payload_hex) // 2

        decoded = {"signal": signal, "dlc": dlc, "raw": payload_hex}
        if msg_id == "0x0C0" and dlc >= 2:
            b0 = int(payload_hex[0:2], 16)
            b1 = int(payload_hex[2:4], 16)
            decoded["rpm"] = round(((b0 << 8) | b1) * 0.25, 1)

        return UnifiedPacket(
            timestamp=timestamp,
            protocol="CAN",
            source=ecu,
            destination="BROADCAST",
            msg_id=msg_id,
            payload_hex=payload_hex,
            payload_decoded=decoded,
            domain=domain,
            metadata={"bus": "CAN-H", "bitrate": 500000},
        )


class EthernetParser:
    """车载以太网(SOME/IP)解析器"""

    def parse(self, service_id: str, method_id: str,
              src: str, dst: str, payload_hex: str,
              timestamp: float = None) -> UnifiedPacket:
        if timestamp is None:
            timestamp = time.time()

        length = len(payload_hex) // 2
        return UnifiedPacket(
            timestamp=timestamp,
            protocol="ETH",
            source=src,
            destination=dst,
            msg_id=f"{service_id}.{method_id}",
            payload_hex=payload_hex,
            payload_decoded={
                "service_id": service_id,
                "method_id": method_id,
                "msg_type": "REQUEST",
                "return_code": "E_OK",
                "length": length,
            },
            domain="infotainment",
            metadata={"eth_type": "SOME/IP", "vlan": 10},
        )


class TrafficParserService:
    """统一流量解析入口"""

    def __init__(self):
        self.can_parser = CANParser()
        self.eth_parser = EthernetParser()

    def parse_batch(self, raw_records: List[dict]) -> List[UnifiedPacket]:
        """批量解析原始记录"""
        packets = []
        for rec in raw_records:
            proto = rec.get("protocol", "").upper()
            ts = rec.get("timestamp", time.time())

            if proto == "CAN":
                pkt = self.can_parser.parse(
                    msg_id=rec["msg_id"],
                    payload_hex=rec.get("payload_hex", ""),
                    timestamp=ts,
                )
            elif proto == "ETH":
                pkt = self.eth_parser.parse(
                    service_id=rec.get("service_id", "0x0000"),
                    method_id=rec.get("method_id", "0x0000"),
                    src=rec.get("source", ""),
                    dst=rec.get("destination", ""),
                    payload_hex=rec.get("payload_hex", ""),
                    timestamp=ts,
                )
            elif proto == "V2X":
                pkt = UnifiedPacket(
                    timestamp=ts,
                    protocol="V2X",
                    source=rec.get("source", ""),
                    destination=rec.get("destination", "BROADCAST"),
                    msg_id=rec.get("msg_type", "BSM"),
                    payload_decoded=rec.get("payload_decoded", {}),
                    domain="v2x",
                    metadata=rec.get("metadata", {}),
                )
            else:
                continue
            packets.append(pkt)
        return packets
