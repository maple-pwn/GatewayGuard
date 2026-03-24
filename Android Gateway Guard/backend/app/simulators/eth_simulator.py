"""车载以太网流量模拟器

模拟SOME/IP协议通信和异常流量
"""

import random
import time
from typing import List

from app.models.packet import UnifiedPacket

# SOME/IP 服务定义: (service_id, method_id, src, dst, domain)
SOMEIP_SERVICES = [
    ("0x0100", "0x0001", "HU", "ADAS", "infotainment"),
    ("0x0100", "0x0002", "HU", "ADAS", "infotainment"),
    ("0x0200", "0x0001", "ADAS", "GW", "chassis"),
    ("0x0300", "0x0001", "TBOX", "GW", "body"),
    ("0x0300", "0x0002", "TBOX", "CLOUD", "body"),
    ("0x0400", "0x0001", "GW", "BCM", "body"),
    ("0x0500", "0x0001", "DIAG_ETH", "GW", "body"),
]


def generate_normal_eth(count: int = 80, base_time: float = None) -> List[UnifiedPacket]:
    """生成正常车载以太网流量"""
    if base_time is None:
        base_time = time.time()

    packets = []
    for i in range(count):
        svc = random.choice(SOMEIP_SERVICES)
        service_id, method_id, src, dst, domain = svc
        payload_len = random.randint(8, 128)

        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.02,
            protocol="ETH",
            source=src,
            destination=dst,
            msg_id=f"{service_id}.{method_id}",
            payload_hex="AA" * payload_len,
            payload_decoded={
                "service_id": service_id,
                "method_id": method_id,
                "msg_type": "REQUEST",
                "return_code": "E_OK",
                "length": payload_len,
            },
            domain=domain,
            metadata={"eth_type": "SOME/IP", "vlan": 10},
        ))
    return packets
