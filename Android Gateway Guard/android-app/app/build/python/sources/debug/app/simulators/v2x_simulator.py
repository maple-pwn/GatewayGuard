"""V2X通信流量模拟器

模拟V2I/V2V的BSM广播和异常流量
"""

import random
import time
from typing import List

from app.models.packet import UnifiedPacket

# V2X消息类型
V2X_MSG_TYPES = [
    ("BSM", "V2V"),    # Basic Safety Message
    ("MAP", "V2I"),    # 地图数据
    ("SPAT", "V2I"),   # 信号灯相位
    ("RSI", "V2I"),    # 路侧信息
]


def generate_normal_v2x(count: int = 60, base_time: float = None) -> List[UnifiedPacket]:
    """生成正常V2X通信流量"""
    if base_time is None:
        base_time = time.time()

    packets = []
    for i in range(count):
        msg_type, comm_type = random.choice(V2X_MSG_TYPES)

        if comm_type == "V2V":
            src = f"OBU_{random.randint(1, 20):03d}"
            dst = "BROADCAST"
        else:
            src = f"RSU_{random.randint(1, 5):02d}"
            dst = "OBU_001"

        lat = 31.2304 + random.uniform(-0.01, 0.01)
        lon = 121.4737 + random.uniform(-0.01, 0.01)
        speed = random.uniform(0, 120)

        packets.append(UnifiedPacket(
            timestamp=base_time + i * 0.1,
            protocol="V2X",
            source=src,
            destination=dst,
            msg_id=msg_type,
            payload_hex="",
            payload_decoded={
                "msg_type": msg_type,
                "comm_type": comm_type,
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "speed_kmh": round(speed, 1),
                "heading": random.randint(0, 359),
            },
            domain="v2x",
            metadata={"channel": "PC5", "frequency": "5.9GHz"},
        ))
    return packets
