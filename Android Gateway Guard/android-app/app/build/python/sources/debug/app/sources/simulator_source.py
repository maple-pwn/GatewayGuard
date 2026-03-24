"""模拟器数据源封装

将现有的模拟器封装为 DataSource 接口，保持向后兼容。
"""

import logging
import time
from collections import deque
from typing import List

from app.models.packet import UnifiedPacket
from app.sources.base import DataSource

logger = logging.getLogger(__name__)


class SimulatorSource(DataSource):
    """封装现有模拟器为统一数据源接口。"""

    def __init__(self, scenario: str = "normal", count: int = 100):
        super().__init__()
        self.scenario = scenario
        self.count = count
        self._buffer: deque[UnifiedPacket] = deque(maxlen=10000)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._generate()
        logger.info(
            "Simulator source started: scenario=%s, count=%d",
            self.scenario, self.count,
        )

    async def stop(self) -> None:
        self._running = False
        self._buffer.clear()

    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        result = []
        for _ in range(min(max_count, len(self._buffer))):
            result.append(self._buffer.popleft())
        return result

    def _generate(self) -> None:
        """调用现有模拟器生成数据。"""
        from app.simulators.can_simulator import (
            generate_normal_can,
            generate_dos_attack,
            generate_fuzzy_attack,
            generate_spoofing_attack,
        )
        from app.simulators.eth_simulator import generate_normal_eth
        from app.simulators.v2x_simulator import generate_normal_v2x

        base_time = time.time()
        packets = []

        if self.scenario == "normal":
            packets.extend(generate_normal_can(self.count, base_time))
            packets.extend(generate_normal_eth(self.count // 2, base_time))
            packets.extend(generate_normal_v2x(self.count // 3, base_time))
        elif self.scenario == "dos":
            packets.extend(generate_normal_can(self.count // 2, base_time))
            packets.extend(generate_dos_attack(self.count, base_time))
        elif self.scenario == "fuzzy":
            packets.extend(generate_normal_can(self.count // 2, base_time))
            packets.extend(generate_fuzzy_attack(self.count, base_time))
        elif self.scenario == "spoofing":
            packets.extend(generate_normal_can(self.count // 2, base_time))
            packets.extend(generate_spoofing_attack(self.count, base_time))
        elif self.scenario == "mixed":
            packets.extend(generate_normal_can(self.count, base_time))
            packets.extend(generate_dos_attack(self.count // 3, base_time))
            packets.extend(generate_fuzzy_attack(self.count // 3, base_time))
            packets.extend(generate_spoofing_attack(self.count // 3, base_time))
            packets.extend(generate_normal_eth(self.count // 3, base_time))
            packets.extend(generate_normal_v2x(self.count // 4, base_time))

        self._buffer.extend(packets)
