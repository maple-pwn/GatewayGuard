"""真实 CAN 总线数据源

基于 python-can + SocketCAN 读取物理/虚拟 CAN 接口。
"""

import asyncio
import logging
import time
from collections import deque
from typing import List

from app.models.packet import UnifiedPacket
from app.services.traffic_parser import CANParser
from app.sources.base import DataSource

logger = logging.getLogger(__name__)


class CANSource(DataSource):
    """从 SocketCAN 接口实时读取 CAN 报文。

    依赖: python-can (已在 requirements.txt 中)
    硬件: 需要 SocketCAN 兼容的 CAN 适配器，或 vcan 虚拟接口用于测试。
    """

    def __init__(self, interface: str = "vcan0", channel: str = "vcan0",
                 bustype: str = "socketcan", bitrate: int = 500000):
        super().__init__()
        self.interface = interface
        self.channel = channel
        self.bustype = bustype
        self.bitrate = bitrate
        self._bus = None
        self._buffer: deque[UnifiedPacket] = deque(maxlen=10000)
        self._reader_task = None
        self._parser = CANParser()

    async def start(self) -> None:
        if self._running:
            return
        try:
            import can
            self._bus = can.Bus(
                channel=self.channel,
                bustype=self.bustype,
                bitrate=self.bitrate,
            )
            self._running = True
            self._reader_task = asyncio.create_task(self._read_loop())
            logger.info(
                "CAN source started: %s (%s, %d bps)",
                self.channel, self.bustype, self.bitrate,
            )
        except Exception as e:
            logger.error("Failed to start CAN source: %s", e)
            raise

    async def stop(self) -> None:
        self._running = False
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._bus:
            self._bus.shutdown()
            self._bus = None
        logger.info("CAN source stopped")

    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        result = []
        for _ in range(min(max_count, len(self._buffer))):
            result.append(self._buffer.popleft())
        return result

    async def _read_loop(self) -> None:
        """后台线程读取 CAN 报文并放入缓冲区。

        python-can 的 recv() 是阻塞调用，
        通过 run_in_executor 避免阻塞事件循环。
        """
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                msg = await loop.run_in_executor(
                    None, lambda: self._bus.recv(timeout=0.1)
                )
                if msg is None:
                    continue
                packet = self._msg_to_packet(msg)
                self._buffer.append(packet)
            except Exception as e:
                if self._running:
                    logger.warning("CAN read error: %s", e)
                    await asyncio.sleep(0.1)

    def _msg_to_packet(self, msg) -> UnifiedPacket:
        """将 python-can Message 转换为 UnifiedPacket。"""
        msg_id = f"0x{msg.arbitration_id:03X}"
        payload_hex = msg.data.hex().upper()
        return self._parser.parse(
            msg_id=msg_id,
            payload_hex=payload_hex,
            timestamp=msg.timestamp or time.time(),
        )
