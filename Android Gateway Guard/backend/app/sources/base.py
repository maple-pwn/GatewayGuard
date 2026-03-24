"""数据源抽象基类"""

import abc
import asyncio
from typing import AsyncIterator, List

from app.models.packet import UnifiedPacket


class DataSource(abc.ABC):
    """所有数据源的抽象基类。

    子类需实现 start/stop/read 三个核心方法。
    """

    def __init__(self):
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    @abc.abstractmethod
    async def start(self) -> None:
        """初始化并启动数据源（打开硬件接口/文件等）。"""

    @abc.abstractmethod
    async def stop(self) -> None:
        """停止并释放资源。"""

    @abc.abstractmethod
    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        """读取一批报文，非阻塞。

        返回空列表表示当前无新数据（而非数据源结束）。
        """

    async def read_stream(self, interval: float = 0.01) -> AsyncIterator[List[UnifiedPacket]]:
        """持续读取的异步生成器。"""
        while self._running:
            batch = await self.read()
            if batch:
                yield batch
            else:
                await asyncio.sleep(interval)
