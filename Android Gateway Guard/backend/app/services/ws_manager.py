"""WebSocket 连接管理器

维护所有活跃的 WebSocket 连接，提供广播能力。
用于实时推送异常告警和流量统计到前端。
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """WebSocket 连接管理器，支持广播推送。"""

    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._last_broadcast: float = 0.0
        self._min_interval: float = 0.1  # 最小广播间隔 100ms

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        logger.info("WebSocket connected, active=%d", self.active_count)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        logger.info("WebSocket disconnected, active=%d", self.active_count)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """向所有连接广播 JSON 消息。自动移除断开的连接。"""
        if not self._connections:
            return

        payload = json.dumps(message, ensure_ascii=False, default=str)
        dead: list[WebSocket] = []

        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self._connections.discard(ws)

    async def broadcast_throttled(
        self, message: Dict[str, Any], min_interval: float = 0.0
    ) -> None:
        """节流广播：距上次广播不足 min_interval 秒则跳过。"""
        interval = min_interval or self._min_interval
        now = time.monotonic()
        if now - self._last_broadcast < interval:
            return
        self._last_broadcast = now
        await self.broadcast(message)

    async def send_personal(self, ws: WebSocket, message: Dict[str, Any]) -> None:
        """向单个连接发送消息。"""
        try:
            payload = json.dumps(message, ensure_ascii=False, default=str)
            await ws.send_text(payload)
        except Exception:
            self._connections.discard(ws)


ws_manager = ConnectionManager()
