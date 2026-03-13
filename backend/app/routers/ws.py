"""WebSocket 实时推送端点

提供 /ws/realtime 端点，前端通过 WebSocket 接收实时告警和统计数据。
"""

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.ws_manager import ws_manager
from app.services.collector import collector

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/realtime")
async def realtime_ws(ws: WebSocket):
    """实时数据推送 WebSocket 端点。"""
    await ws_manager.connect(ws)

    # 连接后立即推送当前状态快照
    await ws_manager.send_personal(ws, {
        "type": "stats_update",
        "data": collector.stats,
    })

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if msg.get("type") == "ping":
                await ws_manager.send_personal(ws, {"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(ws)
