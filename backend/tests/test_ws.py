"""WebSocket 实时推送端点测试"""

import json
import asyncio
import pytest
from starlette.testclient import TestClient
from app.main import app
from app.services.ws_manager import ConnectionManager


class TestWebSocketEndpoint:
    """WebSocket /ws/realtime 端点测试"""

    def test_connect_receives_stats(self):
        client = TestClient(app)
        with client.websocket_connect("/ws/realtime") as ws:
            data = ws.receive_json()
            assert data["type"] == "stats_update"
            assert "running" in data["data"]

    def test_ping_pong(self):
        client = TestClient(app)
        with client.websocket_connect("/ws/realtime") as ws:
            ws.receive_json()  # initial stats
            ws.send_json({"type": "ping"})
            resp = ws.receive_json()
            assert resp["type"] == "pong"

    def test_invalid_json_ignored(self):
        client = TestClient(app)
        with client.websocket_connect("/ws/realtime") as ws:
            ws.receive_json()  # initial stats
            ws.send_text("not json")
            # should not crash; send ping to verify connection alive
            ws.send_json({"type": "ping"})
            resp = ws.receive_json()
            assert resp["type"] == "pong"


class TestConnectionManager:
    """ConnectionManager 单元测试"""

    def test_initial_state(self):
        mgr = ConnectionManager()
        assert mgr.active_count == 0

    @pytest.mark.asyncio
    async def test_broadcast_no_connections(self):
        mgr = ConnectionManager()
        # should not raise
        await mgr.broadcast({"type": "test", "data": {}})

    @pytest.mark.asyncio
    async def test_broadcast_throttled_skips(self):
        mgr = ConnectionManager()
        mgr._last_broadcast = float("inf")
        await mgr.broadcast_throttled({"type": "test"}, min_interval=999)
        # no error, just skipped
