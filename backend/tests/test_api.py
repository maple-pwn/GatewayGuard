"""FastAPI 路由集成测试"""

import pytest
import pytest_asyncio
from typing import Any, cast
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db


@pytest_asyncio.fixture
async def client():
    await init_db()
    transport = ASGITransport(app=cast(Any, app))
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestRootAPI:
    @pytest.mark.asyncio
    async def test_root(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "GatewayGuard"


class TestTrafficAPI:
    @pytest.mark.asyncio
    async def test_get_stats(self, client):
        resp = await client.get("/api/traffic/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_packets" in data

    @pytest.mark.asyncio
    async def test_simulate_normal(self, client):
        resp = await client.post("/api/traffic/simulate?scenario=normal&count=20")
        assert resp.status_code == 200
        data = resp.json()
        assert data["generated"] > 0
        assert data["scenario"] == "normal"

    @pytest.mark.asyncio
    async def test_get_packets(self, client):
        # generate some data first
        await client.post("/api/traffic/simulate?scenario=normal&count=10")
        resp = await client.get("/api/traffic/packets?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) <= 5


class TestCollectorAPI:
    @pytest.mark.asyncio
    async def test_collect_status(self, client):
        resp = await client.get("/api/traffic/collect/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data

    @pytest.mark.asyncio
    async def test_collect_start_stop(self, client):
        resp = await client.post("/api/traffic/collect/start?mode=simulator")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "started" or "error" in data
        # stop it
        resp2 = await client.post("/api/traffic/collect/stop")
        assert resp2.status_code == 200


class TestAnomalyAPI:
    @pytest.mark.asyncio
    async def test_get_events_empty(self, client):
        resp = await client.get("/api/anomaly/events")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_detect(self, client):
        # generate data first
        await client.post("/api/traffic/simulate?scenario=mixed&count=50")
        resp = await client.post("/api/anomaly/detect?limit=100")
        assert resp.status_code == 200
        data = resp.json()
        assert "detected" in data

    @pytest.mark.asyncio
    async def test_detect_requires_explicit_training(self, client):
        await client.post("/api/traffic/simulate?scenario=mixed&count=50")

        resp = await client.post("/api/anomaly/detect?limit=100&with_aggregation=true")
        assert resp.status_code == 200
        data = resp.json()

        assert data["detected"] == 0
        assert data["events"] == 0
        assert data["aggregated_events"] == []
        assert "not trained" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_train_endpoint(self, client):
        await client.post("/api/traffic/simulate?scenario=mixed&count=60")
        resp = await client.post("/api/anomaly/train?limit=200")
        assert resp.status_code == 200
        data = resp.json()
        assert "trained" in data
        assert "packet_count" in data
        assert data["packet_count"] > 0

    @pytest.mark.asyncio
    async def test_events_record_type_filter(self, client):
        resp = await client.get("/api/anomaly/events?record_type=packet_alert")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "events" in data

    @pytest.mark.asyncio
    async def test_get_event_not_found_returns_404(self, client):
        resp = await client.get("/api/anomaly/events/99999999")
        assert resp.status_code == 404
        data = resp.json()
        assert data["detail"] == "Event not found"
