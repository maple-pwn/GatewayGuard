"""FastAPI 路由集成测试"""

import time
import pytest
import pytest_asyncio
from typing import Any, cast
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db, async_session
from app.models.anomaly import AnomalyEventORM


@pytest_asyncio.fixture
async def client():
    await init_db()
    from app.routers.anomaly import detector

    detector.reset()
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
    async def test_status_defaults_to_untrained(self, client):
        resp = await client.get("/api/anomaly/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trained"] is False
        assert "vehicle_profile" in data
        assert "min_train_packets" in data

    @pytest.mark.asyncio
    async def test_get_events_empty(self, client):
        resp = await client.get("/api/anomaly/events")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_detect(self, client):
        # generate data and train first
        await client.post("/api/traffic/simulate?scenario=mixed&count=50")
        await client.post("/api/anomaly/train?limit=100")
        resp = await client.post("/api/anomaly/detect?limit=100")
        assert resp.status_code == 200
        data = resp.json()
        assert "detected" in data

    @pytest.mark.asyncio
    async def test_detect_requires_explicit_training(self, client):
        await client.post("/api/traffic/simulate?scenario=mixed&count=50")

        resp = await client.post("/api/anomaly/detect?limit=100&with_aggregation=true")
        assert resp.status_code == 428
        data = resp.json()
        assert "not trained" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_train_endpoint(self, client):
        await client.post("/api/traffic/simulate?scenario=mixed&count=60")
        resp = await client.post("/api/anomaly/train?limit=200")
        assert resp.status_code == 200
        data = resp.json()
        assert "trained" in data
        assert "packet_count" in data
        assert data["packet_count"] > 0
        assert "vehicle_profile" in data
        assert "min_train_packets" in data

    @pytest.mark.asyncio
    async def test_status_reports_trained_after_training(self, client):
        await client.post("/api/traffic/simulate?scenario=normal&count=120")
        await client.post("/api/anomaly/train?limit=200")

        resp = await client.get("/api/anomaly/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trained"] is True

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


async def _insert_event_for_llm() -> int:
    async with async_session() as session:
        event = AnomalyEventORM(
            timestamp=time.time(),
            anomaly_type="unit_test",
            severity="low",
            confidence=0.5,
            protocol="CAN",
            source_node="TEST_SRC",
            target_node="0x100",
            description="llm route test event",
            detection_method="unit_test",
            status="open",
        )
        session.add(event)
        await session.commit()
        await session.refresh(event)
        return int(event.id)


class TestLLMAPI:
    @pytest.mark.asyncio
    async def test_analyze_not_found_returns_404(self, client):
        resp = await client.post("/api/llm/analyze?event_id=99999999")
        assert resp.status_code == 404
        data = resp.json()
        assert data["detail"] == "Event not found"

    @pytest.mark.asyncio
    async def test_analyze_upstream_failure_returns_503(self, client, monkeypatch):
        from app.routers import llm as llm_router

        event_id = await _insert_event_for_llm()

        async def _fail(*args, **kwargs):
            raise RuntimeError("llm unavailable")

        monkeypatch.setattr(llm_router.llm, "analyze_anomaly", _fail)
        resp = await client.post(f"/api/llm/analyze?event_id={event_id}")

        assert resp.status_code == 503
        data = resp.json()
        assert data["detail"] == "LLM service unavailable"

    @pytest.mark.asyncio
    async def test_report_upstream_failure_returns_503(self, client, monkeypatch):
        from app.routers import llm as llm_router

        await _insert_event_for_llm()

        async def _fail(*args, **kwargs):
            raise RuntimeError("llm unavailable")

        monkeypatch.setattr(llm_router.llm, "generate_report", _fail)
        resp = await client.post("/api/llm/report?limit=5")

        assert resp.status_code == 503
        data = resp.json()
        assert data["detail"] == "LLM service unavailable"

    @pytest.mark.asyncio
    async def test_chat_upstream_failure_returns_503(self, client, monkeypatch):
        from app.routers import llm as llm_router

        async def _fail(*args, **kwargs):
            raise RuntimeError("llm unavailable")

        monkeypatch.setattr(llm_router.llm, "chat", _fail)
        resp = await client.post("/api/llm/chat?message=hello")

        assert resp.status_code == 503
        data = resp.json()
        assert data["detail"] == "LLM service unavailable"
