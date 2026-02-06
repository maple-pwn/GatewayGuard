"""数据源抽象层测试"""

import pytest
import asyncio
from app.models.packet import UnifiedPacket
from app.sources.base import DataSource
from app.sources.simulator_source import SimulatorSource


class TestSimulatorSource:
    """SimulatorSource 测试"""

    @pytest.mark.asyncio
    async def test_start_stop(self):
        src = SimulatorSource(scenario="normal", count=50)
        assert src.running is False
        await src.start()
        assert src.running is True
        await src.stop()
        assert src.running is False

    @pytest.mark.asyncio
    async def test_read_returns_packets(self):
        src = SimulatorSource(scenario="normal", count=50)
        await src.start()
        packets = await src.read(max_count=20)
        assert len(packets) <= 20
        assert all(isinstance(p, UnifiedPacket) for p in packets)
        await src.stop()

    @pytest.mark.asyncio
    async def test_read_drains_buffer(self):
        src = SimulatorSource(scenario="normal", count=10)
        await src.start()
        first = await src.read(max_count=100)
        second = await src.read(max_count=100)
        assert len(first) > 0
        # second read should return fewer or zero (buffer drained)
        assert len(second) < len(first) or len(second) == 0
        await src.stop()

    @pytest.mark.asyncio
    async def test_scenarios(self):
        for scenario in ("normal", "dos", "fuzzy", "spoofing", "mixed"):
            src = SimulatorSource(scenario=scenario, count=30)
            await src.start()
            packets = await src.read(max_count=200)
            assert len(packets) > 0, f"scenario={scenario} produced no packets"
            await src.stop()
