"""实时流量采集引擎

后台常驻协程，持续从 DataSource 读取数据 → 解析 → 存库 → 触发检测。
"""

import asyncio
import json
import logging
import time
from collections import deque
from typing import List, Optional

from app.config import settings
from app.models.packet import UnifiedPacket, PacketORM
from app.models.anomaly import AnomalyEventORM
from app.sources.base import DataSource
from app.services.anomaly_detector import AnomalyDetectorService

logger = logging.getLogger(__name__)


def _create_source(mode: str) -> DataSource:
    """根据配置创建对应的数据源实例。"""
    cfg = settings.sources
    if mode == "can":
        from app.sources.can_source import CANSource
        return CANSource(
            interface=cfg.can.interface,
            channel=cfg.can.channel,
            bustype=cfg.can.bustype,
            bitrate=cfg.can.bitrate,
        )
    elif mode == "ethernet":
        from app.sources.ethernet_source import EthernetSource
        return EthernetSource(
            interface=cfg.ethernet.interface,
            bpf_filter=cfg.ethernet.filter,
        )
    elif mode == "pcap":
        from app.sources.pcap_source import PcapSource
        return PcapSource(file_path=cfg.pcap.file_path)
    elif mode == "simulator":
        from app.sources.simulator_source import SimulatorSource
        return SimulatorSource(scenario="normal", count=200)
    else:
        raise ValueError(f"Unknown source mode: {mode}")


class CollectorService:
    """实时流量采集服务。

    从 DataSource 持续读取 → 存库 → 自动触发异常检测。
    """

    def __init__(self):
        self._sources: List[DataSource] = []
        self._task: Optional[asyncio.Task] = None
        self._detector = AnomalyDetectorService()
        self._running = False
        self._stats = {
            "total_collected": 0,
            "total_anomalies": 0,
            "started_at": None,
            "source_mode": None,
        }
        cfg = settings.sources.collector
        self._interval = cfg.interval_ms / 1000.0
        self._buffer_size = cfg.buffer_size
        self._auto_detect = cfg.auto_detect
        self._detect_batch = cfg.detect_batch_size
        self._pending: deque[UnifiedPacket] = deque(maxlen=self._buffer_size)

    @property
    def running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        return {**self._stats, "running": self._running}

    async def start(self, mode: Optional[str] = None) -> dict:
        """启动采集。mode 为 None 时使用配置文件中的默认值。"""
        if self._running:
            return {"error": "Collector already running"}

        mode = mode or settings.sources.mode
        self._stats["source_mode"] = mode

        if mode == "multi":
            for m in ("can", "ethernet"):
                try:
                    src = _create_source(m)
                    self._sources.append(src)
                except Exception as e:
                    logger.warning("Skip source %s: %s", m, e)
        else:
            self._sources = [_create_source(mode)]

        for src in self._sources:
            await src.start()

        self._running = True
        self._stats["started_at"] = time.time()
        self._task = asyncio.create_task(self._collect_loop())
        logger.info("Collector started, mode=%s, sources=%d", mode, len(self._sources))
        return {"status": "started", "mode": mode, "sources": len(self._sources)}

    async def stop(self) -> dict:
        """停止采集并释放资源。"""
        if not self._running:
            return {"error": "Collector not running"}

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        for src in self._sources:
            await src.stop()
        self._sources.clear()

        logger.info("Collector stopped, total=%d", self._stats["total_collected"])
        return {"status": "stopped", **self._stats}

    async def _collect_loop(self) -> None:
        """主采集循环：从所有数据源读取 → 缓冲 → 批量处理。"""
        while self._running:
            try:
                for src in self._sources:
                    batch = await src.read(max_count=self._detect_batch)
                    if batch:
                        self._pending.extend(batch)
                        self._stats["total_collected"] += len(batch)

                if self._auto_detect and len(self._pending) >= self._detect_batch:
                    await self._persist_and_detect()

                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Collect loop error: %s", e)
                await asyncio.sleep(1.0)

    async def _persist_and_detect(self) -> None:
        """将缓冲区报文存库并执行异常检测。"""
        from app.database import async_session

        packets = []
        for _ in range(min(self._detect_batch, len(self._pending))):
            packets.append(self._pending.popleft())

        if not packets:
            return

        async with async_session() as db:
            for p in packets:
                orm = PacketORM(
                    timestamp=p.timestamp,
                    protocol=p.protocol,
                    source=p.source,
                    destination=p.destination,
                    msg_id=p.msg_id,
                    payload=bytes.fromhex(p.payload_hex) if p.payload_hex else b"",
                    payload_decoded=json.dumps(
                        p.payload_decoded, ensure_ascii=False
                    ),
                    domain=p.domain,
                    metadata_json=json.dumps(p.metadata, ensure_ascii=False),
                )
                db.add(orm)
            await db.commit()

            if not self._detector.ml_detector.is_fitted:
                normal = [pk for pk in packets if not pk.metadata.get("attack")]
                if len(normal) > 20:
                    self._detector.train(normal)

            alerts = self._detector.detect(packets)
            for a in alerts:
                orm = AnomalyEventORM(
                    timestamp=a.timestamp,
                    anomaly_type=a.anomaly_type,
                    severity=a.severity,
                    confidence=a.confidence,
                    protocol=a.protocol,
                    source_node=a.source_node,
                    target_node=a.target_node,
                    description=a.description,
                    detection_method=a.detection_method,
                    status="open",
                )
                db.add(orm)
            await db.commit()
            self._stats["total_anomalies"] += len(alerts)

            if alerts:
                logger.info(
                    "Detected %d anomalies from %d packets",
                    len(alerts), len(packets),
                )


# 全局单例
collector = CollectorService()
