"""Realtime collector service."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from typing import List, Optional

from app.config import settings
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM, UnifiedPacket
from app.platform import is_android_env
from app.services.anomaly_detector import AnomalyDetectorService
from app.services.ws_manager import ws_manager
from app.sources.base import DataSource

logger = logging.getLogger(__name__)

ANDROID_DISABLED_MODES = {"can", "ethernet", "multi"}


def _validate_mode(mode: str) -> None:
    if is_android_env() and mode in ANDROID_DISABLED_MODES:
        raise ValueError(
            f"Mode '{mode}' is not supported on Android. "
            "Use simulator or offline import (pcap/pcapng; blf/asc experimental)."
        )


def _create_source(mode: str) -> DataSource:
    cfg = settings.sources
    _validate_mode(mode)

    if mode == "can":
        from app.sources.can_source import CANSource

        return CANSource(
            interface=cfg.can.interface,
            channel=cfg.can.channel,
            bustype=cfg.can.bustype,
            bitrate=cfg.can.bitrate,
        )
    if mode == "ethernet":
        from app.sources.ethernet_source import EthernetSource

        return EthernetSource(
            interface=cfg.ethernet.interface,
            bpf_filter=cfg.ethernet.filter,
        )
    if mode == "pcap":
        from app.sources.pcap_source import PcapSource

        return PcapSource(file_path=cfg.pcap.file_path)
    if mode == "simulator":
        from app.sources.simulator_source import SimulatorSource

        return SimulatorSource(scenario="normal", count=200)
    raise ValueError(f"Unknown source mode: {mode}")


class CollectorService:
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
        if self._running:
            return {"error": "Collector already running"}

        mode = mode or settings.sources.mode
        try:
            _validate_mode(mode)
        except ValueError as exc:
            return {"error": str(exc)}

        self._stats["source_mode"] = mode
        try:
            if mode == "multi":
                for m in ("can", "ethernet"):
                    try:
                        src = _create_source(m)
                        self._sources.append(src)
                    except Exception as exc:
                        logger.warning("Skip source %s: %s", m, exc)
            else:
                self._sources = [_create_source(mode)]
        except Exception as exc:
            self._sources.clear()
            return {"error": str(exc)}

        if not self._sources:
            return {"error": "No available source for selected mode"}

        for src in self._sources:
            await src.start()

        self._running = True
        self._stats["started_at"] = time.time()
        self._task = asyncio.create_task(self._collect_loop())
        logger.info("Collector started mode=%s sources=%d", mode, len(self._sources))
        return {"status": "started", "mode": mode, "sources": len(self._sources)}

    async def stop(self) -> dict:
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
        logger.info("Collector stopped total_collected=%d", self._stats["total_collected"])
        return {"status": "stopped", **self._stats}

    async def _collect_loop(self) -> None:
        while self._running:
            try:
                for src in self._sources:
                    batch = await src.read(max_count=self._detect_batch)
                    if batch:
                        self._pending.extend(batch)
                        self._stats["total_collected"] += len(batch)

                if self._auto_detect and len(self._pending) >= self._detect_batch:
                    asyncio.create_task(self._persist_and_detect())

                await ws_manager.broadcast_throttled(
                    {"type": "stats_update", "data": self.stats},
                    min_interval=1.0,
                )
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Collect loop error: %s", exc)
                await asyncio.sleep(1.0)

    async def _persist_and_detect(self) -> None:
        from app.database import async_session

        packets = []
        for _ in range(min(self._detect_batch, len(self._pending))):
            packets.append(self._pending.popleft())
        if not packets:
            return

        async with async_session() as db:
            for packet in packets:
                orm = PacketORM(
                    timestamp=packet.timestamp,
                    protocol=packet.protocol,
                    source=packet.source,
                    destination=packet.destination,
                    msg_id=packet.msg_id,
                    payload=bytes.fromhex(packet.payload_hex) if packet.payload_hex else b"",
                    payload_decoded=json.dumps(packet.payload_decoded, ensure_ascii=False),
                    domain=packet.domain,
                    metadata_json=json.dumps(packet.metadata, ensure_ascii=False),
                )
                db.add(orm)
            await db.commit()

            if not self._detector.is_trained:
                alerts = []
                events = []
            elif settings.detector.enable_event_aggregation:
                alerts, events = self._detector.detect_with_aggregation(packets)
            else:
                alerts = self._detector.detect(packets)
                events = []

            for alert in alerts:
                db.add(
                    AnomalyEventORM(
                        timestamp=alert.timestamp,
                        anomaly_type=alert.anomaly_type,
                        severity=alert.severity,
                        confidence=alert.confidence,
                        protocol=alert.protocol,
                        source_node=alert.source_node,
                        target_node=alert.target_node,
                        description=alert.description,
                        detection_method=alert.detection_method,
                        status="open",
                        event_id=alert.event_id,
                        packet_count=alert.packet_count,
                        vehicle_profile=alert.vehicle_profile,
                        evidence=json.dumps(alert.evidence, ensure_ascii=False)
                        if alert.evidence
                        else None,
                    )
                )

            for event in events:
                db.add(
                    AnomalyEventORM(
                        timestamp=event.first_seen,
                        anomaly_type=event.anomaly_type,
                        severity=event.severity,
                        confidence=event.confidence,
                        protocol="CAN",
                        source_node=event.involved_ids[0] if event.involved_ids else "",
                        target_node=",".join(event.involved_ids),
                        description=f"Aggregated {event.anomaly_type} covering {event.packet_count} alerts",
                        detection_method="event_aggregation",
                        status="open",
                        event_id=event.event_id,
                        packet_count=event.packet_count,
                        vehicle_profile=settings.detector.vehicle_profile,
                        evidence=json.dumps({"involved_ids": event.involved_ids}, ensure_ascii=False),
                    )
                )
            await db.commit()

            self._stats["total_anomalies"] += len(alerts)
            if alerts:
                await ws_manager.broadcast(
                    {
                        "type": "alerts",
                        "data": [
                            {
                                "anomaly_type": a.anomaly_type,
                                "severity": a.severity,
                                "confidence": a.confidence,
                                "protocol": a.protocol,
                                "source_node": a.source_node,
                                "description": a.description,
                                "detection_method": a.detection_method,
                                "timestamp": a.timestamp,
                            }
                            for a in alerts
                        ],
                    }
                )

            await ws_manager.broadcast({"type": "stats_update", "data": self.stats})


collector = CollectorService()

