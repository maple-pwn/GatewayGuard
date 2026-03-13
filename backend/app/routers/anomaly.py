"""异常检测相关API路由"""

import json
from typing import Optional, cast

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM, UnifiedPacket
from app.services.anomaly_detector import AnomalyDetectorService

router = APIRouter(prefix="/api/anomaly", tags=["anomaly"])

# 全局检测器实例
detector = AnomalyDetectorService()


@router.get("/events")
async def get_anomaly_events(
    severity: str = Query(None),
    status: str = Query(None),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """查询异常事件列表"""
    stmt = select(AnomalyEventORM).order_by(AnomalyEventORM.timestamp.desc())
    if severity:
        stmt = stmt.where(AnomalyEventORM.severity == severity)
    if status:
        stmt = stmt.where(AnomalyEventORM.status == status)

    count_stmt = select(func.count()).select_from(AnomalyEventORM)
    total = await db.scalar(count_stmt)

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {
        "total": total or 0,
        "events": [
            {
                "id": r.id,
                "timestamp": r.timestamp,
                "anomaly_type": r.anomaly_type,
                "severity": r.severity,
                "confidence": r.confidence,
                "protocol": r.protocol,
                "source_node": r.source_node,
                "target_node": r.target_node,
                "description": r.description,
                "detection_method": r.detection_method,
                "status": r.status,
            }
            for r in rows
        ],
    }


@router.get("/events/{event_id}")
async def get_anomaly_event_detail(
    event_id: int,
    db: AsyncSession = Depends(get_db),
):
    """获取异常事件详情"""
    result = await db.execute(
        select(AnomalyEventORM).where(AnomalyEventORM.id == event_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        return {"error": "Event not found"}
    raw_data = cast(Optional[str], row.raw_data)
    return {
        "id": row.id,
        "timestamp": row.timestamp,
        "anomaly_type": row.anomaly_type,
        "severity": row.severity,
        "confidence": row.confidence,
        "protocol": row.protocol,
        "source_node": row.source_node,
        "target_node": row.target_node,
        "description": row.description,
        "raw_data": json.loads(raw_data) if raw_data is not None else None,
        "detection_method": row.detection_method,
        "status": row.status,
    }


@router.post("/detect")
async def trigger_detection(
    limit: int = Query(500, le=2000),
    with_aggregation: Optional[bool] = Query(
        None,
        description="Whether to return aggregated event-level output; defaults to detector.enable_event_aggregation when omitted",
    ),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(PacketORM).order_by(PacketORM.timestamp.desc()).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    if not rows:
        return {"detected": 0, "message": "No traffic data available"}

    packets = []
    for r in rows:
        payload_bytes = cast(Optional[bytes], r.payload)
        payload_decoded_raw = cast(Optional[str], r.payload_decoded)
        source = cast(Optional[str], r.source)
        destination = cast(Optional[str], r.destination)
        msg_id = cast(Optional[str], r.msg_id)
        domain = cast(Optional[str], r.domain)
        packets.append(
            UnifiedPacket(
                timestamp=cast(float, r.timestamp),
                protocol=cast(str, r.protocol),
                source=source if source is not None else "",
                destination=destination if destination is not None else "",
                msg_id=msg_id if msg_id is not None else "",
                payload_hex=payload_bytes.hex() if payload_bytes is not None else "",
                payload_decoded=json.loads(payload_decoded_raw)
                if payload_decoded_raw is not None
                else {},
                domain=domain if domain is not None else "",
            )
        )

    if not detector.is_trained:
        normal = [
            p
            for p in packets
            if isinstance(getattr(p, "metadata", None), dict)
            and p.metadata.get("attack") is False
        ]
        if len(normal) > 20:
            detector.train(normal)

    effective_with_aggregation = (
        settings.detector.enable_event_aggregation
        if with_aggregation is None
        else with_aggregation
    )

    if effective_with_aggregation:
        alerts, events = detector.detect_with_aggregation(packets)
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
                event_id=a.event_id,
                packet_count=a.packet_count,
            )
            db.add(orm)
        await db.commit()
        return {
            "detected": len(alerts),
            "events": len(events),
            "aggregated_events": [
                {
                    "event_id": e.event_id,
                    "first_seen": e.first_seen,
                    "last_seen": e.last_seen,
                    "packet_count": e.packet_count,
                    "anomaly_type": e.anomaly_type,
                    "severity": e.severity,
                    "confidence": e.confidence,
                }
                for e in events
            ],
        }
    else:
        alerts = detector.detect(packets)
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
        return {
            "detected": len(alerts),
            "alerts": [
                {
                    "anomaly_type": a.anomaly_type,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "description": a.description,
                }
                for a in alerts
            ],
        }
