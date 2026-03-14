"""异常检测相关API路由"""

import json
from typing import Literal, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM, UnifiedPacket
from app.services.anomaly_detector import AnomalyDetectorService

router = APIRouter(prefix="/api/anomaly", tags=["anomaly"])

# 全局检测器实例
detector = AnomalyDetectorService()


def _parse_json_text(raw: Optional[str], fallback: object) -> object:
    if raw is None:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return fallback


def _record_type_for_row(row: AnomalyEventORM) -> str:
    method = cast(Optional[str], row.detection_method)
    return "aggregated_event" if method == "event_aggregation" else "packet_alert"


def _to_unified_packet(row: PacketORM) -> UnifiedPacket:
    payload_bytes = cast(Optional[bytes], row.payload)
    payload_decoded_raw = cast(Optional[str], row.payload_decoded)
    metadata_raw = cast(Optional[str], row.metadata_json)
    source = cast(Optional[str], row.source)
    destination = cast(Optional[str], row.destination)
    msg_id = cast(Optional[str], row.msg_id)
    domain = cast(Optional[str], row.domain)

    payload_decoded = _parse_json_text(payload_decoded_raw, {})
    metadata = _parse_json_text(metadata_raw, {})

    if not isinstance(payload_decoded, dict):
        payload_decoded = {}
    if not isinstance(metadata, dict):
        metadata = {}

    return UnifiedPacket(
        timestamp=cast(float, row.timestamp),
        protocol=cast(str, row.protocol),
        source=source if source is not None else "",
        destination=destination if destination is not None else "",
        msg_id=msg_id if msg_id is not None else "",
        payload_hex=payload_bytes.hex() if payload_bytes is not None else "",
        payload_decoded=payload_decoded,
        domain=domain if domain is not None else "",
        metadata=metadata,
    )


async def _load_latest_packets_chronological(
    db: AsyncSession, limit: int
) -> list[UnifiedPacket]:
    stmt = select(PacketORM).order_by(PacketORM.timestamp.desc()).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    if not rows:
        return []

    rows_chrono = sorted(rows, key=lambda r: cast(float, r.timestamp))
    return [_to_unified_packet(r) for r in rows_chrono]


def _serialize_alert_evidence(evidence: list) -> Optional[str]:
    if not evidence:
        return None
    return json.dumps(evidence, ensure_ascii=False)


def _packet_alert_filter():
    return or_(
        AnomalyEventORM.detection_method != "event_aggregation",
        AnomalyEventORM.detection_method.is_(None),
    )


@router.get("/events")
async def get_anomaly_events(
    severity: str = Query(None),
    status: str = Query(None),
    record_type: Literal["packet_alert", "aggregated_event"] | None = Query(None),
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
    if record_type == "aggregated_event":
        stmt = stmt.where(AnomalyEventORM.detection_method == "event_aggregation")
    elif record_type == "packet_alert":
        stmt = stmt.where(_packet_alert_filter())

    count_stmt = select(func.count()).select_from(AnomalyEventORM)
    if severity:
        count_stmt = count_stmt.where(AnomalyEventORM.severity == severity)
    if status:
        count_stmt = count_stmt.where(AnomalyEventORM.status == status)
    if record_type == "aggregated_event":
        count_stmt = count_stmt.where(
            AnomalyEventORM.detection_method == "event_aggregation"
        )
    elif record_type == "packet_alert":
        count_stmt = count_stmt.where(_packet_alert_filter())
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
                "record_type": _record_type_for_row(r),
                "event_id": r.event_id,
                "packet_count": r.packet_count,
                "vehicle_profile": r.vehicle_profile,
                "evidence": _parse_json_text(cast(Optional[str], r.evidence), []),
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
        raise HTTPException(status_code=404, detail="Event not found")
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
        "record_type": _record_type_for_row(row),
        "event_id": row.event_id,
        "packet_count": row.packet_count,
        "vehicle_profile": row.vehicle_profile,
        "evidence": _parse_json_text(cast(Optional[str], row.evidence), []),
    }


@router.post("/train")
async def trigger_training(
    limit: int = Query(2000, ge=100, le=20000),
    db: AsyncSession = Depends(get_db),
):
    packets = await _load_latest_packets_chronological(db, limit)
    if not packets:
        return {
            "trained": False,
            "packet_count": 0,
            "message": "No traffic data available for training",
        }

    detector.train(packets)
    if not detector.is_trained:
        return {
            "trained": False,
            "packet_count": len(packets),
            "message": "Insufficient packets for training",
        }

    return {
        "trained": True,
        "packet_count": len(packets),
        "vehicle_profile": settings.detector.vehicle_profile,
        "message": "Detector training completed",
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
    packets = await _load_latest_packets_chronological(db, limit)
    if not packets:
        return {"detected": 0, "message": "No traffic data available"}

    effective_with_aggregation = (
        settings.detector.enable_event_aggregation
        if with_aggregation is None
        else with_aggregation
    )

    if not detector.is_trained:
        if effective_with_aggregation:
            return {
                "detected": 0,
                "events": 0,
                "aggregated_events": [],
                "message": "Detector is not trained. Use explicit training flow first.",
            }
        return {
            "detected": 0,
            "alerts": [],
            "message": "Detector is not trained. Use explicit training flow first.",
        }

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
                vehicle_profile=settings.detector.vehicle_profile,
                evidence=_serialize_alert_evidence(a.evidence),
            )
            db.add(orm)

        for e in events:
            evidence = json.dumps({"involved_ids": e.involved_ids}, ensure_ascii=False)
            aggregated_orm = AnomalyEventORM(
                timestamp=e.first_seen,
                anomaly_type=e.anomaly_type,
                severity=e.severity,
                confidence=e.confidence,
                protocol="CAN",
                source_node=e.involved_ids[0] if e.involved_ids else "",
                target_node=",".join(e.involved_ids),
                description=(
                    f"Aggregated {e.anomaly_type} event covering {e.packet_count} alerts"
                ),
                detection_method="event_aggregation",
                status="open",
                event_id=e.event_id,
                packet_count=e.packet_count,
                vehicle_profile=settings.detector.vehicle_profile,
                evidence=evidence,
            )
            db.add(aggregated_orm)

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
                event_id=a.event_id,
                packet_count=a.packet_count,
                vehicle_profile=settings.detector.vehicle_profile,
                evidence=_serialize_alert_evidence(a.evidence),
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
