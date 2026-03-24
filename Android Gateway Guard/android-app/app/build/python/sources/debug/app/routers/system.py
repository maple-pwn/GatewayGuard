"""System-related endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.android_runtime import read_recent_log_lines
from app.config import settings
from app.database import get_db
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM
from app.platform import is_android_env

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
async def get_system_status():
    return {
        "status": "running",
        "android": is_android_env(),
        "runtime_home": settings.runtime_home,
        "config_path": settings.config_path,
        "db_path": settings.db_path,
        "imports_dir": settings.imports_dir,
        "reports_dir": settings.reports_dir,
        "logs_dir": settings.logs_dir,
        "llm_provider": settings.llm.provider,
        "llm_model": (
            settings.llm.ollama_model
            if settings.llm.provider == "ollama"
            else settings.llm.openai_model
        ),
        "detector": {
            "rule_enabled": settings.detector.rule_enabled,
            "ml_enabled": settings.detector.ml_enabled,
            "iforest_enabled": settings.detector.enable_iforest_aux,
        },
    }


@router.get("/logs/recent")
async def get_recent_logs(lines: int = Query(120, ge=20, le=1000)):
    return {
        "lines": lines,
        "content": read_recent_log_lines(lines=lines),
    }


@router.delete("/clear-data")
async def clear_all_data(db: AsyncSession = Depends(get_db)):
    table_statements = {
        "chat_history": {
            "count": text("SELECT COUNT(*) FROM chat_history"),
            "delete": text("DELETE FROM chat_history"),
        },
        "analysis_reports": {
            "count": text("SELECT COUNT(*) FROM analysis_reports"),
            "delete": text("DELETE FROM analysis_reports"),
        },
        "anomaly_events": {
            "count": text("SELECT COUNT(*) FROM anomaly_events"),
            "delete": text("DELETE FROM anomaly_events"),
        },
        "packets": {
            "count": text("SELECT COUNT(*) FROM packets"),
            "delete": text("DELETE FROM packets"),
        },
    }

    counts = {}
    for table, statements in table_statements.items():
        result = await db.execute(statements["count"])
        counts[table] = result.scalar()
        await db.execute(statements["delete"])
    await db.commit()
    return {"cleared": counts, "message": "All data cleared"}


@router.delete("/clear-packets")
async def clear_packets_partial(
    protocol: Optional[str] = Query(None, description="CAN/ETH/V2X"),
    keep_recent: Optional[int] = Query(None, description="Keep latest N rows"),
    db: AsyncSession = Depends(get_db),
):
    count_q = select(func.count()).select_from(PacketORM)
    if protocol:
        count_q = count_q.where(PacketORM.protocol == protocol.upper())
    before = int((await db.execute(count_q)).scalar() or 0)

    if keep_recent and keep_recent > 0:
        cutoff_q = (
            select(PacketORM.id)
            .order_by(PacketORM.timestamp.desc())
            .offset(keep_recent)
            .limit(1)
        )
        cutoff_row = (await db.execute(cutoff_q)).scalar()
        if cutoff_row:
            await db.execute(
                text("DELETE FROM packets WHERE id <= :cutoff"),
                {"cutoff": cutoff_row},
            )
    elif protocol:
        await db.execute(
            text("DELETE FROM packets WHERE protocol = :proto"),
            {"proto": protocol.upper()},
        )
    else:
        return {"error": "protocol or keep_recent is required"}

    await db.commit()
    after = int(
        (await db.execute(select(func.count()).select_from(PacketORM))).scalar() or 0
    )

    return {
        "deleted": before - after,
        "remaining": after,
        "message": f"Deleted {before - after} packet records",
    }


@router.delete("/clear-anomalies")
async def clear_anomalies_partial(
    severity: Optional[str] = Query(
        None, description="critical/high/medium/low"
    ),
    keep_recent: Optional[int] = Query(None, description="Keep latest N rows"),
    db: AsyncSession = Depends(get_db),
):
    count_q = select(func.count()).select_from(AnomalyEventORM)
    if severity:
        count_q = count_q.where(AnomalyEventORM.severity == severity)
    before = int((await db.execute(count_q)).scalar() or 0)

    if keep_recent and keep_recent > 0:
        cutoff_q = (
            select(AnomalyEventORM.id)
            .order_by(AnomalyEventORM.timestamp.desc())
            .offset(keep_recent)
            .limit(1)
        )
        cutoff_row = (await db.execute(cutoff_q)).scalar()
        if cutoff_row:
            await db.execute(
                text("DELETE FROM anomaly_events WHERE id <= :cutoff"),
                {"cutoff": cutoff_row},
            )
    elif severity:
        await db.execute(
            text("DELETE FROM anomaly_events WHERE severity = :sev"),
            {"sev": severity},
        )
    else:
        return {"error": "severity or keep_recent is required"}

    await db.commit()
    after = int(
        (await db.execute(select(func.count()).select_from(AnomalyEventORM))).scalar()
        or 0
    )

    return {
        "deleted": before - after,
        "remaining": after,
        "message": f"Deleted {before - after} anomaly records",
    }

