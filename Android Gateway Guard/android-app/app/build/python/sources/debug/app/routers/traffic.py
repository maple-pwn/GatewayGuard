"""Traffic endpoints."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.android_runtime import ensure_import_path_allowed
from app.database import get_db
from app.models.packet import PacketORM, TrafficStats, UnifiedPacket
from app.platform import is_android_env
from app.services.collector import collector
from app.simulators.can_simulator import (
    generate_dos_attack,
    generate_fuzzy_attack,
    generate_normal_can,
    generate_spoofing_attack,
)
from app.simulators.eth_simulator import generate_normal_eth
from app.simulators.v2x_simulator import generate_normal_v2x

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


async def _save_packets(packets: list[UnifiedPacket], db: AsyncSession):
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


def _packet_attack_type(payload_decoded: object, metadata: object) -> Optional[str]:
    if isinstance(payload_decoded, dict):
        attack = payload_decoded.get("attack")
        if attack:
            return str(attack)
    if isinstance(metadata, dict) and metadata.get("attack"):
        return "simulated_attack"
    return None


def _latest_timestamp(packets: list[UnifiedPacket], fallback: float) -> float:
    return max((packet.timestamp for packet in packets), default=fallback)


def _build_simulation_packets(
    scenario: str,
    count: int,
    base_time: float,
) -> list[UnifiedPacket]:
    packets: list[UnifiedPacket] = []

    if scenario == "normal":
        packets.extend(generate_normal_can(count, base_time))
        packets.extend(generate_normal_eth(count // 2, base_time))
        packets.extend(generate_normal_v2x(count // 3, base_time))
    elif scenario == "dos":
        normal_packets = generate_normal_can(count // 2, base_time)
        attack_base = _latest_timestamp(normal_packets, base_time) + 0.05
        packets.extend(normal_packets)
        packets.extend(generate_dos_attack(count, attack_base))
    elif scenario == "fuzzy":
        normal_packets = generate_normal_can(count // 2, base_time)
        attack_base = _latest_timestamp(normal_packets, base_time) + 0.05
        packets.extend(normal_packets)
        packets.extend(generate_fuzzy_attack(count, attack_base))
    elif scenario == "spoofing":
        normal_packets = generate_normal_can(count // 2, base_time)
        attack_base = _latest_timestamp(normal_packets, base_time) + 0.05
        packets.extend(normal_packets)
        packets.extend(generate_spoofing_attack(count, attack_base))
    elif scenario == "mixed":
        normal_packets: list[UnifiedPacket] = []
        normal_packets.extend(generate_normal_can(count, base_time))
        normal_packets.extend(generate_normal_eth(count // 3, base_time))
        normal_packets.extend(generate_normal_v2x(count // 4, base_time))
        attack_base = _latest_timestamp(normal_packets, base_time) + 0.05
        packets.extend(normal_packets)
        packets.extend(generate_dos_attack(count // 3, attack_base))
        packets.extend(generate_fuzzy_attack(count // 3, attack_base))
        packets.extend(generate_spoofing_attack(count // 3, attack_base))
    else:
        raise ValueError(f"Unsupported simulation scenario: {scenario}")

    return sorted(packets, key=lambda p: p.timestamp)


def _resolve_import_path(file_path: str) -> Path:
    if is_android_env():
        return ensure_import_path_allowed(file_path)

    resolved = Path(file_path).expanduser().resolve()
    if not resolved.exists():
        raise HTTPException(status_code=400, detail=f"Import file not found: {resolved}")
    if resolved.suffix.lower() not in {".pcap", ".pcapng", ".blf", ".asc"}:
        raise HTTPException(
            status_code=400,
            detail="Unsupported extension. Use .pcap/.pcapng/.blf/.asc",
        )
    return resolved


@router.get("/stats", response_model=TrafficStats)
async def get_traffic_stats(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count()).select_from(PacketORM))
    can_count = await db.scalar(
        select(func.count()).select_from(PacketORM).where(PacketORM.protocol == "CAN")
    )
    eth_count = await db.scalar(
        select(func.count()).select_from(PacketORM).where(PacketORM.protocol == "ETH")
    )
    v2x_count = await db.scalar(
        select(func.count()).select_from(PacketORM).where(PacketORM.protocol == "V2X")
    )
    ts_min = await db.scalar(select(func.min(PacketORM.timestamp)))
    ts_max = await db.scalar(select(func.max(PacketORM.timestamp)))

    packets_per_second = 0.0
    if ts_min and ts_max and ts_max > ts_min:
        packets_per_second = (total or 0) / (ts_max - ts_min)

    return TrafficStats(
        total_packets=total or 0,
        can_count=can_count or 0,
        eth_count=eth_count or 0,
        v2x_count=v2x_count or 0,
        time_range_start=ts_min,
        time_range_end=ts_max,
        packets_per_second=round(packets_per_second, 2),
    )


@router.get("/packets")
async def get_packets(
    protocol: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(PacketORM).order_by(PacketORM.timestamp.desc())
    if protocol:
        stmt = stmt.where(PacketORM.protocol == protocol.upper())
    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    packets = []
    for row in rows:
        payload_decoded = json.loads(row.payload_decoded) if row.payload_decoded else {}
        metadata = json.loads(row.metadata_json) if row.metadata_json else {}
        attack_type = _packet_attack_type(payload_decoded, metadata)
        packets.append(
            {
                "id": row.id,
                "timestamp": row.timestamp,
                "protocol": row.protocol,
                "source": row.source,
                "destination": row.destination,
                "msg_id": row.msg_id,
                "domain": row.domain,
                "payload_decoded": payload_decoded,
                "attack_type": attack_type,
                "is_attack": bool(attack_type),
            }
        )
    return packets


@router.post("/simulate")
async def simulate_traffic(
    scenario: str = Query("normal", enum=["normal", "dos", "fuzzy", "spoofing", "mixed"]),
    count: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    base_time = time.time()
    packets = _build_simulation_packets(scenario, count, base_time)
    attack_packets = sum(
        1
        for packet in packets
        if _packet_attack_type(packet.payload_decoded, packet.metadata)
    )

    await _save_packets(packets, db)
    return {"generated": len(packets), "attack_packets": attack_packets, "scenario": scenario}


@router.post("/collect/start")
async def start_collect(
    mode: str = Query(None, enum=["simulator", "can", "ethernet", "pcap", "multi"]),
):
    result = await collector.start(mode=mode)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/collect/stop")
async def stop_collect():
    result = await collector.stop()
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/collect/status")
async def collect_status():
    return collector.stats


@router.post("/import")
async def import_file(
    file_path: str = Query(..., description="Private app path to .pcap/.pcapng/.blf/.asc"),
    max_count: int = Query(50000, ge=1, le=200000),
    db: AsyncSession = Depends(get_db),
):
    from app.sources.pcap_source import PcapSource

    resolved = _resolve_import_path(file_path)
    source = PcapSource(file_path=str(resolved))

    try:
        await source.start()
        packets = await source.read(max_count=max_count)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Import failed: {exc}") from exc
    finally:
        await source.stop()

    await _save_packets(packets, db)
    return {"imported": len(packets), "file": str(resolved)}

