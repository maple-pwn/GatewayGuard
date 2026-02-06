"""流量相关API路由"""

import json
import time
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.packet import PacketORM, PacketResponse, TrafficStats, UnifiedPacket
from app.simulators.can_simulator import (
    generate_normal_can, generate_dos_attack,
    generate_fuzzy_attack, generate_spoofing_attack,
)
from app.simulators.eth_simulator import generate_normal_eth
from app.simulators.v2x_simulator import generate_normal_v2x

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


async def _save_packets(packets: list[UnifiedPacket], db: AsyncSession):
    """将UnifiedPacket列表存入数据库"""
    for p in packets:
        orm = PacketORM(
            timestamp=p.timestamp,
            protocol=p.protocol,
            source=p.source,
            destination=p.destination,
            msg_id=p.msg_id,
            payload=bytes.fromhex(p.payload_hex) if p.payload_hex else b"",
            payload_decoded=json.dumps(p.payload_decoded, ensure_ascii=False),
            domain=p.domain,
            metadata_json=json.dumps(p.metadata, ensure_ascii=False),
        )
        db.add(orm)
    await db.commit()


@router.get("/stats", response_model=TrafficStats)
async def get_traffic_stats(db: AsyncSession = Depends(get_db)):
    """获取流量统计概览"""
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

    pps = 0.0
    if ts_min and ts_max and ts_max > ts_min:
        pps = (total or 0) / (ts_max - ts_min)

    return TrafficStats(
        total_packets=total or 0,
        can_count=can_count or 0,
        eth_count=eth_count or 0,
        v2x_count=v2x_count or 0,
        time_range_start=ts_min,
        time_range_end=ts_max,
        packets_per_second=round(pps, 2),
    )


@router.get("/packets")
async def get_packets(
    protocol: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """分页查询流量记录"""
    stmt = select(PacketORM).order_by(PacketORM.timestamp.desc())
    if protocol:
        stmt = stmt.where(PacketORM.protocol == protocol.upper())
    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "protocol": r.protocol,
            "source": r.source,
            "destination": r.destination,
            "msg_id": r.msg_id,
            "domain": r.domain,
            "payload_decoded": json.loads(r.payload_decoded) if r.payload_decoded else {},
        }
        for r in rows
    ]


@router.post("/simulate")
async def simulate_traffic(
    scenario: str = Query("normal", enum=["normal", "dos", "fuzzy", "spoofing", "mixed"]),
    count: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """生成模拟流量数据"""
    base_time = time.time()
    packets = []

    if scenario == "normal":
        packets.extend(generate_normal_can(count, base_time))
        packets.extend(generate_normal_eth(count // 2, base_time))
        packets.extend(generate_normal_v2x(count // 3, base_time))
    elif scenario == "dos":
        packets.extend(generate_normal_can(count // 2, base_time))
        packets.extend(generate_dos_attack(count, base_time))
    elif scenario == "fuzzy":
        packets.extend(generate_normal_can(count // 2, base_time))
        packets.extend(generate_fuzzy_attack(count, base_time))
    elif scenario == "spoofing":
        packets.extend(generate_normal_can(count // 2, base_time))
        packets.extend(generate_spoofing_attack(count, base_time))
    elif scenario == "mixed":
        packets.extend(generate_normal_can(count, base_time))
        packets.extend(generate_dos_attack(count // 3, base_time))
        packets.extend(generate_fuzzy_attack(count // 3, base_time))
        packets.extend(generate_spoofing_attack(count // 3, base_time))
        packets.extend(generate_normal_eth(count // 3, base_time))
        packets.extend(generate_normal_v2x(count // 4, base_time))

    await _save_packets(packets, db)
    return {"generated": len(packets), "scenario": scenario}


# ---- 实时采集控制 API ----

from app.services.collector import collector


@router.post("/collect/start")
async def start_collect(
    mode: str = Query(None, enum=["simulator", "can", "ethernet", "pcap", "multi"]),
):
    """启动实时流量采集"""
    return await collector.start(mode=mode)


@router.post("/collect/stop")
async def stop_collect():
    """停止实时流量采集"""
    return await collector.stop()


@router.get("/collect/status")
async def collect_status():
    """查询采集状态"""
    return collector.stats


@router.post("/import")
async def import_file(
    file_path: str = Query(..., description="PCAP/BLF/ASC 文件路径"),
    db: AsyncSession = Depends(get_db),
):
    """导入离线抓包文件"""
    from app.sources.pcap_source import PcapSource

    src = PcapSource(file_path=file_path)
    try:
        await src.start()
    except Exception as e:
        return {"error": str(e)}

    packets = await src.read(max_count=50000)
    await src.stop()

    await _save_packets(packets, db)
    return {"imported": len(packets), "file": file_path}
