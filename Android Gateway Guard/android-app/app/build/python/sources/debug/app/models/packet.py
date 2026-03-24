"""流量数据模型"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, LargeBinary, Text, DateTime
from app.database import Base


# ---- SQLAlchemy ORM 模型 ----

class PacketORM(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, index=True)
    source = Column(String(64))
    destination = Column(String(64))
    msg_id = Column(String(32))
    payload = Column(LargeBinary)
    payload_decoded = Column(Text)
    domain = Column(String(32))
    metadata_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


# ---- Pydantic Schema ----

class UnifiedPacket(BaseModel):
    timestamp: float
    protocol: str          # CAN / ETH / V2X
    source: str
    destination: str
    msg_id: str
    payload_hex: str = ""
    payload_decoded: dict = {}
    domain: str = ""       # powertrain / chassis / body / infotainment
    metadata: dict = {}


class PacketResponse(BaseModel):
    id: int
    timestamp: float
    protocol: str
    source: str
    destination: Optional[str] = None
    msg_id: str
    payload_decoded: Optional[dict] = None
    domain: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TrafficStats(BaseModel):
    total_packets: int = 0
    can_count: int = 0
    eth_count: int = 0
    v2x_count: int = 0
    time_range_start: Optional[float] = None
    time_range_end: Optional[float] = None
    packets_per_second: float = 0.0
