"""异常事件数据模型"""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from app.database import Base


# ---- SQLAlchemy ORM ----


class AnomalyEventORM(Base):
    __tablename__ = "anomaly_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    anomaly_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    confidence = Column(Float)
    protocol = Column(String(16))
    source_node = Column(String(64))
    target_node = Column(String(64))
    description = Column(Text)
    raw_data = Column(Text)
    detection_method = Column(String(32))
    status = Column(String(16), default="open")
    created_at = Column(DateTime, default=datetime.utcnow)
    event_id = Column(String(32))
    packet_count = Column(Integer, default=1)
    vehicle_profile = Column(String(64))
    evidence = Column(Text)


# ---- Pydantic Schema ----


class AnomalyEvent(BaseModel):
    timestamp: float
    anomaly_type: str
    severity: str = "medium"
    confidence: float = 0.0
    protocol: str = ""
    source_node: str = ""
    target_node: str = ""
    description: str = ""
    detection_method: str = ""
    raw_packets: list = []
    event_id: Optional[str] = None
    packet_count: int = 1
    vehicle_profile: Optional[str] = None
    evidence: list = []


class AnomalyEventResponse(BaseModel):
    id: int
    timestamp: float
    anomaly_type: str
    severity: str
    confidence: Optional[float] = None
    protocol: Optional[str] = None
    source_node: Optional[str] = None
    target_node: Optional[str] = None
    description: Optional[str] = None
    detection_method: Optional[str] = None
    status: str = "open"
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AnomalyEventList(BaseModel):
    total: int
    events: List[AnomalyEventResponse]
