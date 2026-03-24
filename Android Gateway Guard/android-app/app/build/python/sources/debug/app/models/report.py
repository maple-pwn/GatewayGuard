"""LLM分析报告数据模型"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from app.database import Base


# ---- SQLAlchemy ORM ----

class AnalysisReportORM(Base):
    __tablename__ = "analysis_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("anomaly_events.id"))
    report_type = Column(String(32))
    content = Column(Text)
    llm_model = Column(String(64))
    prompt_tokens = Column(Integer)
    completion_tokens = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatHistoryORM(Base):
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, index=True)
    role = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    tool_calls = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
