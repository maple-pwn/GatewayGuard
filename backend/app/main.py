"""GatewayGuard - FastAPI 主入口"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers import traffic, anomaly, llm, system
from app.services.collector import collector

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    # 如果配置了自动启动采集，则在启动时开始采集
    if settings.sources.collector.enabled:
        logger.info("Auto-starting collector (mode=%s)", settings.sources.mode)
        await collector.start()

    yield

    # 优雅关闭采集器
    if collector.running:
        await collector.stop()


app = FastAPI(
    title="GatewayGuard",
    description="LLM驱动的智能网关网络流量分析与异常预警系统",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router)
app.include_router(anomaly.router)
app.include_router(llm.router)
app.include_router(system.router)


@app.get("/")
async def root():
    return {
        "name": "GatewayGuard",
        "version": "0.1.0",
        "description": "智能网关网络流量分析与异常预警系统",
    }
