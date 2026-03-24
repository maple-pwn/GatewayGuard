"""GatewayGuard FastAPI entrypoint."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.platform import is_android_env
from app.routers import anomaly, llm, system, traffic, ui, ws
from app.services.collector import collector

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    if settings.sources.collector.enabled:
        logger.info("Auto-starting collector (mode=%s)", settings.sources.mode)
        await collector.start()

    yield

    if collector.running:
        await collector.stop()


app = FastAPI(
    title="GatewayGuard",
    description="Traffic analysis and anomaly detection backend",
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
app.include_router(ws.router)
app.include_router(ui.router)


@app.get("/")
async def root():
    return {
        "name": "GatewayGuard",
        "version": "0.1.0",
        "runtime_home": settings.runtime_home,
        "android": is_android_env(),
    }


@app.get("/health/live")
async def health_live():
    return {"status": "alive"}


@app.get("/health/ready")
async def health_ready():
    return {
        "status": "ready",
        "db_path": settings.db_path,
        "collector_running": collector.running,
        "source_mode": settings.sources.mode,
        "android": is_android_env(),
    }
