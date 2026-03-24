"""Chaquopy entrypoint: start FastAPI/Uvicorn in Android process."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from pathlib import Path
from typing import Any


_LOCK = threading.Lock()
_SERVER_THREAD: threading.Thread | None = None
_STATE: dict[str, Any] = {
    "started": False,
    "running": False,
    "host": "127.0.0.1",
    "port": 8000,
    "error": "",
}


def _configure_logging(home_dir: Path) -> None:
    logs_dir = home_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "backend.log"

    root = logging.getLogger()
    if root.handlers:
        return

    root.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)


def _serve(host: str, port: int) -> None:
    try:
        from app.main import app
        import uvicorn

        _STATE["running"] = True
        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            reload=False,
            workers=1,
            access_log=True,
            log_level="info",
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None
        asyncio.run(server.serve())
    except Exception as exc:  # pragma: no cover - startup path
        _STATE["error"] = str(exc)
        logging.exception("Backend server failed")
    finally:
        _STATE["running"] = False


def start_backend(home: str | None = None, host: str = "127.0.0.1", port: int = 8000) -> dict:
    """Start backend once and return startup state for Android shell."""
    with _LOCK:
        if _STATE["started"]:
            return dict(_STATE)

        home_path = Path(home or os.getenv("HOME") or ".").expanduser().resolve()
        os.environ["HOME"] = str(home_path)
        os.environ["GATEWAY_GUARD_ANDROID"] = "1"

        _configure_logging(home_path)
        logging.info("Starting GatewayGuard backend on %s:%d", host, port)

        _STATE["started"] = True
        _STATE["host"] = host
        _STATE["port"] = int(port)
        _STATE["error"] = ""

        global _SERVER_THREAD
        _SERVER_THREAD = threading.Thread(
            target=_serve,
            args=(host, int(port)),
            daemon=True,
            name="gatewayguard-uvicorn",
        )
        _SERVER_THREAD.start()

        return dict(_STATE)


def get_backend_state() -> dict:
    return dict(_STATE)

