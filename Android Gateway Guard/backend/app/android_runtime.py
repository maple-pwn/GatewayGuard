"""Android runtime helpers for writable data and import validation."""

from __future__ import annotations

from pathlib import Path

from app.config import settings

ALLOWED_IMPORT_EXTENSIONS = {".pcap", ".pcapng", ".blf", ".asc"}


def runtime_home() -> Path:
    return Path(settings.runtime_home).resolve()


def imports_dir() -> Path:
    return Path(settings.imports_dir).resolve()


def logs_dir() -> Path:
    return Path(settings.logs_dir).resolve()


def is_subpath(base: Path, candidate: Path) -> bool:
    base = base.resolve()
    candidate = candidate.resolve()
    return base == candidate or base in candidate.parents


def ensure_import_path_allowed(file_path: str) -> Path:
    candidate = Path(file_path).expanduser().resolve()
    allowed_base = imports_dir()
    if not is_subpath(allowed_base, candidate):
        raise ValueError(
            f"Only files under app private imports dir are allowed: {allowed_base}"
        )
    if candidate.suffix.lower() not in ALLOWED_IMPORT_EXTENSIONS:
        raise ValueError(
            f"Unsupported import extension '{candidate.suffix}'. "
            "Supported: .pcap, .pcapng, .blf, .asc"
        )
    if not candidate.is_file():
        raise ValueError(f"Import file does not exist: {candidate}")
    return candidate


def read_recent_log_lines(filename: str = "backend.log", lines: int = 120) -> str:
    target = logs_dir() / filename
    if not target.exists():
        return ""
    rows = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(rows[-max(lines, 1) :])

