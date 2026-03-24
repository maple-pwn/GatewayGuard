"""Platform detection helpers."""

from __future__ import annotations

import os
from pathlib import Path


def is_android_env() -> bool:
    """Return True when running inside Android app process."""
    return bool(
        os.getenv("GATEWAY_GUARD_ANDROID")
        or os.getenv("ANDROID_ARGUMENT")
        or os.getenv("ANDROID_PRIVATE")
    )


def get_home_dir() -> Path:
    """Resolve HOME in a cross-platform way."""
    home = os.getenv("HOME")
    if home:
        return Path(home).expanduser()
    return Path.home()

