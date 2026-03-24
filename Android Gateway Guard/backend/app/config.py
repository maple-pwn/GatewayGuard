"""GatewayGuard configuration with Android runtime-aware paths."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.platform import get_home_dir, is_android_env


PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_TEMPLATE = PACKAGE_ROOT / "config.yaml.example"
RUNTIME_SUBDIRS = ("profiles", "imports", "reports", "logs")


def _runtime_home() -> Path:
    override = os.getenv("GATEWAY_GUARD_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if is_android_env():
        return get_home_dir().resolve()
    return PACKAGE_ROOT.resolve()


def _runtime_config_path(home: Path) -> Path:
    return home / "config.yaml"


def _ensure_runtime_layout() -> Path:
    home = _runtime_home()
    home.mkdir(parents=True, exist_ok=True)

    for folder in RUNTIME_SUBDIRS:
        (home / folder).mkdir(parents=True, exist_ok=True)

    config_path = _runtime_config_path(home)
    if not config_path.exists():
        source_candidates = (
            PACKAGE_ROOT / "config.yaml",
            DEFAULT_CONFIG_TEMPLATE,
        )
        for source in source_candidates:
            if source.exists():
                shutil.copyfile(source, config_path)
                break
        if not config_path.exists():
            config_path.write_text("app:\n  port: 8000\n", encoding="utf-8")

    return home


@dataclass
class LLMConfig:
    provider: str = "openai"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    max_tokens: int = 2048
    temperature: float = 0.3


@dataclass
class DetectorConfig:
    rule_enabled: bool = True
    ml_enabled: bool = True
    frequency_threshold: float = 3.0
    iforest_contamination: float = 0.05
    anomaly_window_size: int = 100
    unknown_id_policy: str = "strict_profile"
    enable_iforest_aux: bool = True
    enable_event_aggregation: bool = True
    enable_payload_profile: bool = True
    enable_replay_detector: bool = True
    enable_rpm_detector: bool = True
    enable_gear_detector: bool = True
    event_window_ms: float = 1000.0
    alert_cooldown_ms: float = 1000.0
    min_train_packets: int = 10
    burst_z_threshold: float = 4.0
    gap_z_threshold: float = 3.0
    temporal_window_size: int = 8
    rpm_can_id: str = "auto"
    gear_can_id: str = "auto"
    vehicle_profile: str = "default"
    profile_dir: str = ""

    @property
    def enable_iforest(self) -> bool:
        return self.enable_iforest_aux

    @enable_iforest.setter
    def enable_iforest(self, value: bool) -> None:
        self.enable_iforest_aux = bool(value)


@dataclass
class CANSourceConfig:
    interface: str = "vcan0"
    channel: str = "vcan0"
    bustype: str = "socketcan"
    bitrate: int = 500000


@dataclass
class EthernetSourceConfig:
    interface: str = "eth0"
    filter: str = "udp port 30490"


@dataclass
class PcapSourceConfig:
    file_path: str = ""


@dataclass
class CollectorConfig:
    enabled: bool = False
    interval_ms: int = 10
    buffer_size: int = 10000
    auto_detect: bool = True
    detect_batch_size: int = 200


@dataclass
class SourcesConfig:
    mode: str = "simulator"  # simulator / can / ethernet / pcap / multi
    can: CANSourceConfig = field(default_factory=CANSourceConfig)
    ethernet: EthernetSourceConfig = field(default_factory=EthernetSourceConfig)
    pcap: PcapSourceConfig = field(default_factory=PcapSourceConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)


@dataclass
class AppConfig:
    db_url: str = ""
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    cors_origins: list = field(default_factory=lambda: ["http://localhost:5173"])
    runtime_home: str = ""
    config_path: str = ""
    db_path: str = ""
    profiles_dir: str = ""
    imports_dir: str = ""
    reports_dir: str = ""
    logs_dir: str = ""
    llm: LLMConfig = field(default_factory=LLMConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    sources: SourcesConfig = field(default_factory=SourcesConfig)


def _load_yaml(config_path: Path) -> dict:
    if not config_path.is_file():
        return {}
    with open(config_path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _apply_section(target, section: dict) -> None:
    for key, value in section.items():
        if hasattr(target, key):
            setattr(target, key, value)


def _resolve_sqlite_url(db_url: str, runtime_home: Path) -> str:
    prefixes = ("sqlite+aiosqlite:///", "sqlite:///")
    selected_prefix = "sqlite+aiosqlite:///"

    if not db_url:
        return f"{selected_prefix}{(runtime_home / 'gateway_guard.db').resolve()}"

    for prefix in prefixes:
        if not db_url.startswith(prefix):
            continue
        selected_prefix = prefix
        path_part = db_url[len(prefix):]
        db_path = Path(path_part)
        if not db_path.is_absolute():
            db_path = (runtime_home / db_path).resolve()
        return f"{selected_prefix}{db_path}"
    return db_url


def _derive_sqlite_path(db_url: str) -> Path:
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if db_url.startswith(prefix):
            return Path(db_url[len(prefix):]).resolve()
    return Path("gateway_guard.db").resolve()


def _finalize_paths(config: AppConfig, runtime_home: Path) -> None:
    config.runtime_home = str(runtime_home)
    config.config_path = str((runtime_home / "config.yaml").resolve())
    config.imports_dir = str((runtime_home / "imports").resolve())
    config.reports_dir = str((runtime_home / "reports").resolve())
    config.logs_dir = str((runtime_home / "logs").resolve())
    config.profiles_dir = str((runtime_home / "profiles").resolve())

    config.db_url = _resolve_sqlite_url(config.db_url, runtime_home)
    config.db_path = str(_derive_sqlite_path(config.db_url))

    profile_dir = Path(config.detector.profile_dir) if config.detector.profile_dir else None
    if profile_dir is None or not profile_dir.is_absolute():
        config.detector.profile_dir = config.profiles_dir


def load_config() -> AppConfig:
    runtime_home = _ensure_runtime_layout()
    config_path = _runtime_config_path(runtime_home)

    data = _load_yaml(config_path)
    config = AppConfig()

    app_data = data.get("app", {})
    _apply_section(config, app_data)

    llm_data = data.get("llm", {})
    _apply_section(config.llm, llm_data)

    detector_data = data.get("detector", {})
    _apply_section(config.detector, detector_data)

    sources_data = data.get("sources", {})
    _apply_section(config.sources, sources_data)
    for sub in ("can", "ethernet", "pcap", "collector"):
        _apply_section(getattr(config.sources, sub), sources_data.get(sub, {}))

    if env_key := os.getenv("OPENAI_API_KEY"):
        config.llm.openai_api_key = env_key
    if env_provider := os.getenv("LLM_PROVIDER"):
        config.llm.provider = env_provider
    if env_ollama := os.getenv("OLLAMA_URL"):
        config.llm.ollama_base_url = env_ollama

    _finalize_paths(config, runtime_home)
    return config


settings = load_config()
