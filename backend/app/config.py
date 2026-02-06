"""GatewayGuard 配置管理 - 基于 config.yaml"""

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


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
    db_url: str = "sqlite+aiosqlite:///./gateway_guard.db"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    cors_origins: list = field(default_factory=lambda: ["http://localhost:5173"])
    llm: LLMConfig = field(default_factory=LLMConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    sources: SourcesConfig = field(default_factory=SourcesConfig)


def _load_yaml() -> dict:
    """读取 config.yaml，文件不存在则返回空字典。"""
    if CONFIG_PATH.is_file():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _apply_section(target, section: dict) -> None:
    """将字典中的键值写入 dataclass 实例，仅覆盖已有字段。"""
    for key, value in section.items():
        if hasattr(target, key):
            setattr(target, key, value)


def load_config() -> AppConfig:
    data = _load_yaml()
    config = AppConfig()

    # --- YAML 层：从文件加载 ---
    app_data = data.get("app", {})
    _apply_section(config, app_data)

    llm_data = data.get("llm", {})
    _apply_section(config.llm, llm_data)

    detector_data = data.get("detector", {})
    _apply_section(config.detector, detector_data)

    sources_data = data.get("sources", {})
    _apply_section(config.sources, sources_data)
    for sub in ("can", "ethernet", "pcap", "collector"):
        sub_data = sources_data.get(sub, {})
        _apply_section(getattr(config.sources, sub), sub_data)

    # --- 环境变量层：优先级最高，覆盖 YAML ---
    if env_key := os.getenv("OPENAI_API_KEY"):
        config.llm.openai_api_key = env_key
    if env_provider := os.getenv("LLM_PROVIDER"):
        config.llm.provider = env_provider
    if env_ollama := os.getenv("OLLAMA_URL"):
        config.llm.ollama_base_url = env_ollama

    return config


settings = load_config()
