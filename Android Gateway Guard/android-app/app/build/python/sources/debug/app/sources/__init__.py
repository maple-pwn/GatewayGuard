"""数据源抽象层

支持模拟器、真实CAN总线、以太网抓包、PCAP文件回放等多种数据源。
"""

from app.sources.base import DataSource
from app.sources.simulator_source import SimulatorSource
from app.sources.can_source import CANSource
from app.sources.ethernet_source import EthernetSource
from app.sources.pcap_source import PcapSource

__all__ = [
    "DataSource",
    "SimulatorSource",
    "CANSource",
    "EthernetSource",
    "PcapSource",
]
