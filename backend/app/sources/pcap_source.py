"""PCAP/BLF 离线文件回放数据源

支持导入 .pcap 和 .blf 格式的抓包文件进行离线分析。
"""

import logging
import time
from collections import deque
from typing import List

from app.models.packet import UnifiedPacket
from app.services.traffic_parser import CANParser
from app.sources.base import DataSource

logger = logging.getLogger(__name__)


class PcapSource(DataSource):
    """从 PCAP/BLF 文件读取报文。"""

    def __init__(self, file_path: str = ""):
        super().__init__()
        self.file_path = file_path
        self._buffer: deque[UnifiedPacket] = deque(maxlen=50000)
        self._parser = CANParser()

    async def start(self) -> None:
        if self._running:
            return
        if not self.file_path:
            raise ValueError("file_path is required")
        self._running = True
        self._load_file()
        logger.info("PCAP source loaded: %s (%d packets)",
                     self.file_path, len(self._buffer))

    async def stop(self) -> None:
        self._running = False
        self._buffer.clear()
        logger.info("PCAP source stopped")

    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        result = []
        for _ in range(min(max_count, len(self._buffer))):
            result.append(self._buffer.popleft())
        return result

    def _load_file(self) -> None:
        """根据文件扩展名选择加载方式。"""
        path = self.file_path.lower()
        if path.endswith(".blf"):
            self._load_blf()
        elif path.endswith(".pcap") or path.endswith(".pcapng"):
            self._load_pcap()
        elif path.endswith(".asc"):
            self._load_asc()
        else:
            raise ValueError(f"Unsupported file format: {path}")

    def _load_blf(self) -> None:
        """加载 Vector BLF 格式的 CAN 日志。"""
        try:
            import can
            with can.BLFReader(self.file_path) as reader:
                for msg in reader:
                    msg_id = f"0x{msg.arbitration_id:03X}"
                    payload_hex = msg.data.hex().upper()
                    pkt = self._parser.parse(
                        msg_id=msg_id,
                        payload_hex=payload_hex,
                        timestamp=msg.timestamp or time.time(),
                    )
                    self._buffer.append(pkt)
        except ImportError:
            raise RuntimeError("python-can is required for BLF")

    def _load_pcap(self) -> None:
        """加载 PCAP 格式的网络抓包。"""
        try:
            from scapy.all import rdpcap
            packets = rdpcap(self.file_path)
            for pkt in packets:
                raw = bytes(pkt)
                ts = float(pkt.time) if hasattr(pkt, 'time') else time.time()
                unified = UnifiedPacket(
                    timestamp=ts,
                    protocol="ETH",
                    source=getattr(pkt, 'src', 'unknown'),
                    destination=getattr(pkt, 'dst', 'unknown'),
                    msg_id=f"0x{len(raw):04X}",
                    payload_hex=raw.hex().upper()[:256],
                    payload_decoded={"length": len(raw)},
                    domain="unknown",
                    metadata={"source_file": self.file_path},
                )
                self._buffer.append(unified)
        except ImportError:
            raise RuntimeError("scapy is required for PCAP")

    def _load_asc(self) -> None:
        """加载 ASC 格式的 CAN 日志。"""
        try:
            import can
            with can.ASCReader(self.file_path) as reader:
                for msg in reader:
                    msg_id = f"0x{msg.arbitration_id:03X}"
                    payload_hex = msg.data.hex().upper()
                    pkt = self._parser.parse(
                        msg_id=msg_id,
                        payload_hex=payload_hex,
                        timestamp=msg.timestamp or time.time(),
                    )
                    self._buffer.append(pkt)
        except ImportError:
            raise RuntimeError("python-can is required for ASC")
