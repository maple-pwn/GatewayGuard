"""以太网抓包数据源

基于 Scapy 抓取车载以太网 SOME/IP 流量。
"""

import asyncio
import logging
import time
from collections import deque
from typing import List

from app.models.packet import UnifiedPacket
from app.sources.base import DataSource

logger = logging.getLogger(__name__)


class EthernetSource(DataSource):
    """从网卡实时抓取以太网报文。"""

    def __init__(self, interface: str = "eth0",
                 bpf_filter: str = "udp port 30490"):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._buffer: deque[UnifiedPacket] = deque(maxlen=10000)
        self._sniffer = None
        self._sniffer_task = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._sniffer_task = asyncio.create_task(self._sniff_loop())
        logger.info("Ethernet source started: %s filter='%s'",
                     self.interface, self.bpf_filter)

    async def stop(self) -> None:
        self._running = False
        if self._sniffer and hasattr(self._sniffer, 'stop'):
            self._sniffer.stop()
        if self._sniffer_task:
            self._sniffer_task.cancel()
            try:
                await self._sniffer_task
            except asyncio.CancelledError:
                pass
        logger.info("Ethernet source stopped")

    async def read(self, max_count: int = 100) -> List[UnifiedPacket]:
        result = []
        for _ in range(min(max_count, len(self._buffer))):
            result.append(self._buffer.popleft())
        return result

    async def _sniff_loop(self) -> None:
        loop = asyncio.get_event_loop()
        try:
            from scapy.all import sniff
            await loop.run_in_executor(
                None,
                lambda: sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._handle_packet,
                    stop_filter=lambda _: not self._running,
                    store=False,
                ),
            )
        except Exception as e:
            if self._running:
                logger.error("Ethernet sniff error: %s", e)

    def _handle_packet(self, pkt) -> None:
        try:
            raw = bytes(pkt)
            packet = UnifiedPacket(
                timestamp=float(pkt.time) if hasattr(pkt, 'time') else time.time(),
                protocol="ETH",
                source=pkt.src if hasattr(pkt, 'src') else "unknown",
                destination=pkt.dst if hasattr(pkt, 'dst') else "unknown",
                msg_id=f"0x{len(raw):04X}",
                payload_hex=raw.hex().upper()[:256],
                payload_decoded={
                    "length": len(raw),
                    "eth_type": "SOME/IP",
                },
                domain="infotainment",
                metadata={"interface": self.interface},
            )
            self._buffer.append(packet)
        except Exception as e:
            logger.warning("Packet parse error: %s", e)
