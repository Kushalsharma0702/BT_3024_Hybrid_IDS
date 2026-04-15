"""
packet_capture.py — Packet capture and normalization layer.

Abstracts scapy's sniff() into a clean interface:
  - Applies BPF filters at the kernel level (efficient)
  - Parses raw scapy packets into normalized dicts
  - Handles malformed packets without crashing
  - Supports both live capture and pcap replay (for testing)
  - Emits packet metadata dicts consumed by detection engines

Packet metadata schema:
    {
      "src_ip":       str,
      "dst_ip":       str,
      "src_port":     int,
      "dst_port":     int,
      "protocol":     str,        # TCP | UDP | ICMP | OTHER
      "size":         int,        # IP payload length in bytes
      "payload_bytes":bytes,      # raw payload (may be empty)
      "payload_str":  str,        # best-effort UTF-8 decode
      "tcp_flags":    str,        # scapy flag string, e.g. "SA"
      "user_agent":   str,        # HTTP User-Agent if parseable
      "timestamp":    float,      # epoch seconds
    }
"""

from __future__ import annotations

import logging
import re
import time
from typing import Callable, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# Lazy import: scapy is heavy and emits warnings during import
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff, rdpcap
    from scapy.packet import Packet
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed. Live capture unavailable; use pcap replay or simulation.")

_UA_RE = re.compile(rb"[Uu]ser-[Aa]gent:\s*([^\r\n]{1,256})")
_EMPTY_META: Dict = {}


def _parse_packet(pkt: "Packet") -> Optional[Dict]:
    """
    Parse a scapy Packet into a normalized metadata dict.
    Returns None if the packet should be discarded.
    """
    try:
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        src_ip: str = ip.src
        dst_ip: str = ip.dst

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        tcp_flags = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = pkt[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)

        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp_layer = pkt[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        # Payload
        payload_bytes: bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        # Best-effort decode
        try:
            payload_str = payload_bytes.decode("utf-8", errors="replace")
        except Exception:
            payload_str = ""

        # HTTP User-Agent extraction
        user_agent = ""
        if payload_bytes:
            m = _UA_RE.search(payload_bytes)
            if m:
                try:
                    user_agent = m.group(1).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

        size = len(ip.payload)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "payload_bytes": payload_bytes,
            "payload_str": payload_str,
            "tcp_flags": tcp_flags,
            "user_agent": user_agent,
            "timestamp": time.time(),
        }

    except Exception as exc:
        logger.debug("Packet parse error (discarding): %s", exc)
        return None


class PacketCapture:
    """
    Live packet capture using scapy's sniff().

    Usage:
        capture = PacketCapture(interface="eth0", bpf_filter="ip")
        for pkt_meta in capture.stream():
            process(pkt_meta)
    """

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = "ip",
        batch_size: int = 50,
        timeout: float = 1.0,
    ) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for live capture. Install with: pip install scapy")
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._batch_size = batch_size
        self._timeout = timeout
        self._running = False

        logger.info(
            "PacketCapture configured: iface=%s filter='%s' batch=%d",
            interface, bpf_filter, batch_size,
        )

    def stream(self) -> Generator[Dict, None, None]:
        """Continuously yield parsed packet metadata dicts."""
        self._running = True
        logger.info("Starting live capture on %s", self._interface)

        while self._running:
            try:
                packets = sniff(
                    iface=self._interface,
                    filter=self._bpf_filter,
                    count=self._batch_size,
                    timeout=self._timeout,
                )
                for pkt in packets:
                    meta = _parse_packet(pkt)
                    if meta:
                        yield meta
            except PermissionError:
                logger.critical("Insufficient privileges. Run as root or with CAP_NET_RAW.")
                raise
            except KeyboardInterrupt:
                break
            except Exception as exc:
                logger.error("Capture error: %s", exc)
                time.sleep(0.5)   # brief back-off before retry

    def stop(self) -> None:
        self._running = False


class PcapReplay:
    """
    Replays packets from a .pcap file. Useful for testing and validation.

    Usage:
        replay = PcapReplay("test_traffic.pcap")
        for pkt_meta in replay.stream():
            process(pkt_meta)
    """

    def __init__(self, pcap_path: str, replay_speed: float = 0.0) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for pcap replay.")
        self._path = pcap_path
        self._replay_speed = replay_speed   # 0.0 = as fast as possible

    def stream(self) -> Generator[Dict, None, None]:
        logger.info("Replaying pcap: %s", self._path)
        try:
            packets = rdpcap(self._path)
        except Exception as exc:
            logger.error("Failed to read pcap %s: %s", self._path, exc)
            return

        for pkt in packets:
            meta = _parse_packet(pkt)
            if meta:
                yield meta
                if self._replay_speed > 0:
                    time.sleep(self._replay_speed)


class SimulatedCapture:
    """
    Generates synthetic packet metadata for unit testing without scapy.

    Accepts a list of pre-built metadata dicts and yields them.
    """

    def __init__(self, packets: List[Dict]) -> None:
        self._packets = packets

    def stream(self) -> Generator[Dict, None, None]:
        for pkt in self._packets:
            pkt.setdefault("timestamp", time.time())
            yield pkt
