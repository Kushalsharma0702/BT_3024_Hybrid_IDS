"""
feature_extractor.py — Statistical feature engineering for anomaly detection.

Transforms raw packet metadata (from the capture layer) into a normalized
numeric feature vector suitable for IsolationForest inference.

Feature set:
  0  packet_size          — raw payload byte length
  1  packet_rate          — packets/second from src_ip (rolling 60 s window)
  2  unique_ports         — distinct dst ports contacted by src_ip
  3  tcp_flag_score       — weighted score of unusual TCP flag combos
  4  protocol_encoded     — ordinal: 1=TCP, 2=UDP, 3=ICMP, 0=other
  5  payload_entropy      — Shannon entropy of payload bytes (0–8 bits)
  6  burst_score          — short-window burst indicator (10 s sub-window)
  7  avg_payload_size     — exponential moving average of payload sizes per src

All features are float32 for numpy efficiency.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

import numpy as np

# TCP flag bit positions (scapy flag string encoding)
_TCP_FLAG_WEIGHTS: Dict[str, float] = {
    "S": 0.0,    # SYN  — normal
    "A": 0.0,    # ACK  — normal
    "SA": 0.0,   # SYN-ACK — normal
    "F": 0.1,    # FIN
    "R": 0.3,    # RST  — mildly suspicious in bulk
    "P": 0.0,    # PSH
    "U": 0.5,    # URG  — rarely legitimate
    "": 0.0,
    "FPU": 0.9,  # Xmas scan
    "FP": 0.4,
    "SFP": 0.7,  # invalid combo
    "SFPU": 1.0, # Christmas tree
}

_PROTO_ENCODE: Dict[str, int] = {
    "TCP": 1, "UDP": 2, "ICMP": 3,
}

# Per-source rolling state
_FlowWindow = Deque[float]  # timestamps of packets


class _SourceState:
    """Per-IP in-memory state for feature computation."""
    __slots__ = (
        "pkt_times", "short_times", "dst_ports",
        "payload_ema", "payload_ema_alpha",
    )

    def __init__(self) -> None:
        self.pkt_times: Deque[float] = deque()
        self.short_times: Deque[float] = deque()   # 10-s burst window
        self.dst_ports: Deque[Tuple[float, int]] = deque()  # (ts, port)
        self.payload_ema: float = 0.0
        self.payload_ema_alpha: float = 0.1


class FeatureExtractor:
    """
    Maintains per-source-IP flow state and extracts feature vectors.

    Usage:
        extractor = FeatureExtractor(flow_window=60.0)
        vec = extractor.extract(pkt_meta)   # returns np.ndarray shape (8,)
    """

    FEATURE_DIM: int = 8

    def __init__(self, flow_window_seconds: float = 60.0) -> None:
        self._window = flow_window_seconds
        self._short_window = 10.0
        self._state: Dict[str, _SourceState] = defaultdict(_SourceState)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def extract(self, pkt_meta: Dict) -> np.ndarray:
        """
        Extract feature vector from a parsed packet metadata dict.

        Expected keys:
            src_ip (str), dst_ip (str), dst_port (int),
            protocol (str), payload_bytes (bytes | None),
            tcp_flags (str), size (int)

        Returns np.ndarray of shape (FEATURE_DIM,), dtype float32.
        """
        src_ip: str = pkt_meta.get("src_ip", "0.0.0.0")
        dst_port: int = pkt_meta.get("dst_port", 0)
        protocol: str = pkt_meta.get("protocol", "")
        payload: bytes = pkt_meta.get("payload_bytes") or b""
        tcp_flags: str = pkt_meta.get("tcp_flags", "")
        size: int = pkt_meta.get("size", 0)

        now = time.time()
        state = self._state[src_ip]
        self._evict(state, now)

        # Update rolling windows
        state.pkt_times.append(now)
        state.short_times.append(now)
        state.dst_ports.append((now, dst_port))
        state.payload_ema = (
            state.payload_ema_alpha * size
            + (1 - state.payload_ema_alpha) * state.payload_ema
        )

        features = np.array([
            float(size),
            self._packet_rate(state),
            float(self._unique_ports(state)),
            self._tcp_flag_score(tcp_flags),
            float(_PROTO_ENCODE.get(protocol.upper(), 0)),
            self._shannon_entropy(payload),
            self._burst_score(state),
            state.payload_ema,
        ], dtype=np.float32)

        return features

    def get_feature_names(self) -> List[str]:
        return [
            "packet_size", "packet_rate", "unique_ports",
            "tcp_flag_score", "protocol_encoded", "payload_entropy",
            "burst_score", "avg_payload_ema",
        ]

    def state_size(self) -> int:
        """Return number of tracked source IPs."""
        return len(self._state)

    def flush_stale(self, max_idle_seconds: float = 300.0) -> None:
        """Remove IP state entries that have been idle longer than threshold."""
        now = time.time()
        stale = [
            ip for ip, s in self._state.items()
            if not s.pkt_times or (now - s.pkt_times[-1]) > max_idle_seconds
        ]
        for ip in stale:
            del self._state[ip]

    # ------------------------------------------------------------------ #
    #  Feature computations                                                #
    # ------------------------------------------------------------------ #

    def _evict(self, state: _SourceState, now: float) -> None:
        cutoff = now - self._window
        short_cutoff = now - self._short_window
        while state.pkt_times and state.pkt_times[0] < cutoff:
            state.pkt_times.popleft()
        while state.short_times and state.short_times[0] < short_cutoff:
            state.short_times.popleft()
        while state.dst_ports and state.dst_ports[0][0] < cutoff:
            state.dst_ports.popleft()

    @staticmethod
    def _packet_rate(state: _SourceState) -> float:
        n = len(state.pkt_times)
        if n < 2:
            return 0.0
        elapsed = state.pkt_times[-1] - state.pkt_times[0]
        return n / elapsed if elapsed > 0 else float(n)

    @staticmethod
    def _unique_ports(state: _SourceState) -> int:
        return len({port for _, port in state.dst_ports})

    @staticmethod
    def _tcp_flag_score(flags: str) -> float:
        return _TCP_FLAG_WEIGHTS.get(flags, 0.2)

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        counts: Dict[int, int] = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _burst_score(state: _SourceState) -> float:
        """Normalize burst by threshold (50 pkts/10 s)."""
        n = len(state.short_times)
        return min(n / 50.0, 1.0)
