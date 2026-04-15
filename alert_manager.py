"""
alert_manager.py — Alert lifecycle management for the Hybrid IDS.

Responsibilities:
  - Receive raw alert candidates from detection engines
  - Apply confidence threshold filtering
  - Deduplicate alerts within configurable time windows
  - Enforce per-source-IP rate limiting
  - Assign risk levels
  - Serialize and persist alerts as newline-delimited JSON
  - Optionally emit to stdout for real-time SOC monitoring
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple

from ids_core.config import AlertConfig

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Immutable alert record emitted by the IDS."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    detection_type: str          # "signature" | "anomaly" | "hybrid"
    alert_subtype: str           # e.g. "sql_injection", "port_scan", "isolation_forest"
    confidence: float            # 0.0–1.0
    risk_level: str              # "low" | "medium" | "high"
    description: str
    raw_evidence: Dict           # engine-specific metadata
    alert_id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.alert_id:
            self.alert_id = f"{self.detection_type}:{self.alert_subtype}:{self.src_ip}:{int(self.timestamp)}"

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["timestamp_iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
        )
        return d


class AlertManager:
    """
    Central alert sink with deduplication, rate limiting, and persistence.

    Thread-safety note: This implementation uses in-process state.
    For multi-process deployments, back the dedup store with Redis.
    """

    def __init__(self, config: AlertConfig) -> None:
        self._cfg = config
        self._log_path = Path(config.log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        # Dedup: (src_ip, alert_subtype) -> last emission timestamp
        self._dedup: Dict[Tuple[str, str], float] = {}

        # Rate limiting: src_ip -> deque of emission timestamps
        self._rate_tracker: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=config.rate_limit_per_ip + 1)
        )

        # Stats
        self.total_received: int = 0
        self.total_emitted: int = 0
        self.total_suppressed: int = 0

        self._file_handle = self._log_path.open("a", buffering=1)  # line-buffered
        logger.info("AlertManager initialized. Log → %s", self._log_path)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def process(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        detection_type: str,
        alert_subtype: str,
        confidence: float,
        description: str,
        raw_evidence: Optional[Dict] = None,
    ) -> Optional[Alert]:
        """
        Validate, filter, and optionally emit an alert.

        Returns the Alert object if emitted, None if suppressed.
        """
        self.total_received += 1
        now = time.time()

        # 1. Confidence gate
        if confidence < self._cfg.min_confidence:
            self.total_suppressed += 1
            logger.debug("Suppressed low-confidence alert (%.2f < %.2f)", confidence, self._cfg.min_confidence)
            return None

        # 2. Deduplication
        dedup_key = (src_ip, alert_subtype)
        last_seen = self._dedup.get(dedup_key, 0.0)
        if (now - last_seen) < self._cfg.dedup_window_seconds:
            self.total_suppressed += 1
            logger.debug("Dedup suppressed: %s/%s", src_ip, alert_subtype)
            return None

        # 3. Per-IP rate limiting
        timestamps = self._rate_tracker[src_ip]
        # purge entries older than 60 s
        while timestamps and (now - timestamps[0]) > 60.0:
            timestamps.popleft()
        if len(timestamps) >= self._cfg.rate_limit_per_ip:
            self.total_suppressed += 1
            logger.debug("Rate-limited alert from %s", src_ip)
            return None

        # 4. Construct alert
        risk = self._assign_risk(confidence)
        alert = Alert(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            detection_type=detection_type,
            alert_subtype=alert_subtype,
            confidence=round(confidence, 4),
            risk_level=risk,
            description=description,
            raw_evidence=raw_evidence or {},
        )

        # 5. Update state and persist
        self._dedup[dedup_key] = now
        timestamps.append(now)
        self._emit(alert)
        self.total_emitted += 1
        return alert

    def stats(self) -> Dict:
        return {
            "total_received": self.total_received,
            "total_emitted": self.total_emitted,
            "total_suppressed": self.total_suppressed,
        }

    def close(self) -> None:
        try:
            self._file_handle.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _assign_risk(self, confidence: float) -> str:
        if confidence >= self._cfg.high_risk_confidence:
            return "high"
        if confidence >= self._cfg.medium_risk_confidence:
            return "medium"
        return "low"

    def _emit(self, alert: Alert) -> None:
        payload = alert.to_dict()
        line = (
            json.dumps(payload, indent=2) if self._cfg.json_pretty
            else json.dumps(payload)
        )
        try:
            self._file_handle.write(line + "\n")
        except OSError as exc:
            logger.error("Failed to write alert to log: %s", exc)

        if self._cfg.console_output:
            risk_color = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}.get(
                alert.risk_level, ""
            )
            reset = "\033[0m"
            print(
                f"{risk_color}[{alert.risk_level.upper()}]{reset} "
                f"{time.strftime('%H:%M:%S', time.gmtime(alert.timestamp))} "
                f"| {alert.detection_type.upper()} | {alert.alert_subtype} "
                f"| {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port} "
                f"| conf={alert.confidence:.2f}"
            )
