"""
config.py — Central configuration for the Hybrid IDS system.

All tunable parameters are consolidated here to support environment-based
overrides, enterprise deployment, and rapid threshold adjustment without
touching business logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class CaptureConfig:
    """Network capture settings."""
    interface: str = os.getenv("IDS_INTERFACE", "eth0")
    bpf_filter: str = os.getenv("IDS_BPF_FILTER", "ip")          # BPF pre-filter
    packet_timeout: float = 1.0                                    # sniff timeout per batch
    batch_size: int = 100                                          # packets per processing cycle


@dataclass(frozen=True)
class SignatureConfig:
    """Signature engine thresholds and patterns."""
    port_scan_window_seconds: float = 10.0
    port_scan_unique_ports_threshold: int = 15
    port_scan_min_confidence: float = 0.75

    # Regex confidence weights (0.0–1.0)
    sqli_confidence: float = 0.90
    xss_confidence: float = 0.85
    cmdi_confidence: float = 0.92
    ua_confidence: float = 0.70
    keyword_confidence: float = 0.80


@dataclass(frozen=True)
class AnomalyConfig:
    """IsolationForest and feature engineering settings."""
    contamination: float = float(os.getenv("IDS_CONTAMINATION", "0.05"))
    n_estimators: int = 150
    max_samples: str = "auto"
    random_state: int = 42

    # Rolling window for feature accumulation
    flow_window_seconds: float = 60.0
    min_samples_to_train: int = 200
    retrain_interval_seconds: float = 300.0     # retrain every 5 min

    # Feature thresholds
    entropy_high_threshold: float = 7.5         # bits; high = encrypted/random payload
    burst_rate_threshold: int = 50              # packets/second from single src


@dataclass(frozen=True)
class AlertConfig:
    """Alert management, dedup, and output settings."""
    log_path: str = os.getenv("IDS_LOG_PATH", "logs/alerts.jsonl")
    min_confidence: float = float(os.getenv("IDS_MIN_CONFIDENCE", "0.65"))

    # Deduplication: suppress same (src_ip, alert_type) within window
    dedup_window_seconds: float = 30.0

    # Rate limiting: max alerts per source IP per minute
    rate_limit_per_ip: int = 10

    # Risk thresholds
    high_risk_confidence: float = 0.85
    medium_risk_confidence: float = 0.70

    # Console output
    console_output: bool = True
    json_pretty: bool = False


@dataclass
class IDSConfig:
    """Root configuration object passed through the entire system."""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    signature: SignatureConfig = field(default_factory=SignatureConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    debug: bool = os.getenv("IDS_DEBUG", "false").lower() == "true"


# Module-level singleton for convenience imports
DEFAULT_CONFIG = IDSConfig()
