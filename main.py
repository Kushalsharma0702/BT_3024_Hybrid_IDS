"""
main.py — Hybrid IDS orchestrator.

Ties together all subsystems:
  PacketCapture → FeatureExtractor → SignatureEngine → AnomalyEngine → AlertManager

Supports:
  - Live capture (requires root + scapy)
  - Pcap file replay
  - Simulation mode (for CI/testing)

Entry points:
  python main.py --mode live --iface eth0
  python main.py --mode pcap --file traffic.pcap
  python main.py --mode simulate
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from typing import Dict, Generator, Optional

from ids_core.alert_manager import AlertManager
from ids_core.anomaly_engine import AnomalyEngine
from ids_core.config import IDSConfig
from ids_core.feature_extractor import FeatureExtractor
from ids_core.packet_capture import PacketCapture, PcapReplay, SimulatedCapture
from ids_core.signature_engine import SignatureEngine

# ─────────────────────────────────────────────────────────────────────────────
#  Logging setup
# ─────────────────────────────────────────────────────────────────────────────

def _configure_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/ids.log", mode="a"),
        ],
    )

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Core IDS orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HybridIDS:
    """
    Main IDS orchestrator.

    Wires capture → feature extraction → signature + anomaly detection → alerting.
    Designed for single-threaded operation (add asyncio or threading for scale).
    """

    def __init__(self, config: IDSConfig) -> None:
        self._cfg = config
        self._running = False

        # Subsystem initialization
        self._alert_mgr = AlertManager(config.alert)
        self._extractor = FeatureExtractor(config.anomaly.flow_window_seconds)
        self._sig_engine = SignatureEngine(config.signature)
        self._anomaly_engine = AnomalyEngine(config.anomaly, self._extractor)

        # Periodic maintenance counters
        self._pkt_count: int = 0
        self._last_maintenance: float = time.time()
        self._maintenance_interval: float = 60.0

        logger.info("HybridIDS initialized successfully.")

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, packet_source: Generator[Dict, None, None]) -> None:
        """
        Main processing loop. Feed packet metadata dicts from any source.
        """
        self._running = True
        logger.info("IDS entering run loop.")

        try:
            for pkt_meta in packet_source:
                if not self._running:
                    break
                self._process_packet(pkt_meta)
        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
        finally:
            self._shutdown()

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------ #
    #  Packet processing pipeline                                          #
    # ------------------------------------------------------------------ #

    def _process_packet(self, pkt_meta: Dict) -> None:
        self._pkt_count += 1

        src_ip: str = pkt_meta.get("src_ip", "0.0.0.0")
        dst_ip: str = pkt_meta.get("dst_ip", "0.0.0.0")
        src_port: int = pkt_meta.get("src_port", 0)
        dst_port: int = pkt_meta.get("dst_port", 0)
        protocol: str = pkt_meta.get("protocol", "OTHER")

        # ── 1. Signature detection ────────────────────────────────────
        sig_matches = self._sig_engine.inspect(pkt_meta)
        for match in sig_matches:
            self._alert_mgr.process(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                detection_type="signature",
                alert_subtype=match.category,
                confidence=match.confidence,
                description=match.evidence,
                raw_evidence={
                    "pattern_hit": match.pattern_hit,
                    "category": match.category,
                },
            )

        # ── 2. Feature extraction ─────────────────────────────────────
        try:
            feature_vec = self._extractor.extract(pkt_meta)
        except Exception as exc:
            logger.debug("Feature extraction failed: %s", exc)
            self._run_maintenance()
            return

        # ── 3. Anomaly detection ──────────────────────────────────────
        try:
            anomaly_result = self._anomaly_engine.ingest(feature_vec)
        except Exception as exc:
            logger.debug("Anomaly engine error: %s", exc)
            self._run_maintenance()
            return

        if anomaly_result.is_anomaly and anomaly_result.model_trained:
            # Multi-condition guard: only alert if confidence meaningfully high
            # AND at least one feature is individually suspicious
            passes_guard = self._multi_condition_guard(pkt_meta, feature_vec, anomaly_result.confidence)
            if passes_guard:
                self._alert_mgr.process(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    detection_type="anomaly",
                    alert_subtype="isolation_forest",
                    confidence=anomaly_result.confidence,
                    description=(
                        f"Statistical anomaly detected "
                        f"(score={anomaly_result.raw_score:.4f})"
                    ),
                    raw_evidence={
                        "raw_if_score": anomaly_result.raw_score,
                        "feature_names": self._extractor.get_feature_names(),
                        "feature_values": feature_vec.tolist(),
                        "buffer_size": self._anomaly_engine.buffer_size,
                    },
                )

        self._run_maintenance()

    def _multi_condition_guard(
        self, pkt_meta: Dict, feature_vec, confidence: float
    ) -> bool:
        """
        False-positive suppression: require at least one corroborating indicator
        beyond the IsolationForest score alone.

        Conditions (any one must be true):
          - High burst score  (index 6 > 0.4)
          - High entropy      (index 5 > 7.0)  — encrypted or random payload
          - Many unique ports (index 2 > 10)
          - High packet rate  (index 1 > 30 pkts/s)
          - Confidence is very high (≥ 0.90, trust the model)
        """
        if confidence >= 0.90:
            return True

        burst_score = float(feature_vec[6])
        entropy = float(feature_vec[5])
        unique_ports = float(feature_vec[2])
        pkt_rate = float(feature_vec[1])

        return (
            burst_score > 0.4
            or entropy > 7.0
            or unique_ports > 10
            or pkt_rate > 30
        )

    # ------------------------------------------------------------------ #
    #  Maintenance                                                         #
    # ------------------------------------------------------------------ #

    def _run_maintenance(self) -> None:
        now = time.time()
        if (now - self._last_maintenance) < self._maintenance_interval:
            return

        self._last_maintenance = now
        self._extractor.flush_stale()
        self._sig_engine.flush_stale_scan_state()

        stats = self._alert_mgr.stats()
        logger.info(
            "Maintenance | pkts=%d buffer=%d trained=%s alerts=%d suppressed=%d",
            self._pkt_count,
            self._anomaly_engine.buffer_size,
            self._anomaly_engine.is_trained,
            stats["total_emitted"],
            stats["total_suppressed"],
        )

    def _shutdown(self) -> None:
        self._alert_mgr.close()
        stats = self._alert_mgr.stats()
        logger.info(
            "IDS shutdown. Packets: %d | Alerts emitted: %d | Suppressed: %d",
            self._pkt_count, stats["total_emitted"], stats["total_suppressed"],
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Simulation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_simulated_traffic() -> list:
    """
    Generates a realistic mix of benign and attack packets for demo/testing.
    """
    base_ts = time.time()
    packets = []

    # Normal HTTP traffic
    for i in range(300):
        packets.append({
            "src_ip": f"192.168.1.{(i % 20) + 10}",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "size": 200 + (i % 800),
            "payload_bytes": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "payload_str": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "tcp_flags": "PA",
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "timestamp": base_ts + i * 0.1,
        })

    # SQL Injection attempt
    sqli_payload = "GET /search?q=' UNION SELECT username,password FROM users-- HTTP/1.1\r\n"
    packets.append({
        "src_ip": "10.10.10.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "size": len(sqli_payload),
        "payload_bytes": sqli_payload.encode(),
        "payload_str": sqli_payload,
        "tcp_flags": "PA",
        "user_agent": "sqlmap/1.7",
        "timestamp": base_ts + 30,
    })

    # XSS payload
    xss_payload = "POST /comment HTTP/1.1\r\n\r\nbody=<script>document.cookie</script>"
    packets.append({
        "src_ip": "172.16.0.200",
        "dst_ip": "10.0.0.1",
        "src_port": 44000,
        "dst_port": 8080,
        "protocol": "TCP",
        "size": len(xss_payload),
        "payload_bytes": xss_payload.encode(),
        "payload_str": xss_payload,
        "tcp_flags": "PA",
        "user_agent": "Mozilla/5.0",
        "timestamp": base_ts + 31,
    })

    # Command injection
    cmdi_payload = "GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1\r\n"
    packets.append({
        "src_ip": "10.10.10.101",
        "dst_ip": "10.0.0.1",
        "src_port": 55000,
        "dst_port": 80,
        "protocol": "TCP",
        "size": len(cmdi_payload),
        "payload_bytes": cmdi_payload.encode(),
        "payload_str": cmdi_payload,
        "tcp_flags": "PA",
        "user_agent": "curl/7.82",
        "timestamp": base_ts + 32,
    })

    # Port scan simulation (same src, many dst ports)
    for port in range(20, 100):
        packets.append({
            "src_ip": "203.0.113.50",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": port,
            "protocol": "TCP",
            "size": 40,
            "payload_bytes": b"",
            "payload_str": "",
            "tcp_flags": "S",
            "user_agent": "",
            "timestamp": base_ts + 33 + port * 0.05,
        })

    # High-entropy (encrypted-looking) burst — anomaly bait
    import os
    import math
    for i in range(80):
        rand_payload = os.urandom(512)
        packets.append({
            "src_ip": "198.51.100.99",
            "dst_ip": "10.0.0.1",
            "src_port": 60000 + i,
            "dst_port": 4444,
            "protocol": "TCP",
            "size": 512,
            "payload_bytes": rand_payload,
            "payload_str": "",
            "tcp_flags": "PA",
            "user_agent": "",
            "timestamp": base_ts + 40 + i * 0.1,
        })

    return packets


# ─────────────────────────────────────────────────────────────────────────────
#  CLI entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hybrid IDS — Signature + ML Anomaly Detection")
    parser.add_argument(
        "--mode", choices=["live", "pcap", "simulate"],
        default="simulate",
        help="Capture mode (default: simulate)",
    )
    parser.add_argument("--iface", default="eth0", help="Network interface for live mode")
    parser.add_argument("--file", default="", help="Path to .pcap file for pcap mode")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--min-confidence", type=float, default=0.65)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main() -> None:
    import os
    os.makedirs("logs", exist_ok=True)

    args = _parse_args()
    _configure_logging(args.debug)

    # Build config (can be extended to read from YAML/env)
    from ids_core.config import (
        IDSConfig, CaptureConfig, AnomalyConfig, AlertConfig
    )
    config = IDSConfig(
        capture=CaptureConfig(interface=args.iface),
        anomaly=AnomalyConfig(contamination=args.contamination),
        alert=AlertConfig(min_confidence=args.min_confidence),
        debug=args.debug,
    )

    ids = HybridIDS(config)

    # Signal handler for graceful shutdown
    def _handle_signal(sig, frame):
        logger.info("Signal %s received. Shutting down...", sig)
        ids.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Select capture source
    if args.mode == "live":
        source = PacketCapture(
            interface=config.capture.interface,
            bpf_filter=config.capture.bpf_filter,
            batch_size=config.capture.batch_size,
            timeout=config.capture.packet_timeout,
        ).stream()

    elif args.mode == "pcap":
        if not args.file:
            logger.critical("--file is required for pcap mode.")
            sys.exit(1)
        source = PcapReplay(args.file).stream()

    else:  # simulate
        logger.info("Running in simulation mode with synthetic traffic.")
        packets = _build_simulated_traffic()
        source = SimulatedCapture(packets).stream()

    ids.run(source)


if __name__ == "__main__":
    main()
