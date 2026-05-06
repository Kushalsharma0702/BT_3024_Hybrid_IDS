import argparse
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, sniff


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
MODEL_PATH = BASE_DIR / "hybrid_ids_model.pkl"
SCALER_PATH = BASE_DIR / "ids_scaler.bin"
ALERTS_JSON_PATH = LOG_DIR / "alerts.json"
ALERTS_LOG_PATH = LOG_DIR / "alerts.log"

POWER9_FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "sload",
    "dload",
]

TRAINED_FEATURES_FALLBACK = [
    "dur",
    "sbytes",
    "dbytes",
    "sloss",
    "dloss",
    "sload",
    "dload",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
]

ANOMALY_THRESHOLD = 0.90
UNCERTAIN_LOW = 0.50

stats_lock = threading.Lock()
file_lock = threading.Lock()
log_throttle_lock = threading.Lock()

_LAST_LOG_TIMES: Dict[str, float] = {}
LOG_THROTTLE_SECONDS = 10.0

STATS: Dict[str, int] = {
    "total_packets": 0,
    "anomalies_detected": 0,
    "signature_hits": 0,
    "alerts_generated": 0,
    "possible_false_positives": 0,
}

SIM_STATS: Dict[str, int] = {
    "syn_flood_packets_actual": 0,
    "syn_flood_packets_flagged": 0,
    "dos_packets_actual": 0,
    "dos_packets_flagged": 0,
    "portscan_packets_actual": 0,
    "portscan_packets_flagged": 0,
    "normal_packets_actual": 0,
    "normal_packets_flagged": 0,
}


class FlowTracker:
    """Maintains lightweight bidirectional flow state for Power 9 feature extraction."""

    def __init__(self) -> None:
        self.flow_state: Dict[Tuple[str, str, int, int, int], Dict[str, Any]] = {}
        self.scan_state: Dict[str, Dict[str, Any]] = {}
        self.reverse_scan_state: Dict[str, Dict[str, Any]] = {}
        self.state_lock = threading.Lock()
        self.scan_window_seconds = 10.0

    @staticmethod
    def _canonical_flow_key(
        src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int
    ) -> Tuple[Tuple[str, str, int, int, int], bool]:
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto), True
        return (dst_ip, src_ip, dst_port, src_port, proto), False

    def _update_scan_state(self, src_ip: str, dst_port: int, now: float) -> int:
        state = self.scan_state.get(src_ip)
        if state is None:
            state = {"ports": {}, "last_cleanup": now}
            self.scan_state[src_ip] = state

        state["ports"][dst_port] = now

        if now - state["last_cleanup"] >= 1.0:
            cutoff = now - self.scan_window_seconds
            stale_ports = [p for p, ts in state["ports"].items() if ts < cutoff]
            for p in stale_ports:
                del state["ports"][p]
            state["last_cleanup"] = now

        return len(state["ports"])

    def _update_reverse_scan_state(self, dst_ip: str, src_port: int, now: float) -> int:
        state = self.reverse_scan_state.get(dst_ip)
        if state is None:
            state = {"ports": {}, "last_cleanup": now}
            self.reverse_scan_state[dst_ip] = state

        state["ports"][src_port] = now

        if now - state["last_cleanup"] >= 1.0:
            cutoff = now - self.scan_window_seconds
            stale_ports = [p for p, ts in state["ports"].items() if ts < cutoff]
            for p in stale_ports:
                del state["ports"][p]
            state["last_cleanup"] = now

        return len(state["ports"])

    def update_and_extract(self, packet: Any) -> Optional[Dict[str, Any]]:
        if IP not in packet:
            return None

        now = time.time()
        ip_layer = packet[IP]

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        proto = int(ip_layer.proto)
        ttl = int(getattr(ip_layer, "ttl", 0) or 0)

        src_port = 0
        dst_port = 0
        tcp_syn = 0

        if TCP in packet:
            tcp_layer = packet[TCP]
            src_port = int(getattr(tcp_layer, "sport", 0) or 0)
            dst_port = int(getattr(tcp_layer, "dport", 0) or 0)
            flags = int(getattr(tcp_layer, "flags", 0) or 0)
            tcp_syn = 1 if (flags & 0x02) and not (flags & 0x10) else 0
        elif UDP in packet:
            udp_layer = packet[UDP]
            src_port = int(getattr(udp_layer, "sport", 0) or 0)
            dst_port = int(getattr(udp_layer, "dport", 0) or 0)

        packet_len = int(len(packet))
        flow_key, is_forward = self._canonical_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        with self.state_lock:
            flow = self.flow_state.get(flow_key)
            if flow is None:
                flow = {
                    "start_ts": now,
                    "last_ts": now,
                    "spkts": 0,
                    "dpkts": 0,
                    "sbytes": 0,
                    "dbytes": 0,
                    "sttl": 0,
                    "dttl": 0,
                }
                self.flow_state[flow_key] = flow

            flow["last_ts"] = now

            if is_forward:
                flow["spkts"] += 1
                flow["sbytes"] += packet_len
                flow["sttl"] = ttl
            else:
                flow["dpkts"] += 1
                flow["dbytes"] += packet_len
                flow["dttl"] = ttl

            dur = max(flow["last_ts"] - flow["start_ts"], 1e-6)
            sload = (flow["sbytes"] * 8.0) / dur
            dload = (flow["dbytes"] * 8.0) / dur

            unique_dst_ports = self._update_scan_state(src_ip, dst_port, now)
            unique_src_ports_for_dst = self._update_reverse_scan_state(dst_ip, src_port, now)

            features: Dict[str, Any] = {
                "dur": float(dur),
                "spkts": float(flow["spkts"]),
                "dpkts": float(flow["dpkts"]),
                "sbytes": float(flow["sbytes"]),
                "dbytes": float(flow["dbytes"]),
                # Real packet loss is not directly observable from single packet sniffing
                # without deeper transport tracking, so default to 0.0 at flow level.
                "sloss": 0.0,
                "dloss": 0.0,
                "sttl": float(flow["sttl"]),
                "dttl": float(flow["dttl"]),
                "sload": float(sload),
                "dload": float(dload),
                "ct_src_dport_ltm": float(unique_dst_ports),
                "ct_dst_sport_ltm": float(unique_src_ports_for_dst),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": proto,
                "tcp_syn": tcp_syn,
                "src_unique_dst_ports": unique_dst_ports,
            }

        return features


class AnomalyEngine:
    """Loads scaler + ensemble and applies mandatory weighted soft-voting logic."""

    def __init__(self, model_path: Path, scaler_path: Path) -> None:
        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(
                f"Model/scaler missing. Expected: {model_path} and {scaler_path}"
            )

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

        self.rf_model = None
        self.xgb_model = None
        self.feature_order = self._resolve_feature_order()

        named_estimators = getattr(self.model, "named_estimators_", None)
        if isinstance(named_estimators, dict):
            self.rf_model = named_estimators.get("rf")
            self.xgb_model = named_estimators.get("xgb")
        else:
            self.rf_model = getattr(self.model, "rf", None)
            self.xgb_model = getattr(self.model, "xgb", None)

    def _resolve_feature_order(self) -> List[str]:
        scaler_features = getattr(self.scaler, "feature_names_in_", None)
        if scaler_features is not None:
            return [str(f) for f in scaler_features]

        model_features = getattr(self.model, "feature_names_in_", None)
        if model_features is not None:
            return [str(f) for f in model_features]

        return TRAINED_FEATURES_FALLBACK

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        model_features = {f: float(features.get(f, 0.0) or 0.0) for f in self.feature_order}
        x_df = pd.DataFrame([model_features], columns=self.feature_order)
        x_scaled = self.scaler.transform(x_df)

        if self.rf_model is not None and self.xgb_model is not None:
            p_rf = float(self.rf_model.predict_proba(x_scaled)[0][1])
            p_xgb = float(self.xgb_model.predict_proba(x_scaled)[0][1])
            p_attack = (0.6 * p_xgb) + (0.4 * p_rf)
        else:
            # Fallback for model variants while preserving runtime safety.
            p_attack = float(self.model.predict_proba(x_scaled)[0][1])
            p_rf = p_attack
            p_xgb = p_attack

        uncertain = UNCERTAIN_LOW < p_attack < ANOMALY_THRESHOLD
        is_attack = p_attack >= ANOMALY_THRESHOLD

        return {
            "p_attack": p_attack,
            "p_rf": p_rf,
            "p_xgb": p_xgb,
            "is_attack": is_attack,
            "uncertain": uncertain,
        }


flow_tracker = FlowTracker()
anomaly_engine = AnomalyEngine(MODEL_PATH, SCALER_PATH)
executor = ThreadPoolExecutor(max_workers=2)

SIGNATURES = [
    {
        "name": "SYN flood",
        "severity": "HIGH",
        "condition": lambda f: f.get("tcp_syn", 0) == 1
        and f.get("spkts", 0.0) >= 60
        and f.get("sload", 0.0) > 150000.0,
    },
    {
        "name": "Port scan",
        "severity": "HIGH",
        "condition": lambda f: f.get("src_unique_dst_ports", 0) >= 20
        and f.get("spkts", 0.0) >= 20,
    },
    {
        "name": "DoS pattern",
        "severity": "MEDIUM",
        "condition": lambda f: (f.get("spkts", 0.0) + f.get("dpkts", 0.0)) >= 200
        and (f.get("sload", 0.0) + f.get("dload", 0.0)) > 500000.0,
    },
]


LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("hybrid_ids")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    rotating_file = RotatingFileHandler(
        str(ALERTS_LOG_PATH), maxBytes=5 * 1024 * 1024, backupCount=3
    )
    rotating_file.setLevel(logging.INFO)
    rotating_file.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    logger.addHandler(rotating_file)
    logger.propagate = False


def _log_throttled(level: str, key: str, message: str, *args: Any) -> None:
    now = time.time()
    with log_throttle_lock:
        last = _LAST_LOG_TIMES.get(key, 0.0)
        if now - last < LOG_THROTTLE_SECONDS:
            return
        _LAST_LOG_TIMES[key] = now

    if level == "exception":
        logger.exception(message, *args)
    elif level == "warning":
        logger.warning(message, *args)
    else:
        logger.info(message, *args)


def extract_features(packet: Any) -> Optional[Dict[str, Any]]:
    """Extracts robust flow-level features from a packet for both engines."""
    try:
        return flow_tracker.update_and_extract(packet)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        _log_throttled("exception", "feature_extraction_failed", "Feature extraction failed: %s", exc)
        return None


def check_signatures(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Returns all matching signatures for the current packet/flow features."""
    matched: List[Dict[str, Any]] = []
    for sig in SIGNATURES:
        try:
            if sig["condition"](features):
                matched.append(sig)
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            _log_throttled(
                "exception",
                f"signature_eval_failed_{sig.get('name', 'unknown')}",
                "Signature evaluation failed (%s): %s",
                sig.get("name"),
                exc,
            )
    return matched


def predict_anomaly(features: Dict[str, Any]) -> Dict[str, Any]:
    """Runs weighted soft-voting anomaly detection with confidence gating."""
    try:
        return anomaly_engine.predict(features)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        _log_throttled("exception", "anomaly_prediction_failed", "Anomaly prediction failed: %s", exc)
        return {
            "p_attack": 0.0,
            "p_rf": 0.0,
            "p_xgb": 0.0,
            "is_attack": False,
            "uncertain": False,
        }


def decision_engine(
    signature_matches: List[Dict[str, Any]], anomaly_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Fuses deterministic and probabilistic outputs into final action."""
    if signature_matches:
        primary = signature_matches[0]
        return {
            "status": "SIGNATURE_ALERT",
            "alert": True,
            "attack_type": primary["name"],
            "severity": "HIGH",
            "confidence": 1.0,
            "signature_matches": signature_matches,
        }

    if anomaly_result.get("is_attack", False):
        return {
            "status": "ANOMALY_ALERT",
            "alert": True,
            "attack_type": "ML anomaly",
            "severity": "MEDIUM",
            "confidence": float(anomaly_result.get("p_attack", 0.0)),
            "signature_matches": [],
        }

    if anomaly_result.get("uncertain", False):
        return {
            "status": "NORMAL",
            "alert": False,
            "attack_type": "uncertain_rejected",
            "severity": "INFO",
            "confidence": float(anomaly_result.get("p_attack", 0.0)),
            "signature_matches": [],
        }

    return {
        "status": "NORMAL",
        "alert": False,
        "attack_type": "none",
        "severity": "INFO",
        "confidence": float(anomaly_result.get("p_attack", 0.0)),
        "signature_matches": [],
    }


def _append_alert_to_json(alert: Dict[str, Any]) -> None:
    with file_lock:
        if ALERTS_JSON_PATH.exists():
            try:
                existing = json.loads(ALERTS_JSON_PATH.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except json.JSONDecodeError:
                existing = []
        else:
            existing = []

        existing.append(alert)
        try:
            ALERTS_JSON_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        except PermissionError:
            _log_throttled(
                "warning",
                "alerts_json_permission",
                "Permission denied writing %s; skipping file write",
                ALERTS_JSON_PATH,
            )


def alert_manager(decision: Dict[str, Any], features: Dict[str, Any]) -> None:
    """Prints structured alerts, writes alerts.json, and persists log records."""
    timestamp = datetime.now(timezone.utc).isoformat()

    if decision["status"] == "NORMAL":
        print(
            f"[NORMAL] src={features.get('source_ip', 'unknown')} "
            f"dst={features.get('destination_ip', 'unknown')} "
            f"p_attack={decision.get('confidence', 0.0):.4f}"
        )
        return

    alert = {
        "timestamp": timestamp,
        "source_ip": features.get("source_ip", "unknown"),
        "attack_type": decision.get("attack_type", "unknown"),
        "confidence": round(float(decision.get("confidence", 0.0)), 6),
        "severity": decision.get("severity", "MEDIUM"),
    }

    if decision["status"] == "SIGNATURE_ALERT":
        print(f"[SIGNATURE ALERT] {json.dumps(alert)}")
    else:
        print(f"[ANOMALY ALERT] {json.dumps(alert)}")

    logger.warning("ALERT %s", json.dumps(alert))
    _append_alert_to_json(alert)

    with stats_lock:
        STATS["alerts_generated"] += 1


def _process_packet(packet: Any) -> None:
    with stats_lock:
        STATS["total_packets"] += 1

    sim_label = getattr(packet, "sim_label", None)
    if sim_label:
        with stats_lock:
            if sim_label == "syn_flood":
                SIM_STATS["syn_flood_packets_actual"] += 1
            elif sim_label == "dos_pattern":
                SIM_STATS["dos_packets_actual"] += 1
            elif sim_label == "portscan":
                SIM_STATS["portscan_packets_actual"] += 1
            elif sim_label == "normal":
                SIM_STATS["normal_packets_actual"] += 1

    features = extract_features(packet)
    if features is None:
        return

    future_sig = executor.submit(check_signatures, features)
    future_anom = executor.submit(predict_anomaly, features)

    signature_matches = future_sig.result()
    anomaly_result = future_anom.result()

    decision = decision_engine(signature_matches, anomaly_result)

    with stats_lock:
        if decision["status"] == "SIGNATURE_ALERT":
            STATS["signature_hits"] += len(signature_matches)
        elif decision["status"] == "ANOMALY_ALERT":
            STATS["anomalies_detected"] += 1
        elif anomaly_result.get("uncertain", False):
            STATS["possible_false_positives"] += 1

    if sim_label:
        with stats_lock:
            flagged = decision["status"] in {"SIGNATURE_ALERT", "ANOMALY_ALERT"}
            if sim_label == "syn_flood" and flagged:
                SIM_STATS["syn_flood_packets_flagged"] += 1
            elif sim_label == "dos_pattern" and flagged:
                SIM_STATS["dos_packets_flagged"] += 1
            elif sim_label == "portscan" and flagged:
                SIM_STATS["portscan_packets_flagged"] += 1
            elif sim_label == "normal" and flagged:
                SIM_STATS["normal_packets_flagged"] += 1

    alert_manager(decision, features)


def capture_packets(interface: Optional[str] = None, packet_count: int = 0) -> None:
    """Starts real-time packet capture and dispatches packets to IDS pipeline."""
    print("--- Hybrid IDS Started ---")
    print(f"Model: {MODEL_PATH}")
    print(f"Scaler: {SCALER_PATH}")
    print("Sniffing live traffic... Press Ctrl+C to stop.")

    try:
        sniff(
            iface=interface,
            prn=_process_packet,
            store=False,
            filter="ip",
            count=packet_count,
        )
    except PermissionError:
        print("Error: Packet capture requires elevated privileges. Run with sudo.")
    finally:
        print("\n--- IDS Summary ---")
        for key, value in STATS.items():
            print(f"{key}: {value}")


def _build_simulated_packets() -> List[Any]:
    packets: List[Any] = []

    # Baseline normal HTTP traffic
    for i in range(200):
        packets.append(
            IP(src=f"192.168.1.{10 + (i % 10)}", dst="10.0.0.1")
            / TCP(sport=50000 + i, dport=80, flags="PA")
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        packets[-1].sim_label = "normal"

    # Port scan setup: many unique ports
    for port in range(20, 45):
        packets.append(
            IP(src="10.0.0.50", dst="192.168.1.200")
            / TCP(sport=12345, dport=port, flags="S")
        )
        packets[-1].sim_label = "portscan"

    # Port scan trigger: repeated hits to one port to raise spkts
    for i in range(25):
        packets.append(
            IP(src="10.0.0.50", dst="192.168.1.200")
            / TCP(sport=12345, dport=80, flags="S")
        )
        packets[-1].sim_label = "portscan"

    # SYN flood trigger
    for i in range(150):
        packets.append(
            IP(src="10.0.0.60", dst="192.168.1.210")
            / TCP(sport=40000, dport=443, flags="S")
        )
        packets[-1].sim_label = "syn_flood"

    # DoS pattern trigger (high packet count on one flow)
    for i in range(500):
        packets.append(
            IP(src="10.0.0.70", dst="192.168.1.220")
            / TCP(sport=41000, dport=8080, flags="PA")
            / Raw(load=b"A" * 1400)
        )
        packets[-1].sim_label = "dos_pattern"

    return packets


def run_simulation() -> None:
    print("--- Hybrid IDS Simulation ---")
    print(f"Model: {MODEL_PATH}")
    print(f"Scaler: {SCALER_PATH}")
    packets = _build_simulated_packets()
    for pkt in packets:
        _process_packet(pkt)

    print("\n--- IDS Summary ---")
    for key, value in STATS.items():
        print(f"{key}: {value}")

    if any(value > 0 for value in SIM_STATS.values()):
        print("\n--- Simulation Label Summary ---")
        for key, value in SIM_STATS.items():
            print(f"{key}: {value}")


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Production-grade Hybrid IDS")
    parser.add_argument(
        "--mode",
        choices=["live", "simulate"],
        default="live",
        help="Capture mode (default: live)",
    )
    parser.add_argument(
        "--anomaly-threshold",
        type=float,
        default=ANOMALY_THRESHOLD,
        help="Anomaly confidence threshold (default: 0.90)",
    )
    parser.add_argument("--iface", type=str, default=None, help="Network interface for capture")
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 means continuous)",
    )
    return parser


def main() -> None:
    parser = _build_cli()
    args = parser.parse_args()
    if not (0.0 < args.anomaly_threshold <= 1.0):
        parser.error("--anomaly-threshold must be in (0.0, 1.0]")

    global ANOMALY_THRESHOLD
    ANOMALY_THRESHOLD = float(args.anomaly_threshold)
    if args.mode == "simulate":
        run_simulation()
        return

    capture_packets(interface=args.iface, packet_count=args.count)


if __name__ == "__main__":
    main()
