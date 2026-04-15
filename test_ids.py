"""
tests/test_ids.py — Unit and integration tests for the Hybrid IDS.

Run with: pytest tests/ -v
"""

from __future__ import annotations

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest

from ids_core.config import IDSConfig, AlertConfig, AnomalyConfig, SignatureConfig
from ids_core.feature_extractor import FeatureExtractor
from ids_core.signature_engine import SignatureEngine
from ids_core.anomaly_engine import AnomalyEngine
from ids_core.alert_manager import AlertManager


# ─────────────────────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sig_config():
    return SignatureConfig()

@pytest.fixture
def sig_engine(sig_config):
    return SignatureEngine(sig_config)

@pytest.fixture
def extractor():
    return FeatureExtractor(flow_window_seconds=60.0)

@pytest.fixture
def alert_mgr(tmp_path):
    cfg = AlertConfig(
        log_path=str(tmp_path / "alerts.jsonl"),
        console_output=False,
        min_confidence=0.50,
        dedup_window_seconds=0.0,  # disable dedup for testing
    )
    return AlertManager(cfg)


def _make_pkt(
    src_ip="192.168.1.1",
    dst_ip="10.0.0.1",
    src_port=54321,
    dst_port=80,
    protocol="TCP",
    payload_str="",
    user_agent="Mozilla/5.0",
    tcp_flags="PA",
    size=200,
) -> dict:
    payload_bytes = payload_str.encode() if payload_str else b""
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


# ─────────────────────────────────────────────────────────────────────────────
#  Signature Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSignatureEngine:

    def test_sqli_union_select(self, sig_engine):
        pkt = _make_pkt(payload_str="GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1")
        matches = sig_engine.inspect(pkt)
        categories = [m.category for m in matches]
        assert "sql_injection" in categories

    def test_sqli_or_bypass(self, sig_engine):
        pkt = _make_pkt(payload_str="username=admin' OR 1=1--&password=x")
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "sql_injection" for m in matches)

    def test_xss_script_tag(self, sig_engine):
        pkt = _make_pkt(payload_str="comment=<script>alert(1)</script>")
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "xss" for m in matches)

    def test_xss_event_handler(self, sig_engine):
        pkt = _make_pkt(payload_str='<img src=x onerror=alert(1)>')
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "xss" for m in matches)

    def test_cmdi_semicolon(self, sig_engine):
        pkt = _make_pkt(payload_str="ping?host=127.0.0.1;cat /etc/passwd")
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "command_injection" for m in matches)

    def test_cmdi_path_traversal(self, sig_engine):
        pkt = _make_pkt(payload_str="GET /../../../../etc/shadow HTTP/1.1")
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "command_injection" for m in matches)

    def test_suspicious_ua_sqlmap(self, sig_engine):
        pkt = _make_pkt(user_agent="sqlmap/1.7.8#stable (https://sqlmap.org)")
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "suspicious_user_agent" for m in matches)

    def test_clean_traffic_no_alert(self, sig_engine):
        pkt = _make_pkt(
            payload_str="GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        )
        matches = sig_engine.inspect(pkt)
        # No signature matches on normal traffic
        non_scan = [m for m in matches if m.category != "port_scan"]
        assert len(non_scan) == 0

    def test_port_scan_detection(self, sig_engine):
        src = "10.0.0.99"
        # Contact 20 unique ports rapidly
        for port in range(1, 25):
            pkt = _make_pkt(src_ip=src, dst_port=port, payload_str="", tcp_flags="S")
            matches = sig_engine.inspect(pkt)

        # Last packet should trigger port scan
        pkt = _make_pkt(src_ip=src, dst_port=100, payload_str="", tcp_flags="S")
        matches = sig_engine.inspect(pkt)
        assert any(m.category == "port_scan" for m in matches)

    def test_malformed_packet_no_crash(self, sig_engine):
        # Completely empty packet
        pkt = {"src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0,
               "payload_str": "", "user_agent": "", "tcp_flags": "", "protocol": ""}
        try:
            sig_engine.inspect(pkt)
        except Exception as e:
            pytest.fail(f"Signature engine crashed on malformed packet: {e}")

    def test_confidence_ranges(self, sig_engine):
        pkt = _make_pkt(payload_str="' UNION SELECT username FROM users--")
        matches = sig_engine.inspect(pkt)
        for m in matches:
            assert 0.0 <= m.confidence <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
#  Feature Extractor Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureExtractor:

    def test_output_shape(self, extractor):
        pkt = _make_pkt()
        vec = extractor.extract(pkt)
        assert vec.shape == (FeatureExtractor.FEATURE_DIM,)
        assert vec.dtype == np.float32

    def test_entropy_random_payload(self, extractor):
        import os
        rand_bytes = os.urandom(512)
        pkt = _make_pkt(size=512)
        pkt["payload_bytes"] = rand_bytes
        vec = extractor.extract(pkt)
        entropy = vec[5]
        assert entropy > 6.0, f"Random payload should have high entropy, got {entropy}"

    def test_entropy_empty_payload(self, extractor):
        pkt = _make_pkt(size=0)
        pkt["payload_bytes"] = b""
        vec = extractor.extract(pkt)
        assert vec[5] == 0.0

    def test_protocol_encoding(self, extractor):
        for proto, expected in [("TCP", 1), ("UDP", 2), ("ICMP", 3), ("OTHER", 0)]:
            pkt = _make_pkt(protocol=proto)
            vec = extractor.extract(pkt)
            assert int(vec[4]) == expected

    def test_unique_ports_accumulation(self, extractor):
        src_ip = "192.168.100.1"
        for port in range(1, 11):
            pkt = _make_pkt(src_ip=src_ip, dst_port=port)
            vec = extractor.extract(pkt)
        assert vec[2] >= 10.0   # unique_ports

    def test_burst_score_clamped(self, extractor):
        src_ip = "192.168.200.1"
        for _ in range(100):
            pkt = _make_pkt(src_ip=src_ip)
            vec = extractor.extract(pkt)
        assert vec[6] <= 1.0   # burst_score should be clamped

    def test_no_nan_inf(self, extractor):
        for _ in range(50):
            pkt = _make_pkt()
            vec = extractor.extract(pkt)
            assert not np.any(np.isnan(vec))
            assert not np.any(np.isinf(vec))


# ─────────────────────────────────────────────────────────────────────────────
#  Anomaly Engine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAnomalyEngine:

    def _make_engine(self):
        config = AnomalyConfig(
            min_samples_to_train=50,
            retrain_interval_seconds=9999,
            contamination=0.1,
        )
        extractor = FeatureExtractor()
        return AnomalyEngine(config, extractor)

    def test_not_trained_during_warmup(self):
        engine = self._make_engine()
        vec = np.zeros(8, dtype=np.float32)
        result = engine.ingest(vec)
        assert not result.model_trained

    def test_trains_after_min_samples(self):
        engine = self._make_engine()
        for i in range(60):
            vec = np.random.rand(8).astype(np.float32)
            engine.ingest(vec)
        assert engine.is_trained

    def test_anomaly_result_shape(self):
        engine = self._make_engine()
        # Train
        for i in range(60):
            vec = np.random.rand(8).astype(np.float32) * 0.5
            engine.ingest(vec)

        # Score
        outlier = np.array([9999, 9999, 9999, 1.0, 1.0, 8.0, 1.0, 9999], dtype=np.float32)
        result = engine.ingest(outlier)

        assert isinstance(result.confidence, float)
        assert 0.0 <= result.confidence <= 1.0
        assert result.model_trained

    def test_no_crash_on_nan_input(self):
        engine = self._make_engine()
        for _ in range(60):
            engine.ingest(np.random.rand(8).astype(np.float32))

        nan_vec = np.array([float('nan'), float('inf'), 0, 0, 0, 0, 0, 0], dtype=np.float32)
        try:
            result = engine.ingest(nan_vec)
        except Exception as e:
            pytest.fail(f"Engine crashed on NaN input: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Alert Manager Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertManager:

    def test_emits_above_threshold(self, alert_mgr):
        alert = alert_mgr.process(
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
            src_port=1234, dst_port=80, protocol="TCP",
            detection_type="signature", alert_subtype="sql_injection",
            confidence=0.90, description="Test alert", raw_evidence={},
        )
        assert alert is not None
        assert alert.confidence == 0.90

    def test_suppresses_below_threshold(self, alert_mgr):
        alert = alert_mgr.process(
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
            src_port=1234, dst_port=80, protocol="TCP",
            detection_type="signature", alert_subtype="sql_injection",
            confidence=0.30,  # below default 0.50
            description="Low confidence", raw_evidence={},
        )
        assert alert is None

    def test_risk_level_assignment(self, alert_mgr):
        high = alert_mgr.process(
            src_ip="2.3.4.5", dst_ip="10.0.0.1",
            src_port=0, dst_port=80, protocol="TCP",
            detection_type="signature", alert_subtype="xss",
            confidence=0.92, description="Test", raw_evidence={},
        )
        assert high is not None
        assert high.risk_level == "high"

    def test_alert_written_to_log(self, alert_mgr, tmp_path):
        import json
        alert_mgr.process(
            src_ip="5.6.7.8", dst_ip="10.0.0.1",
            src_port=9000, dst_port=443, protocol="TCP",
            detection_type="anomaly", alert_subtype="isolation_forest",
            confidence=0.80, description="Anomaly test", raw_evidence={"test": True},
        )
        alert_mgr.close()
        log_file = tmp_path / "alerts.jsonl"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) >= 1
        data = json.loads(lines[0])
        assert data["src_ip"] == "5.6.7.8"
        assert data["detection_type"] == "anomaly"
        assert "timestamp_iso" in data

    def test_dedup_suppression(self, tmp_path):
        cfg = AlertConfig(
            log_path=str(tmp_path / "dedup.jsonl"),
            console_output=False,
            min_confidence=0.5,
            dedup_window_seconds=10.0,  # 10s window
        )
        mgr = AlertManager(cfg)
        kwargs = dict(
            src_ip="9.9.9.9", dst_ip="10.0.0.1",
            src_port=1111, dst_port=80, protocol="TCP",
            detection_type="signature", alert_subtype="port_scan",
            confidence=0.80, description="Port scan", raw_evidence={},
        )
        first = mgr.process(**kwargs)
        second = mgr.process(**kwargs)  # Should be deduped
        assert first is not None
        assert second is None
        mgr.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Integration Test
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:

    def test_full_pipeline_sqli(self, tmp_path):
        """End-to-end: SQLi packet should produce signature alert."""
        from ids_core.config import IDSConfig, AlertConfig
        import main as ids_main

        cfg = IDSConfig(
            alert=AlertConfig(
                log_path=str(tmp_path / "alerts.jsonl"),
                console_output=False,
                min_confidence=0.60,
                dedup_window_seconds=0.0,
            )
        )

        ids = ids_main.HybridIDS(cfg)

        sqli_pkt = _make_pkt(
            payload_str="GET /login?user=' OR '1'='1' -- HTTP/1.1",
            user_agent="sqlmap/1.7",
        )
        ids._process_packet(sqli_pkt)

        stats = ids._alert_mgr.stats()
        assert stats["total_emitted"] >= 1
