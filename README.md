# Hybrid IDS — Production-Grade Intrusion Detection System

A modular, enterprise-structured hybrid Network IDS combining signature-based and ML anomaly detection, written in Python 3.11+.

---

## Architecture

```
hybrid_ids/
├── main.py                  # Orchestrator & CLI entrypoint
├── requirements.txt
├── logs/                    # JSON alert output + IDS log
├── models/                  # Reserved for persisted model snapshots
├── tests/
│   └── test_ids.py          # Full test suite (pytest-compatible)
└── ids_core/
    ├── __init__.py
    ├── config.py            # All tunable parameters, dataclass-based
    ├── packet_capture.py    # Scapy live capture, pcap replay, simulation
    ├── feature_extractor.py # Statistical feature engineering (8 features)
    ├── signature_engine.py  # Regex patterns + port scan behavioral detection
    ├── anomaly_engine.py    # IsolationForest with adaptive retraining
    └── alert_manager.py     # Dedup, rate-limit, JSON persistence, console output
```

### Data Flow

```
PacketCapture
     │
     ▼  pkt_meta dict
FeatureExtractor ──────────► AnomalyEngine (IsolationForest)
     │                              │
     ▼                              ▼
SignatureEngine               AnomalyResult
     │                              │
     └──────────────┬───────────────┘
                    ▼
              AlertManager
         (dedup + rate-limit + JSON log)
```

---

## Installation

```bash
# Python 3.11+ required
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# For live capture (requires root)
pip install scapy
```

---

## Running

### Automated End-to-End Test Harness
```bash
sudo /home/cyberdude/Documents/Projects/ids/.venv/bin/python automated_ids_test.py \
  --iface wlp0s20f3 \
  --target-ip 10.196.211.124 \
  --tag local_lab
```

This single command will:
- start `hybrid_ids_realtime.py`
- start `tcpdump` packet capture
- generate port-scan traffic
- generate SYN-flood traffic
- stop all processes cleanly
- save artifacts under `Major_Project/test_runs/<timestamp>_<tag>/`

Saved artifacts include:
- `logs/ids_stdout.log`
- `logs/alerts.log`
- `logs/alerts.json`
- `evidence/capture.pcap`
- `reports/summary.json`
- `reports/summary.md`

### IDS Dashboard (Live + History)
```bash
cd /home/cyberdude/Documents/Projects/ids/Major_Project
/home/cyberdude/Documents/Projects/ids/.venv/bin/python ids_dashboard.py
```

Open in browser:
- `http://127.0.0.1:8050`

Dashboard features:
- Live IDS metrics from `logs/alerts.json` (falls back to `logs/alerts.log`)
- Recent alert table with confidence/severity/type
- Historical run explorer from `test_runs/*`
- Run-level details with alert preview and artifact paths

### Simulation Mode (no root, no scapy required)
```bash
python main.py --mode simulate
```

### Live Capture
```bash
sudo python main.py --mode live --iface eth0
```

### Pcap Replay
```bash
python main.py --mode pcap --file /path/to/capture.pcap
```

### All Options
```bash
python main.py --help

  --mode {live,pcap,simulate}
  --iface ETH_INTERFACE          (default: eth0)
  --file PCAP_FILE
  --contamination FLOAT          (default: 0.05)
  --min-confidence FLOAT         (default: 0.65)
  --debug
```

### Environment Variables
```bash
IDS_INTERFACE=eth1
IDS_BPF_FILTER="tcp port 80 or tcp port 443"
IDS_CONTAMINATION=0.03
IDS_MIN_CONFIDENCE=0.70
IDS_LOG_PATH=logs/production_alerts.jsonl
IDS_DEBUG=false
```

---

## Alert Format

Alerts are written as newline-delimited JSON to `logs/alerts.jsonl`:

```json
{
  "timestamp": 1709000000.123,
  "timestamp_iso": "2025-02-27T10:13:20Z",
  "alert_id": "signature:sql_injection:10.10.10.100:1709000000",
  "src_ip": "10.10.10.100",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 80,
  "protocol": "TCP",
  "detection_type": "signature",
  "alert_subtype": "sql_injection",
  "confidence": 0.9,
  "risk_level": "high",
  "description": "SQLi pattern in payload",
  "raw_evidence": {
    "pattern_hit": "UNION SELECT",
    "category": "sql_injection"
  }
}
```

Risk levels: `low` (conf < 0.70) | `medium` (0.70–0.85) | `high` (≥ 0.85)

---

## Detection Capabilities

### Signature Engine
| Category | Method | Confidence |
|---|---|---|
| SQL Injection | Regex (UNION SELECT, OR bypass, SLEEP, etc.) | 0.90 |
| XSS | Regex (`<script>`, event handlers, `javascript:`) | 0.85 |
| Command Injection | Regex (semicolon chains, path traversal, `/etc/passwd`) | 0.92 |
| Port Scanning | Behavioral — ≥15 unique dst ports in 10s window | 0.75–0.98 |
| Suspicious UA | Regex (sqlmap, nikto, masscan, dirbuster, etc.) | 0.70 |
| Malicious Keywords | Regex (metasploit, meterpreter, cobalt strike, etc.) | 0.80 |

### Anomaly Engine — Feature Vector
| Index | Feature | Description |
|---|---|---|
| 0 | `packet_size` | Raw IP payload byte length |
| 1 | `packet_rate` | Packets/second from src IP (60s window) |
| 2 | `unique_ports` | Unique dst ports contacted in window |
| 3 | `tcp_flag_score` | Weighted anomaly score for TCP flag combos |
| 4 | `protocol_encoded` | 1=TCP 2=UDP 3=ICMP 0=other |
| 5 | `payload_entropy` | Shannon entropy of payload bytes (0–8 bits) |
| 6 | `burst_score` | Short-window (10s) packet burst normalized to [0,1] |
| 7 | `avg_payload_ema` | Exponential moving average of payload sizes per src |

---

## False Positive Minimization

The system layers four defenses against false positives:

1. **Confidence threshold** — alerts below `min_confidence` are silently dropped
2. **Deduplication** — same `(src_ip, alert_subtype)` suppressed within `dedup_window_seconds`
3. **Rate limiting** — max `rate_limit_per_ip` alerts per source IP per minute
4. **Multi-condition guard** — anomaly alerts require corroborating behavioral evidence (burst, entropy, port count, or packet rate) unless confidence ≥ 0.90

---

## Tuning Guide: Reducing False Positives

### Too many anomaly alerts on normal traffic?
```python
# Lower contamination (default 0.05 = expect 5% anomalies)
# Start with 0.01–0.02 for low-noise environments
IDS_CONTAMINATION=0.02

# Raise minimum confidence
IDS_MIN_CONFIDENCE=0.75

# Increase minimum samples before training
# (more baseline = better model)
min_samples_to_train=500
```

### Port scan false positives (e.g., health checkers)?
```python
# Raise threshold (default 15 ports in 10s)
SignatureConfig(
    port_scan_unique_ports_threshold=25,
    port_scan_window_seconds=5.0,
)
```

### Whitelist known scanners or internal tools:
Add a pre-filter in `main.py → _process_packet()`:
```python
WHITELISTED_IPS = {"10.0.0.5", "10.0.0.10"}
if pkt_meta["src_ip"] in WHITELISTED_IPS:
    return
```

### BPF filter to reduce noise at capture layer:
```bash
IDS_BPF_FILTER="tcp and not (src net 10.0.0.0/8 and dst net 10.0.0.0/8)"
```

---

## Test Attack Examples

### SQLi (curl)
```bash
curl "http://target/search?q=' UNION SELECT username,password FROM users--"
```

### XSS
```bash
curl -X POST http://target/comment -d "body=<script>document.cookie</script>"
```

### Command Injection
```bash
curl "http://target/ping?host=127.0.0.1;cat+/etc/passwd"
```

### Port Scan (nmap)
```bash
nmap -sS -p 1-100 --min-rate 50 target
```

### High-Entropy Data Exfil Simulation (Python)
```python
import socket, os
s = socket.create_connection(("target", 4444))
for _ in range(80):
    s.send(os.urandom(512))
```

---

## Enterprise Scaling Suggestions

| Layer | Current | Enterprise Upgrade |
|---|---|---|
| Capture | scapy (single process) | libpcap/DPDK + multi-core ring buffers |
| Processing | Single-threaded | asyncio / multiprocessing per-interface |
| Anomaly model | In-memory IsolationForest | Joblib model persistence + A/B versioning |
| Alert storage | JSONL file | Elasticsearch / Kafka / Splunk sink |
| State tracking | Python dicts | Redis (for multi-node IDS clusters) |
| Model training | In-process | Separate training microservice |
| Rule updates | Code deployment | YAML/STIX pattern hot-reload |
| Threat Intel | None | MISP / VirusTotal / AbuseIPDB integration |
| Dashboard | None | Kibana / Grafana + custom SOC UI |

---

## Running Tests

```bash
# With pytest
pip install pytest
pytest tests/ -v

# Without pytest  
python -c "exec(open('tests/test_ids.py').read())"
```

---

## License

MIT — for academic research, lab deployment, and SOC prototyping.
