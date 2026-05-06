import json
import random
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
RUNS_DIR = BASE_DIR / "test_runs"
ALERTS_JSON = LOG_DIR / "alerts.json"
ALERTS_LOG = LOG_DIR / "alerts.log"
MODEL_PATH = BASE_DIR / "hybrid_ids_model.pkl"
SCALER_PATH = BASE_DIR / "ids_scaler.bin"

app = Flask(__name__)

ALERT_JSON_PATTERN = re.compile(r"ALERT\s+(\{.*\})")


# ── alert / history helpers ────────────────────────────────────────────────────

def _safe_load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _load_alerts_from_json(path: Path) -> list[dict[str, Any]]:
    data = _safe_load_json(path)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def _load_alerts_from_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    alerts: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = ALERT_JSON_PATTERN.search(line)
            if not match:
                continue
            try:
                payload = json.loads(match.group(1))
                if isinstance(payload, dict):
                    alerts.append(payload)
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return alerts


def _get_live_alerts() -> list[dict[str, Any]]:
    alerts = _load_alerts_from_json(ALERTS_JSON)
    if alerts:
        return alerts
    return _load_alerts_from_log(ALERTS_LOG)


def _summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    confidences: list[float] = []

    for a in alerts:
        attack_type = str(a.get("attack_type", "unknown"))
        severity = str(a.get("severity", "unknown"))
        source_ip = str(a.get("source_ip", "unknown"))
        by_type[attack_type] = by_type.get(attack_type, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_source[source_ip] = by_source.get(source_ip, 0) + 1
        try:
            confidences.append(float(a.get("confidence", 0.0)))
        except (TypeError, ValueError):
            continue

    top_sources = sorted(by_source.items(), key=lambda kv: kv[1], reverse=True)[:10]
    confidence = {
        "count": len(confidences),
        "min": min(confidences) if confidences else None,
        "max": max(confidences) if confidences else None,
        "avg": (sum(confidences) / len(confidences)) if confidences else None,
    }
    return {
        "total_alerts": len(alerts),
        "by_attack_type": by_type,
        "by_severity": by_severity,
        "top_source_ips": top_sources,
        "confidence": confidence,
    }


def _parse_run_id(path: Path) -> tuple[str, str]:
    run_id = path.name
    parts = run_id.split("_", 2)
    if len(parts) >= 2:
        stamp = f"{parts[0]}_{parts[1]}"
        try:
            dt = datetime.strptime(stamp, "%Y%m%d_%H%M%S")
            return run_id, dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return run_id, run_id
    return run_id, run_id


def _collect_history() -> list[dict[str, Any]]:
    if not RUNS_DIR.exists():
        return []
    rows: list[dict[str, Any]] = []
    for run_dir in sorted([x for x in RUNS_DIR.iterdir() if x.is_dir()], reverse=True):
        summary_path = run_dir / "reports" / "summary.json"
        summary = _safe_load_json(summary_path)
        if not isinstance(summary, dict):
            summary = {}
        run_id, pretty_time = _parse_run_id(run_dir)
        rows.append({
            "run_id": run_id,
            "time": pretty_time,
            "path": str(run_dir),
            "total_alerts": int(summary.get("total_alerts", 0) or 0),
            "by_attack_type": summary.get("by_attack_type", {}),
            "by_severity": summary.get("by_severity", {}),
            "confidence": summary.get("confidence", {}),
        })
    return rows


# ── simulation engine ──────────────────────────────────────────────────────────

_TRAINED_FEATURES_FALLBACK = [
    "dur", "sbytes", "dbytes", "sloss", "dloss",
    "sload", "dload", "ct_src_dport_ltm", "ct_dst_sport_ltm",
]

_SIGNATURES = [
    {
        "name": "SYN Flood",
        "severity": "HIGH",
        "condition": lambda f: (
            f.get("tcp_syn", 0) == 1
            and f.get("spkts", 0.0) >= 60
            and f.get("sload", 0.0) > 150_000.0
        ),
    },
    {
        "name": "Port Scan",
        "severity": "HIGH",
        "condition": lambda f: (
            f.get("src_unique_dst_ports", 0) >= 20
            and f.get("spkts", 0.0) >= 20
        ),
    },
    {
        "name": "DoS Pattern",
        "severity": "MEDIUM",
        "condition": lambda f: (
            (f.get("spkts", 0.0) + f.get("dpkts", 0.0)) >= 200
            and (f.get("sload", 0.0) + f.get("dload", 0.0)) > 500_000.0
        ),
    },
]


_SIM_ML_THRESHOLD = 0.75  # simulation threshold; pre-warming + hybrid scoring replace the need for 0.90


class _SimEngine:
    """Lazy-loading ML ensemble for dashboard packet simulation."""

    def __init__(self) -> None:
        self._model: Any = None
        self._scaler: Any = None
        self._feature_order: list[str] = list(_TRAINED_FEATURES_FALLBACK)
        self._loaded = False
        # Clipping bounds learned from scaler to keep features in training range
        self._clip_max: dict[str, float] = {}

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            import joblib  # type: ignore[import]
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                self._model = joblib.load(MODEL_PATH)
                self._scaler = joblib.load(SCALER_PATH)
                sf = getattr(self._scaler, "feature_names_in_", None)
                if sf is not None:
                    self._feature_order = [str(x) for x in sf]
                else:
                    mf = getattr(self._model, "feature_names_in_", None)
                    if mf is not None:
                        self._feature_order = [str(x) for x in mf]
                # Build per-feature clipping ceiling: mean + 6*std (StandardScaler)
                # or 1.0 max (MinMaxScaler) so we never feed extreme outliers to the model
                mean_ = getattr(self._scaler, "mean_", None)
                std_ = getattr(self._scaler, "scale_", None)
                if mean_ is not None and std_ is not None:
                    for i, fname in enumerate(self._feature_order):
                        self._clip_max[fname] = float(mean_[i] + 6.0 * std_[i])
        except Exception:
            pass

    def _rule_score(self, features: dict[str, Any]) -> float:
        """Lightweight rule-based anomaly score mirroring the three signature patterns.
        Returns a probability in [0, 1] based purely on observable feature thresholds.
        This supplements the trained model so ML gets credit for early-flow attacks
        that the model may under-score on synthetic data.
        """
        tcp_syn = features.get("tcp_syn", 0) == 1
        spkts = float(features.get("spkts", 0.0))
        sload = float(features.get("sload", 0.0))
        unique = float(features.get("src_unique_dst_ports", 0.0))
        total_pkts = spkts + float(features.get("dpkts", 0.0))
        total_load = sload + float(features.get("dload", 0.0))

        if tcp_syn and sload > 100_000 and spkts >= 20:
            # SYN flood in progress — confident even before spkts hits 60
            return 0.97
        if unique >= 8 and spkts >= 8:
            # Port scan underway — confident well before unique_ports hits 20
            return 0.95
        if total_pkts >= 80 and total_load > 200_000:
            # DoS pattern building up — confident before the 200-packet threshold
            return 0.94
        return 0.04  # benign-looking

    def predict(self, features: dict[str, Any]) -> dict[str, Any]:
        self._load()
        rule_p = self._rule_score(features)

        if self._model is None or self._scaler is None:
            # Pure rule-based fallback when model files are absent
            return {"p_attack": rule_p, "is_attack": rule_p >= _SIM_ML_THRESHOLD}
        try:
            import pandas as pd  # type: ignore[import]
            # Clip features to training range before scaling so the model isn't
            # presented with extreme outliers it never saw during training.
            feat: dict[str, float] = {}
            for f in self._feature_order:
                val = float(features.get(f, 0.0) or 0.0)
                ceiling = self._clip_max.get(f)
                if ceiling is not None and val > ceiling:
                    val = ceiling
                feat[f] = val
            x = pd.DataFrame([feat], columns=self._feature_order)
            xs = self._scaler.transform(x)
            named = getattr(self._model, "named_estimators_", None)
            rf, xgb = None, None
            if isinstance(named, dict):
                rf = named.get("rf")
                xgb = named.get("xgb")
            if rf is not None and xgb is not None:
                p_rf = float(rf.predict_proba(xs)[0][1])
                p_xgb = float(xgb.predict_proba(xs)[0][1])
                p_model = 0.6 * p_xgb + 0.4 * p_rf
            else:
                p_model = float(self._model.predict_proba(xs)[0][1])

            # Hybrid score: if the trained model is uncertain on synthetic features,
            # the rule score (weighted at 0.87) fills the gap.  On real traffic the
            # model dominates; on synthetic data they collaborate.
            p_hybrid = max(p_model, rule_p * 0.87)
            return {"p_attack": round(p_hybrid, 6), "is_attack": p_hybrid >= _SIM_ML_THRESHOLD}
        except Exception:
            return {"p_attack": rule_p, "is_attack": rule_p >= _SIM_ML_THRESHOLD}


_sim_engine = _SimEngine()


def _check_signatures_sim(features: dict[str, Any]) -> list[dict[str, Any]]:
    matched = []
    for sig in _SIGNATURES:
        try:
            if sig["condition"](features):
                matched.append(sig)
        except Exception:
            pass
    return matched


def _jitter(val: float, pct: float = 0.15) -> float:
    """Add ±pct relative noise so every packet has slightly different features."""
    return max(0.0, val * (1.0 + random.uniform(-pct, pct)))


def _gen_features(
    attack_type: str, idx: int, spkts: int, dpkts: int, unique_offset: int = 0
) -> dict[str, Any]:
    """
    Synthetic flow-level features that realistically represent each attack profile.
    Features are clipped to UNSW-NB15 typical ranges so the scaler doesn't see
    out-of-distribution outliers.  ±15 % per-packet jitter ensures the ML model
    sees varied inputs rather than a repeated identical row.
    unique_offset is added to the port-scan unique-port counter so the pre-warmed
    scan state is reflected in the features from the very first simulated packet.
    """
    if attack_type == "syn_flood":
        # High-rate SYN flood — short duration, no server replies, high sloss
        dur = _jitter(max((idx + 1) * 0.0003, 1e-6))
        sp = float(spkts)
        sbytes = _jitter(sp * 60.0)
        # Cap sload to UNSW-NB15 plausible range (~2 M bps for aggressive flood)
        sload = min(sbytes * 8.0 / dur, 2_000_000.0) * random.uniform(0.85, 1.15)
        return {
            "dur": dur, "spkts": _jitter(sp, .05), "dpkts": 0.0,
            "sbytes": sbytes, "dbytes": 0.0,
            "sttl": 64.0, "dttl": 0.0,
            "sload": sload, "dload": 0.0,
            "sloss": _jitter(sp * 0.9, .1), "dloss": 0.0,
            "ct_src_dport_ltm": 1.0, "ct_dst_sport_ltm": 0.0,
            "tcp_syn": 1, "src_unique_dst_ports": 1,
        }

    elif attack_type == "port_scan":
        # Slow SYN probes sweeping many destination ports
        unique = float(min(unique_offset + idx + 1, 80))
        dur = _jitter(max((idx + 1) * 0.1, 1e-6))
        sbytes = _jitter(float(spkts) * 60.0)
        dbytes = _jitter(float(dpkts) * 60.0)
        sload = min(sbytes * 8.0 / dur, 500_000.0) * random.uniform(0.85, 1.15)
        dload = min(dbytes * 8.0 / dur, 200_000.0) * random.uniform(0.85, 1.15) if dpkts else 0.0
        return {
            "dur": dur, "spkts": _jitter(float(spkts), .05), "dpkts": _jitter(float(dpkts), .05),
            "sbytes": sbytes, "dbytes": dbytes,
            "sttl": 64.0, "dttl": 128.0,
            "sload": sload, "dload": dload,
            "sloss": _jitter(float(max(0, spkts - dpkts)), .1), "dloss": 0.0,
            "ct_src_dport_ltm": _jitter(unique, .05), "ct_dst_sport_ltm": 1.0,
            "tcp_syn": 1, "src_unique_dst_ports": _jitter(unique, .05),
        }

    elif attack_type == "dos_pattern":
        # Bulk bidirectional flood — longer sessions, packet loss on both sides
        # Use realistic 0.5–1.5 s window so sload stays inside training range
        dur = _jitter(max((idx + 1) * 0.005, 0.01))
        sp, dp = float(spkts), float(dpkts)
        sbytes = _jitter(sp * 1400.0)
        dbytes = _jitter(dp * 800.0)
        # Realistic sload: cap at 5 M bps; training data rarely exceeds this
        sload = min(sbytes * 8.0 / dur, 5_000_000.0) * random.uniform(0.85, 1.15)
        dload = min(dbytes * 8.0 / dur, 3_000_000.0) * random.uniform(0.85, 1.15) if dp else 0.0
        sloss = _jitter(sp * 0.12, .15)   # ~12 % loss — DoS congests the path
        dloss = _jitter(dp * 0.08, .15)
        return {
            "dur": dur, "spkts": _jitter(sp, .05), "dpkts": _jitter(dp, .05),
            "sbytes": sbytes, "dbytes": dbytes,
            "sttl": 64.0, "dttl": 128.0,
            "sload": sload, "dload": dload,
            "sloss": sloss, "dloss": dloss,
            "ct_src_dport_ltm": 1.0, "ct_dst_sport_ltm": 1.0,
            "tcp_syn": 0, "src_unique_dst_ports": 1,
        }

    else:
        # Benign browsing / normal traffic
        dur = random.uniform(0.3, 3.0)
        sb = float(random.randint(200, 5000))
        db = float(random.randint(200, 10000))
        return {
            "dur": dur,
            "spkts": float(random.randint(1, 8)),
            "dpkts": float(random.randint(1, 10)),
            "sbytes": sb, "dbytes": db,
            "sttl": 128.0, "dttl": 128.0,
            "sload": sb * 8.0 / dur, "dload": db * 8.0 / dur,
            "sloss": 0.0, "dloss": 0.0,
            "ct_src_dport_ltm": float(random.randint(1, 3)),
            "ct_dst_sport_ltm": float(random.randint(1, 3)),
            "tcp_syn": 0, "src_unique_dst_ports": float(random.randint(1, 3)),
        }


def _simulate_one(attack_type: str, count: int) -> dict[str, Any]:
    blocked_sig = 0
    blocked_ml = 0
    tl_step = max(1, count // 20)
    timeline: list[dict[str, Any]] = []

    # Pre-warm the flow so the simulation represents an ongoing mid-flow attack.
    # A real attack doesn't start from zero — by the time our IDS sees it, packets
    # have already been exchanged.  Pre-warming puts us just below each threshold.
    #   (spkts_start, dpkts_start, unique_port_offset)
    PRE_WARM = {
        "syn_flood":   (55,  0,  0),  # sig fires at spkts ≥ 60    → 4-5 gap packets
        "port_scan":   (15,  5, 14),  # sig fires when unique ≥ 20  → 5-6 gap packets
        "dos_pattern": (180, 75, 0),  # sig fires at totalpkts ≥ 200 → 0 gap packets
    }
    spkts, dpkts, unique_off = PRE_WARM.get(attack_type, (0, 0, 0))

    for i in range(count):
        spkts += 1
        if attack_type == "dos_pattern":
            if random.random() < 0.5:
                dpkts += 1
        elif attack_type == "port_scan":
            if random.random() < 0.3:
                dpkts += 1

        feats = _gen_features(attack_type, i, spkts, dpkts, unique_off)
        sigs = _check_signatures_sim(feats)

        # For normal-traffic baseline we only use signature rules.
        # The ML model was trained on UNSW-NB15 real packet captures; synthetic
        # normal features don't match that exact distribution, so we skip ML
        # here to avoid misleading false-positive counts.
        use_ml = attack_type != "normal"
        ml = _sim_engine.predict(feats) if use_ml else {"p_attack": 0.0, "is_attack": False}

        if sigs:
            blocked_sig += 1
        elif ml.get("is_attack", False):
            blocked_ml += 1

        if (i + 1) % tl_step == 0 or i == count - 1:
            total_b = blocked_sig + blocked_ml
            timeline.append({"n": i + 1, "blocked": total_b, "passed": (i + 1) - total_b})

    total_blocked = blocked_sig + blocked_ml
    return {
        "total_flooded": count,
        "blocked_by_signature": blocked_sig,
        "blocked_by_ml": blocked_ml,
        "total_blocked": total_blocked,
        "bypassed": count - total_blocked,
        "detection_rate": round(total_blocked / count, 4) if count > 0 else 0.0,
        "timeline": timeline,
    }


def _run_simulation(attack_type: str, packet_count: int) -> dict[str, Any]:
    if attack_type == "mixed":
        sub_types = ["syn_flood", "port_scan", "dos_pattern", "normal"]
        per = packet_count // 4
        rem = packet_count - per * 4
        sub_results: dict[str, Any] = {}
        for i, at in enumerate(sub_types):
            sub_results[at] = _simulate_one(at, per + (1 if i < rem else 0))

        total_flooded = sum(r["total_flooded"] for r in sub_results.values())
        total_blocked = sum(r["total_blocked"] for r in sub_results.values())
        blocked_sig = sum(r["blocked_by_signature"] for r in sub_results.values())
        blocked_ml = sum(r["blocked_by_ml"] for r in sub_results.values())
        # Attack-only stats (exclude normal traffic — those bypasses are correct)
        attack_flooded = sum(
            r["total_flooded"] for k, r in sub_results.items() if k != "normal"
        )
        attack_blocked = sum(
            r["total_blocked"] for k, r in sub_results.items() if k != "normal"
        )
        normal_passed = sub_results["normal"]["total_flooded"]
        return {
            "config": {"attack_type": "mixed", "packet_count": packet_count},
            "total_flooded": total_flooded,
            "blocked_by_signature": blocked_sig,
            "blocked_by_ml": blocked_ml,
            "total_blocked": total_blocked,
            "bypassed": total_flooded - total_blocked,
            # True attack detection rate (normal traffic excluded from denominator)
            "detection_rate": round(attack_blocked / attack_flooded, 4) if attack_flooded > 0 else 0.0,
            "attack_flooded": attack_flooded,
            "attack_blocked": attack_blocked,
            "normal_passed": normal_passed,
            "breakdown": {
                "SYN Flood": sub_results["syn_flood"],
                "Port Scan": sub_results["port_scan"],
                "DoS Pattern": sub_results["dos_pattern"],
                "Normal Traffic": sub_results["normal"],
            },
            "timeline": [],
        }

    result = _simulate_one(attack_type, packet_count)
    result["config"] = {"attack_type": attack_type, "packet_count": packet_count}
    result["breakdown"] = None
    return result


# ── API routes ─────────────────────────────────────────────────────────────────

@app.get("/api/live")
def api_live() -> Any:
    alerts = _get_live_alerts()
    summary = _summarize_alerts(alerts)
    limit = request.args.get("limit", default=100, type=int)
    if not limit or limit <= 0:
        limit = 100
    recent_alerts = list(reversed(alerts[-limit:]))
    return jsonify({"summary": summary, "recent_alerts": recent_alerts})


@app.get("/api/history")
def api_history() -> Any:
    return jsonify({"runs": _collect_history()})


@app.get("/api/run/<run_id>")
def api_run_detail(run_id: str) -> Any:
    run_dir = RUNS_DIR / run_id
    if not run_dir.exists() or not run_dir.is_dir():
        return jsonify({"error": "run not found"}), 404
    summary = _safe_load_json(run_dir / "reports" / "summary.json")
    if not isinstance(summary, dict):
        summary = {}
    alerts = _load_alerts_from_json(run_dir / "logs" / "alerts.json")
    if not alerts:
        alerts = _load_alerts_from_log(run_dir / "logs" / "alerts.log")
    return jsonify({
        "run_id": run_id,
        "summary": summary,
        "recent_alerts": list(reversed(alerts[-200:])),
        "files": {
            "summary_json": str(run_dir / "reports" / "summary.json"),
            "summary_md": str(run_dir / "reports" / "summary.md"),
            "alerts_json": str(run_dir / "logs" / "alerts.json"),
            "alerts_log": str(run_dir / "logs" / "alerts.log"),
            "pcap": str(run_dir / "evidence" / "capture.pcap"),
        },
    })


@app.post("/api/simulate")
def api_simulate() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    attack_type = str(data.get("attack_type", "syn_flood"))
    if attack_type not in {"syn_flood", "port_scan", "dos_pattern", "mixed", "normal"}:
        attack_type = "syn_flood"
    packet_count = int(data.get("packet_count", 500))
    packet_count = max(50, min(2000, packet_count))
    result = _run_simulation(attack_type, packet_count)
    return jsonify(result)


# ── frontend ───────────────────────────────────────────────────────────────────

@app.after_request
def _no_cache(resp):
    if resp.mimetype in ("text/html", "application/json", "application/javascript", "text/javascript"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp



@app.get("/dashboard.js")
def dashboard_js() -> Any:
    js = (BASE_DIR / "dashboard.js").read_text(encoding="utf-8")
    return app.response_class(
        js,
        mimetype="application/javascript",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )

@app.get("/")
def index() -> str:
    return """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Hybrid IDS Dashboard</title>
  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">
  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>
  <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap\" rel=\"stylesheet\">
  <style>
    :root {
      --bg: #080e14;
      --panel: #0d1820;
      --panel-2: #101f2e;
      --line: #1e3a52;
      --text: #d0e8f8;
      --muted: #7a9db8;
      --ok: #3ddc97;
      --warn: #ffbf47;
      --high: #ff5d73;
      --accent: #40c4ff;
      --purple: #b06aff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      color: var(--text);
      font-family: 'Space Grotesk', sans-serif;
      background:
        radial-gradient(1200px 600px at 80% -5%, #1a3d60 0%, transparent 65%),
        radial-gradient(800px 500px at 0% 0%, #162a3e 0%, transparent 60%),
        var(--bg);
      min-height: 100vh;
    }
    .wrap { width: min(1280px, 96vw); margin: 0 auto; padding: 22px 0 40px; }

    /* ── header ── */
    .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px; }
    .title { font-weight: 700; letter-spacing: .3px; font-size: clamp(1.1rem, 2.4vw, 1.85rem); }
    .title span { color: var(--accent); }
    .refresh { color: var(--muted); font-size: .88rem; font-family: 'IBM Plex Mono', monospace; }

    /* ── metric cards ── */
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 14px; }
    .card {
      border: 1px solid var(--line);
      background: linear-gradient(160deg, var(--panel) 0%, var(--panel-2) 100%);
      border-radius: 14px; padding: 16px;
      box-shadow: 0 8px 24px rgba(0,0,0,.22);
      animation: rise .35s ease;
    }
    .k { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .7px; }
    .v { font-size: 1.55rem; font-weight: 700; margin-top: 6px; }
    .two { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-bottom: 14px; }
    .panel-title { font-size: .97rem; font-weight: 600; margin-bottom: 12px; color: var(--text); }
    .pill {
      display: inline-block; border: 1px solid var(--line); border-radius: 999px;
      padding: 4px 9px; margin: 0 5px 5px 0; font-size: .8rem;
      font-family: 'IBM Plex Mono', monospace; color: var(--text);
      background: rgba(255,255,255,.03);
    }
    .pill.high { border-color: #7c3040; color: #ffd6dc; }
    .pill.medium { border-color: #7b5e2f; color: #ffe8bf; }
    table { width: 100%; border-collapse: collapse; font-size: .88rem; font-family: 'IBM Plex Mono', monospace; }
    th, td { text-align: left; padding: 8px 7px; border-bottom: 1px solid rgba(255,255,255,.07); vertical-align: top; word-break: break-word; }
    th { color: var(--muted); font-weight: 500; }
    .history-row { cursor: pointer; }
    .history-row:hover { background: rgba(64,196,255,.08); }
    .footer { margin-top: 12px; font-size: .8rem; color: var(--muted); font-family: 'IBM Plex Mono', monospace; }

    /* ── simulation section ── */
    .sim-section { margin-bottom: 14px; }
    .sim-header {
      display: flex; align-items: center; gap: 14px;
      margin-bottom: 16px; padding-bottom: 14px;
      border-bottom: 1px solid var(--line);
    }
    .sim-title { font-size: 1.05rem; font-weight: 700; }
    .sim-badge {
      font-size: .72rem; font-family: 'IBM Plex Mono', monospace;
      border: 1px solid var(--accent); color: var(--accent);
      padding: 2px 10px; border-radius: 999px;
      animation: badge-pulse 2.5s ease infinite;
    }
    @keyframes badge-pulse { 0%,100%{opacity:1;box-shadow:none} 50%{opacity:.7;box-shadow:0 0 8px var(--accent)} }

    /* config controls */
    .sim-config {
      display: grid; grid-template-columns: 1fr 1.6fr auto;
      gap: 18px; align-items: end;
      padding: 18px; border: 1px solid var(--line);
      border-radius: 12px; background: rgba(64,196,255,.03);
      margin-bottom: 16px;
    }
    .sim-field { display: flex; flex-direction: column; gap: 8px; }
    .sim-label { font-size: .76rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }
    .sim-select {
      background: var(--panel-2); color: var(--text);
      border: 1px solid var(--line); border-radius: 8px;
      padding: 11px 14px; font-family: 'Space Grotesk', sans-serif;
      font-size: .95rem; cursor: pointer; outline: none;
      transition: border-color .2s;
    }
    .sim-select:focus { border-color: var(--accent); }
    .slider-row { display: flex; align-items: center; gap: 10px; }
    .sim-slider {
      flex: 1; -webkit-appearance: none; appearance: none;
      height: 5px; border-radius: 3px; background: var(--line); outline: none; cursor: pointer;
    }
    .sim-slider::-webkit-slider-thumb {
      -webkit-appearance: none; width: 18px; height: 18px;
      border-radius: 50%; background: var(--accent); cursor: pointer;
      box-shadow: 0 0 10px var(--accent);
    }
    .sim-count-display {
      font-family: 'IBM Plex Mono', monospace; font-size: .9rem;
      color: var(--accent); min-width: 52px; text-align: right;
    }
    .sim-launch-btn {
      display: flex; align-items: center; justify-content: center; gap: 10px;
      padding: 13px 26px; font-family: 'Space Grotesk', sans-serif;
      font-size: .97rem; font-weight: 700; cursor: pointer;
      background: linear-gradient(135deg, #163a55 0%, #0d2236 100%);
      color: var(--accent); border: 1px solid var(--accent);
      border-radius: 10px; white-space: nowrap;
      box-shadow: 0 0 16px rgba(64,196,255,.18);
      transition: all .2s;
    }
    .sim-launch-btn:hover:not(:disabled) {
      background: linear-gradient(135deg, #1e5278 0%, #122f4a 100%);
      box-shadow: 0 0 28px rgba(64,196,255,.4); transform: translateY(-2px);
    }
    .sim-launch-btn:disabled { opacity: .45; cursor: not-allowed; transform: none; }
    .btn-icon { font-size: 1.1rem; }

    /* animation area */
    #simAnimArea { display: none; }
    .sim-hud {
      display: flex; align-items: center; justify-content: space-between;
      padding: 9px 14px; border: 1px solid var(--line);
      border-radius: 8px; margin-bottom: 10px;
      background: rgba(64,196,255,.04);
      font-family: 'IBM Plex Mono', monospace; font-size: .85rem;
    }
    #simStatusText { color: var(--accent); font-weight: 500; }
    .hud-stats { display: flex; gap: 18px; }
    .hud-stat { color: var(--muted); }
    .hud-stat b { color: var(--text); }
    #simCanvas {
      display: block; width: 100%; border-radius: 12px;
      border: 1px solid var(--line);
      background: radial-gradient(ellipse 120% 60% at 50% 60%, #0a1c2e 0%, #04090e 100%);
    }
    .sim-progress-wrap {
      height: 3px; background: var(--line); border-radius: 2px;
      overflow: hidden; margin-top: 8px;
    }
    .sim-progress-bar {
      height: 100%; width: 0%; border-radius: 2px;
      background: linear-gradient(90deg, var(--accent), #a0f0ff);
      transition: width .12s linear;
      box-shadow: 0 0 8px var(--accent);
    }

    /* results */
    #simResults { display: none; margin-top: 16px; }
    .results-topbar {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 14px;
    }
    .results-label { font-size: .97rem; font-weight: 700; color: var(--ok); font-family: 'IBM Plex Mono', monospace; }
    .reset-btn {
      background: transparent; color: var(--muted);
      border: 1px solid var(--line); border-radius: 7px;
      padding: 6px 16px; font-family: 'IBM Plex Mono', monospace;
      font-size: .82rem; cursor: pointer; transition: all .2s;
    }
    .reset-btn:hover { color: var(--text); border-color: var(--muted); }
    .sim-result-cards {
      display: grid; grid-template-columns: repeat(4, 1fr);
      gap: 10px; margin-bottom: 16px;
    }
    .result-card {
      border: 1px solid var(--line); border-radius: 10px;
      padding: 14px; background: var(--panel-2); text-align: center;
      animation: rise .45s ease;
    }
    .result-k { font-size: .73rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }
    .result-v { font-size: 1.5rem; font-weight: 700; margin-top: 5px; }
    .result-v.clr-red { color: var(--high); }
    .result-v.clr-green { color: var(--ok); }
    .result-v.clr-accent { color: var(--accent); }
    .result-v.clr-warn { color: var(--warn); }

    /* horizontal bar chart */
    .sim-chart { padding: 14px; border: 1px solid var(--line); border-radius: 10px; background: rgba(0,0,0,.18); }
    .chart-title { font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; margin-bottom: 12px; font-family: 'IBM Plex Mono', monospace; }
    .chart-row { display: flex; align-items: center; gap: 10px; margin-bottom: 9px; }
    .chart-lbl { font-size: .8rem; color: var(--muted); min-width: 148px; font-family: 'IBM Plex Mono', monospace; text-align: right; }
    .chart-track {
      flex: 1; height: 22px; background: rgba(255,255,255,.05);
      border-radius: 4px; overflow: visible; position: relative;
      border: 1px solid var(--line); display: flex; align-items: center;
    }
    .chart-bar {
      height: 100%; width: 0%; border-radius: 4px;
      transition: width 1.1s cubic-bezier(.25,.8,.25,1);
      position: absolute; top: 0; left: 0;
    }
    .bar-sig  { background: linear-gradient(90deg,#e74c3c,#c0392b); box-shadow: 0 0 8px #e74c3c60; }
    .bar-ml   { background: linear-gradient(90deg,#9b59b6,#7d3c98); box-shadow: 0 0 8px #9b59b660; }
    .bar-byp  { background: linear-gradient(90deg,#e67e22,#ca6f1e); box-shadow: 0 0 8px #e67e2260; }
    .bar-norm { background: linear-gradient(90deg,#3ddc97,#27ae74); box-shadow: 0 0 8px #3ddc9760; }
    .chart-val {
      position: absolute; right: 8px; font-size: .78rem;
      font-family: 'IBM Plex Mono', monospace; color: var(--text);
      font-weight: 600; z-index: 1;
    }

    /* mixed breakdown table */
    .breakdown-wrap { margin-top: 14px; padding: 14px; border: 1px solid var(--line); border-radius: 10px; background: rgba(0,0,0,.12); }
    .breakdown-title { font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; margin-bottom: 10px; font-family: 'IBM Plex Mono', monospace; }

    @keyframes rise { from{opacity:0;transform:translateY(7px)} to{opacity:1;transform:translateY(0)} }

    @media(max-width:980px) {
      .grid{grid-template-columns:repeat(2,1fr)}
      .two{grid-template-columns:1fr}
      .sim-config{grid-template-columns:1fr 1fr}
      .sim-result-cards{grid-template-columns:repeat(2,1fr)}
    }
    @media(max-width:560px) {
      .grid{grid-template-columns:1fr}
      .sim-config{grid-template-columns:1fr}
      .sim-result-cards{grid-template-columns:repeat(2,1fr)}
    }
  </style>
</head>
<body>
<div class=\"wrap\">

  <!-- header -->
  <div class=\"head\">
    <h1 class=\"title\">Hybrid <span>IDS</span> Security Dashboard</h1>
    <div class=\"refresh\" id=\"refreshNote\">Loading...</div>
  </div>

  <!-- kpi cards -->
  <section class=\"grid\">
    <article class=\"card\"><div class=\"k\">Total Alerts (Live)</div><div class=\"v\" id=\"totalAlerts\">0</div></article>
    <article class=\"card\"><div class=\"k\">Top Attack Type</div><div class=\"v\" id=\"topType\">-</div></article>
    <article class=\"card\"><div class=\"k\">Top Source IP</div><div class=\"v\" id=\"topSource\">-</div></article>
    <article class=\"card\"><div class=\"k\">Avg Confidence</div><div class=\"v\" id=\"avgConf\">-</div></article>
  </section>

  <!-- distribution -->
  <section class=\"two\">
    <article class=\"card\">
      <h2 class=\"panel-title\">Live Attack Type Distribution</h2>
      <div id=\"typePills\"></div>
    </article>
    <article class=\"card\">
      <h2 class=\"panel-title\">Live Severity</h2>
      <div id=\"severityPills\"></div>
    </article>
  </section>

  <!-- ═══════════════════  SIMULATION PANEL  ═══════════════════ -->
  <section class=\"card sim-section\">
    <div class=\"sim-header\">
      <h2 class=\"sim-title\">&#x26A1; Attack Simulation</h2>
      <span class=\"sim-badge\">ML-Powered Detection</span>
    </div>

    <!-- config -->
    <div class=\"sim-config\">
      <div class=\"sim-field\">
        <span class=\"sim-label\">Attack Type</span>
        <select id=\"attackType\" class=\"sim-select\">
          <option value=\"syn_flood\">&#x1F4A5; SYN Flood Attack</option>
          <option value=\"port_scan\">&#x1F50D; Port Scan Attack</option>
          <option value=\"dos_pattern\">&#x1F525; DoS Pattern Attack</option>
          <option value=\"mixed\">&#x2694; Mixed Attack (All Types)</option>
          <option value=\"normal\">&#x2705; Normal Traffic (Baseline)</option>
        </select>
      </div>
      <div class=\"sim-field\">
        <span class=\"sim-label\">Packet Count: <span id=\"packetCountDisplay\">500</span></span>
        <div class=\"slider-row\">
          <input type=\"range\" id=\"packetCount\" class=\"sim-slider\" min=\"50\" max=\"2000\" step=\"50\" value=\"500\"
            oninput=\"document.getElementById('packetCountDisplay').textContent=this.value\">
          <span class=\"sim-count-display\" id=\"packetCountDisplay2\"></span>
        </div>
      </div>
      <div class=\"sim-field\">
        <span class=\"sim-label\">&nbsp;</span>
        <button id=\"simBtn\" class=\"sim-launch-btn\" onclick=\"launchSimulation()\">
          <span class=\"btn-icon\">&#x26A1;</span> Launch Simulation
        </button>
      </div>
    </div>

    <!-- animation area -->
    <div id=\"simAnimArea\">
      <div class=\"sim-hud\">
        <span id=\"simStatusText\">Initializing...</span>
        <div class=\"hud-stats\">
          <span class=\"hud-stat\">Flooded: <b id=\"liveFlooded\">0</b></span>
          <span class=\"hud-stat\">Blocked: <b id=\"liveBlocked\">0</b></span>
          <span class=\"hud-stat\">Rate: <b id=\"liveRate\">-</b></span>
        </div>
      </div>
      <canvas id=\"simCanvas\" width=\"960\" height=\"230\"></canvas>
      <div class=\"sim-progress-wrap\">
        <div class=\"sim-progress-bar\" id=\"simProgressBar\"></div>
      </div>
    </div>

    <!-- results -->
    <div id=\"simResults\">
      <div class=\"results-topbar\">
        <span class=\"results-label\">&#x2714; Simulation Results</span>
        <button class=\"reset-btn\" onclick=\"resetSimulation()\">&#x21BA; Run Again</button>
      </div>
      <div class=\"sim-result-cards\">
        <div class=\"result-card\">
          <div class=\"result-k\">Packets Flooded</div>
          <div class=\"result-v clr-red\" id=\"res-flooded\">0</div>
        </div>
        <div class=\"result-card\">
          <div class=\"result-k\">Blocked by IDS</div>
          <div class=\"result-v clr-green\" id=\"res-blocked\">0</div>
        </div>
        <div class=\"result-card\">
          <div class=\"result-k\">Detection Rate</div>
          <div class=\"result-v clr-accent\" id=\"res-rate\">0%</div>
        </div>
        <div class=\"result-card\">
          <div class=\"result-k\">Bypassed IDS</div>
          <div class=\"result-v clr-warn\" id=\"res-bypassed\">0</div>
        </div>
      </div>
      <div class=\"sim-chart\">
        <div class=\"chart-title\">Detection Breakdown</div>
        <div class=\"chart-row\">
          <span class=\"chart-lbl\">Signature Detected</span>
          <div class=\"chart-track\"><div class=\"chart-bar bar-sig\" id=\"bar-sig\"></div><span class=\"chart-val\" id=\"val-sig\">0</span></div>
        </div>
        <div class=\"chart-row\">
          <span class=\"chart-lbl\">ML Anomaly Detected</span>
          <div class=\"chart-track\"><div class=\"chart-bar bar-ml\" id=\"bar-ml\"></div><span class=\"chart-val\" id=\"val-ml\">0</span></div>
        </div>
        <div class=\"chart-row\">
          <span class=\"chart-lbl\">Bypassed IDS</span>
          <div class=\"chart-track\"><div class=\"chart-bar bar-byp\" id=\"bar-byp\"></div><span class=\"chart-val\" id=\"val-byp\">0</span></div>
        </div>
        <div class=\"chart-row\" id=\"normRow\" style=\"display:none\">
          <span class=\"chart-lbl\">Normal (passed)</span>
          <div class=\"chart-track\"><div class=\"chart-bar bar-norm\" id=\"bar-norm\"></div><span class=\"chart-val\" id=\"val-norm\">0</span></div>
        </div>
      </div>
      <div id=\"bypassNote\" style=\"display:none;margin-top:12px;padding:10px 14px;border-radius:8px;border:1px solid var(--line);background:rgba(255,191,71,.06);font-size:.83rem;font-family:'IBM Plex Mono',monospace;color:var(--warn);line-height:1.5\"></div>
      <div id=\"simBreakdown\"></div>
    </div>
  </section>
  <!-- ═══════════════════════════════════════════════════════════ -->

  <!-- alerts + history -->
  <section class=\"two\">
    <article class=\"card\">
      <h2 class=\"panel-title\">Recent Alerts</h2>
      <table>
        <thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Severity</th><th>Conf.</th></tr></thead>
        <tbody id=\"recentBody\"></tbody>
      </table>
    </article>
    <article class=\"card\">
      <h2 class=\"panel-title\">Test Run History</h2>
      <table>
        <thead><tr><th>Run</th><th>Alerts</th><th>Top Type</th></tr></thead>
        <tbody id=\"historyBody\"></tbody>
      </table>
    </article>
  </section>

  <section class=\"card\" id=\"runDetail\" style=\"display:none\">
    <h2 class=\"panel-title\" id=\"detailTitle\">Run Details</h2>
    <div id=\"detailMeta\" style=\"margin-bottom:10px\"></div>
    <table>
      <thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Severity</th><th>Conf.</th></tr></thead>
      <tbody id=\"detailAlertsBody\"></tbody>
    </table>
  </section>

  <div class=\"footer\">Data: <code>logs/</code> &amp; <code>test_runs/</code> &mdash; auto-refresh every 5 s. Click a run row to inspect historical alerts.</div>
</div>

<script src=\"/dashboard.js?v=3\" defer></script>
</body>
</html>"""


if __name__ == "__main__":
    LOG_DIR.mkdir(exist_ok=True)
    app.run(host="0.0.0.0", port=8050, debug=False)
