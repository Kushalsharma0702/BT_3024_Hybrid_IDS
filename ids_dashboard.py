import json
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

app = Flask(__name__)

ALERT_JSON_PATTERN = re.compile(r"ALERT\s+(\{.*\})")


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
        rows.append(
            {
                "run_id": run_id,
                "time": pretty_time,
                "path": str(run_dir),
                "total_alerts": int(summary.get("total_alerts", 0) or 0),
                "by_attack_type": summary.get("by_attack_type", {}),
                "by_severity": summary.get("by_severity", {}),
                "confidence": summary.get("confidence", {}),
            }
        )

    return rows


@app.get("/api/live")
def api_live() -> Any:
    alerts = _get_live_alerts()
    summary = _summarize_alerts(alerts)

    limit = request.args.get("limit", default=100, type=int)
    if limit is None or limit <= 0:
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

    return jsonify(
        {
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
        }
    )


@app.get("/")
def index() -> str:
    # Purposefully bold visual language for readability in SOC-like workflows.
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
      --bg: #0a1118;
      --panel: #0f1a24;
      --panel-2: #132434;
      --line: #2a4258;
      --text: #d8e6f2;
      --muted: #91a9bc;
      --ok: #3ddc97;
      --warn: #ffbf47;
      --high: #ff5d73;
      --accent: #40c4ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--text);
      font-family: 'Space Grotesk', sans-serif;
      background:
        radial-gradient(1200px 600px at 85% -10%, #1f3f5f 0%, rgba(31,63,95,0) 70%),
        radial-gradient(900px 500px at 0% 0%, #19344b 0%, rgba(25,52,75,0) 65%),
        var(--bg);
      min-height: 100vh;
    }
    .wrap {
      width: min(1200px, 96vw);
      margin: 0 auto;
      padding: 22px 0 28px;
    }
    .head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
    }
    .title {
      margin: 0;
      font-weight: 700;
      letter-spacing: 0.4px;
      font-size: clamp(1.2rem, 2.5vw, 2rem);
    }
    .refresh {
      color: var(--muted);
      font-size: .92rem;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .card {
      border: 1px solid var(--line);
      background: linear-gradient(180deg, var(--panel), var(--panel-2));
      border-radius: 14px;
      padding: 14px;
      box-shadow: 0 10px 24px rgba(0,0,0,0.18);
      animation: rise .35s ease;
    }
    .k { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .7px; }
    .v { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }

    .two {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 12px;
      margin-bottom: 12px;
    }
    .panel-title { margin: 0 0 10px; font-size: 1rem; }
    .pill {
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 8px;
      margin: 0 6px 6px 0;
      font-size: .82rem;
      font-family: 'IBM Plex Mono', monospace;
      color: var(--text);
      background: rgba(255,255,255,0.03);
    }
    .pill.high { border-color: #7c3040; color: #ffd6dc; }
    .pill.medium { border-color: #7b5e2f; color: #ffe8bf; }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: .9rem;
      font-family: 'IBM Plex Mono', monospace;
    }
    th, td {
      text-align: left;
      padding: 8px 7px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      vertical-align: top;
      word-break: break-word;
    }
    th { color: var(--muted); font-weight: 500; }

    .history-row { cursor: pointer; }
    .history-row:hover { background: rgba(64,196,255,0.08); }

    .footer {
      margin-top: 10px;
      font-size: .82rem;
      color: var(--muted);
      font-family: 'IBM Plex Mono', monospace;
    }

    @keyframes rise {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @media (max-width: 980px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .two { grid-template-columns: 1fr; }
    }
    @media (max-width: 560px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"head\">
      <h1 class=\"title\">Hybrid IDS Security Dashboard</h1>
      <div class=\"refresh\" id=\"refreshNote\">Refreshing...</div>
    </div>

    <section class=\"grid\">
      <article class=\"card\"><div class=\"k\">Total Alerts (Live)</div><div class=\"v\" id=\"totalAlerts\">0</div></article>
      <article class=\"card\"><div class=\"k\">Top Attack Type</div><div class=\"v\" id=\"topType\">-</div></article>
      <article class=\"card\"><div class=\"k\">Top Source IP</div><div class=\"v\" id=\"topSource\">-</div></article>
      <article class=\"card\"><div class=\"k\">Average Confidence</div><div class=\"v\" id=\"avgConf\">-</div></article>
    </section>

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

    <section class=\"two\">
      <article class=\"card\">
        <h2 class=\"panel-title\">Recent Alerts</h2>
        <table>
          <thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Severity</th><th>Confidence</th></tr></thead>
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
      <div id=\"detailMeta\"></div>
      <table>
        <thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Severity</th><th>Confidence</th></tr></thead>
        <tbody id=\"detailAlertsBody\"></tbody>
      </table>
    </section>

    <div class=\"footer\">Data source: <code>logs/</code> + <code>test_runs/</code>. Click a run row to inspect historical alerts.</div>
  </div>

  <script>
    function topKey(obj) {
      const entries = Object.entries(obj || {});
      if (!entries.length) return '-';
      entries.sort((a,b) => b[1]-a[1]);
      return entries[0][0];
    }

    function renderPills(el, map, clsRule) {
      const entries = Object.entries(map || {});
      if (!entries.length) {
        el.innerHTML = '<span class="pill">No data</span>';
        return;
      }
      el.innerHTML = entries
        .sort((a,b) => b[1]-a[1])
        .map(([k,v]) => `<span class="pill ${clsRule(k)}">${k}: ${v}</span>`)
        .join('');
    }

    async function fetchJSON(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    }

    async function refreshLive() {
      const data = await fetchJSON('/api/live?limit=120');
      const s = data.summary || {};
      const alerts = data.recent_alerts || [];

      document.getElementById('totalAlerts').textContent = s.total_alerts ?? 0;
      document.getElementById('topType').textContent = topKey(s.by_attack_type);
      const topSource = (s.top_source_ips && s.top_source_ips.length) ? s.top_source_ips[0][0] : '-';
      document.getElementById('topSource').textContent = topSource;

      const avg = s.confidence && s.confidence.avg;
      document.getElementById('avgConf').textContent = (typeof avg === 'number') ? avg.toFixed(4) : '-';

      renderPills(document.getElementById('typePills'), s.by_attack_type, () => '');
      renderPills(
        document.getElementById('severityPills'),
        s.by_severity,
        (k) => String(k).toUpperCase() === 'HIGH' ? 'high' : 'medium'
      );

      const body = document.getElementById('recentBody');
      body.innerHTML = alerts.slice(0, 40).map(a => `
        <tr>
          <td>${a.timestamp || '-'}</td>
          <td>${a.source_ip || '-'}</td>
          <td>${a.attack_type || '-'}</td>
          <td>${a.severity || '-'}</td>
          <td>${(a.confidence ?? '-')}</td>
        </tr>
      `).join('');
    }

    async function refreshHistory() {
      const data = await fetchJSON('/api/history');
      const runs = data.runs || [];
      const body = document.getElementById('historyBody');
      body.innerHTML = runs.map(r => {
        const types = Object.entries(r.by_attack_type || {}).sort((a,b) => b[1]-a[1]);
        const topType = types.length ? types[0][0] : '-';
        return `
          <tr class="history-row" data-run="${r.run_id}">
            <td>${r.time}</td>
            <td>${r.total_alerts}</td>
            <td>${topType}</td>
          </tr>
        `;
      }).join('');

      [...document.querySelectorAll('.history-row')].forEach(row => {
        row.addEventListener('click', () => loadRun(row.dataset.run));
      });
    }

    async function loadRun(runId) {
      const data = await fetchJSON(`/api/run/${runId}`);
      const summary = data.summary || {};
      const recent = data.recent_alerts || [];

      document.getElementById('runDetail').style.display = 'block';
      document.getElementById('detailTitle').textContent = `Run Details: ${runId}`;
      document.getElementById('detailMeta').innerHTML = `
        <span class="pill">Total alerts: ${summary.total_alerts ?? 0}</span>
        <span class="pill">Types: ${JSON.stringify(summary.by_attack_type || {})}</span>
        <span class="pill">Severity: ${JSON.stringify(summary.by_severity || {})}</span>
      `;

      document.getElementById('detailAlertsBody').innerHTML = recent.slice(0, 80).map(a => `
        <tr>
          <td>${a.timestamp || '-'}</td>
          <td>${a.source_ip || '-'}</td>
          <td>${a.attack_type || '-'}</td>
          <td>${a.severity || '-'}</td>
          <td>${a.confidence ?? '-'}</td>
        </tr>
      `).join('');
    }

    async function boot() {
      try {
        await Promise.all([refreshLive(), refreshHistory()]);
        document.getElementById('refreshNote').textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
      } catch (err) {
        document.getElementById('refreshNote').textContent = `Refresh failed: ${err.message}`;
      }
    }

    boot();
    setInterval(boot, 5000);
  </script>
</body>
</html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=False)
