import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, send  # type: ignore


BASE_DIR = Path(__file__).resolve().parent
IDS_SCRIPT = BASE_DIR / "hybrid_ids_realtime.py"
LOG_DIR = BASE_DIR / "logs"
ALERTS_LOG = LOG_DIR / "alerts.log"
ALERTS_JSON = LOG_DIR / "alerts.json"
RUNS_DIR = BASE_DIR / "test_runs"


def require_root() -> None:
    if os.geteuid() != 0:
        print("This script needs root privileges for sniffing/sending packets.")
        print("Run with: sudo /path/to/python automated_ids_test.py ...")
        sys.exit(1)


def ensure_inputs() -> None:
    missing = []
    if not IDS_SCRIPT.exists():
        missing.append(str(IDS_SCRIPT))
    if missing:
        print("Missing required files:")
        for path in missing:
            print(f"- {path}")
        sys.exit(1)


def create_run_dirs(tag: str | None) -> Path:
    RUNS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_name = f"{ts}_{tag}" if tag else ts
    run_dir = RUNS_DIR / run_name
    (run_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)
    return run_dir


def reset_live_logs() -> None:
    LOG_DIR.mkdir(exist_ok=True)
    ALERTS_LOG.write_text("", encoding="utf-8")
    ALERTS_JSON.write_text("[]\n", encoding="utf-8")


def start_ids_process(iface: str, python_bin: str) -> subprocess.Popen[str]:
    cmd = [python_bin, str(IDS_SCRIPT), "--iface", iface]
    return subprocess.Popen(
        cmd,
        cwd=str(BASE_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def start_tcpdump(iface: str, pcap_path: Path) -> subprocess.Popen[str]:
    cmd = [
        "tcpdump",
        "-i",
        iface,
        "-nn",
        "-w",
        str(pcap_path),
        "ip",
    ]
    return subprocess.Popen(
        cmd,
        cwd=str(BASE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def run_port_scan(target_ip: str, start_port: int, end_port: int, delay_s: float) -> None:
    print(f"[traffic] Port scan simulation on {target_ip}:{start_port}-{end_port}")
    for p in range(start_port, end_port + 1):
        send(IP(dst=target_ip) / TCP(sport=45000 + (p % 1000), dport=p, flags="S"), verbose=0)
        if delay_s > 0:
            time.sleep(delay_s)


def run_syn_flood(target_ip: str, target_port: int, packets: int, delay_s: float) -> None:
    print(f"[traffic] SYN flood simulation to {target_ip}:{target_port} packets={packets}")
    for i in range(packets):
        sport = 40000 + (i % 20000)
        send(IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S"), verbose=0)
        if delay_s > 0:
            time.sleep(delay_s)


def stop_process(proc: subprocess.Popen[str], name: str, timeout_s: float = 8.0) -> None:
    if proc.poll() is not None:
        return

    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()


def collect_ids_stdout(ids_proc: subprocess.Popen[str], outfile: Path) -> None:
    lines: list[str] = []
    if ids_proc.stdout is not None:
        for line in ids_proc.stdout:
            lines.append(line)

    outfile.write_text("".join(lines), encoding="utf-8")


def load_alerts() -> list[dict[str, Any]]:
    if not ALERTS_JSON.exists():
        return []
    try:
        data = json.loads(ALERTS_JSON.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
    except json.JSONDecodeError:
        return []
    return []


def build_summary(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    type_counter = Counter(a.get("attack_type", "unknown") for a in alerts)
    src_counter = Counter(a.get("source_ip", "unknown") for a in alerts)
    sever_counter = Counter(a.get("severity", "unknown") for a in alerts)

    confidences: list[float] = []
    for a in alerts:
        try:
            confidences.append(float(a.get("confidence", 0.0)))
        except (TypeError, ValueError):
            continue

    confidence_stats = {
        "count": len(confidences),
        "min": min(confidences) if confidences else None,
        "max": max(confidences) if confidences else None,
        "avg": (sum(confidences) / len(confidences)) if confidences else None,
    }

    return {
        "total_alerts": len(alerts),
        "by_attack_type": dict(type_counter),
        "top_source_ips": src_counter.most_common(10),
        "by_severity": dict(sever_counter),
        "confidence": confidence_stats,
    }


def write_report(run_dir: Path, args: argparse.Namespace, summary: dict[str, Any]) -> None:
    summary_json_path = run_dir / "reports" / "summary.json"
    summary_md_path = run_dir / "reports" / "summary.md"

    summary_json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    md = [
        "# Automated IDS Test Report",
        "",
        f"- Run directory: `{run_dir}`",
        f"- Interface: `{args.iface}`",
        f"- Target IP: `{args.target_ip}`",
        f"- Port scan range: `{args.scan_start}-{args.scan_end}`",
        f"- SYN flood target port: `{args.flood_port}`",
        f"- SYN flood packets: `{args.flood_packets}`",
        "",
        "## Results",
        f"- Total alerts: `{summary.get('total_alerts', 0)}`",
        f"- Attack types: `{summary.get('by_attack_type', {})}`",
        f"- Top source IPs: `{summary.get('top_source_ips', [])}`",
        f"- Severity counts: `{summary.get('by_severity', {})}`",
        f"- Confidence stats: `{summary.get('confidence', {})}`",
        "",
        "## Artifacts",
        f"- IDS console output: `{run_dir / 'logs' / 'ids_stdout.log'}`",
        f"- Alert log: `{run_dir / 'logs' / 'alerts.log'}`",
        f"- Alert JSON: `{run_dir / 'logs' / 'alerts.json'}`",
        f"- Packet evidence (pcap): `{run_dir / 'evidence' / 'capture.pcap'}`",
    ]
    summary_md_path.write_text("\n".join(md) + "\n", encoding="utf-8")


def copy_artifacts(run_dir: Path) -> None:
    if ALERTS_LOG.exists():
        shutil.copy2(ALERTS_LOG, run_dir / "logs" / "alerts.log")
    if ALERTS_JSON.exists():
        shutil.copy2(ALERTS_JSON, run_dir / "logs" / "alerts.json")


def run_workflow(args: argparse.Namespace) -> int:
    require_root()
    ensure_inputs()

    run_dir = create_run_dirs(args.tag)
    pcap_file = run_dir / "evidence" / "capture.pcap"

    print(f"[info] Run directory: {run_dir}")
    reset_live_logs()

    python_bin = args.python_bin or sys.executable
    ids_proc = start_ids_process(args.iface, python_bin)
    tcpdump_proc = start_tcpdump(args.iface, pcap_file)

    print("[info] IDS started. Warming up...")
    time.sleep(args.warmup_seconds)

    try:
        run_port_scan(args.target_ip, args.scan_start, args.scan_end, args.scan_delay)
        time.sleep(args.pause_between_phases)
        run_syn_flood(args.target_ip, args.flood_port, args.flood_packets, args.flood_delay)
        time.sleep(args.cooldown_seconds)
    finally:
        stop_process(ids_proc, "ids")
        stop_process(tcpdump_proc, "tcpdump")

    collect_ids_stdout(ids_proc, run_dir / "logs" / "ids_stdout.log")
    copy_artifacts(run_dir)

    alerts = load_alerts()
    summary = build_summary(alerts)
    write_report(run_dir, args, summary)

    print("[done] Test run completed.")
    print(f"[done] Total alerts: {summary.get('total_alerts', 0)}")
    print(f"[done] Results saved to: {run_dir}")
    return 0


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Automated end-to-end IDS test harness")
    parser.add_argument("--iface", required=True, help="Network interface for IDS and tcpdump")
    parser.add_argument("--target-ip", required=True, help="Lab target IP to send test traffic")
    parser.add_argument("--python-bin", default=None, help="Python interpreter to run IDS script")
    parser.add_argument("--tag", default=None, help="Optional tag for the run directory name")

    parser.add_argument("--scan-start", type=int, default=1, help="Port scan start port")
    parser.add_argument("--scan-end", type=int, default=300, help="Port scan end port")
    parser.add_argument("--scan-delay", type=float, default=0.0, help="Delay between scan packets")

    parser.add_argument("--flood-port", type=int, default=80, help="Destination port for SYN flood")
    parser.add_argument("--flood-packets", type=int, default=3000, help="Number of SYN packets")
    parser.add_argument("--flood-delay", type=float, default=0.0, help="Delay between flood packets")

    parser.add_argument("--warmup-seconds", type=float, default=3.0, help="IDS warm-up time")
    parser.add_argument("--pause-between-phases", type=float, default=1.0, help="Pause between scan and flood")
    parser.add_argument("--cooldown-seconds", type=float, default=3.0, help="Cooldown before stopping IDS")

    return parser


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()

    if args.scan_end < args.scan_start:
        parser.error("--scan-end must be greater than or equal to --scan-start")

    sys.exit(run_workflow(args))


if __name__ == "__main__":
    main()
