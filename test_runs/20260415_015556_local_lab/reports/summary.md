# Automated IDS Test Report

- Run directory: `/home/cyberdude/Documents/Projects/ids/Major_Project/test_runs/20260415_015556_local_lab`
- Interface: `wlp0s20f3`
- Target IP: `10.196.211.124`
- Port scan range: `1-300`
- SYN flood target port: `80`
- SYN flood packets: `3000`

## Results
- Total alerts: `83`
- Attack types: `{'ML anomaly': 56, 'Port scan': 27}`
- Top source IPs: `[('192.168.1.14', 36), ('40.79.173.40', 31), ('140.82.112.21', 15), ('148.113.9.188', 1)]`
- Severity counts: `{'MEDIUM': 56, 'HIGH': 27}`
- Confidence stats: `{'count': 83, 'min': 0.900945, 'max': 1.0, 'avg': 0.954290108433735}`

## Artifacts
- IDS console output: `/home/cyberdude/Documents/Projects/ids/Major_Project/test_runs/20260415_015556_local_lab/logs/ids_stdout.log`
- Alert log: `/home/cyberdude/Documents/Projects/ids/Major_Project/test_runs/20260415_015556_local_lab/logs/alerts.log`
- Alert JSON: `/home/cyberdude/Documents/Projects/ids/Major_Project/test_runs/20260415_015556_local_lab/logs/alerts.json`
- Packet evidence (pcap): `/home/cyberdude/Documents/Projects/ids/Major_Project/test_runs/20260415_015556_local_lab/evidence/capture.pcap`
