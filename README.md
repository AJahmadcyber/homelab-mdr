# Homelab MDR — SOC Detection Engineering Lab

> An open-source detection-and-response home lab: endpoint and network telemetry feeding a Wazuh SIEM, Suricata IDS on pfSense, and custom detection rules mapped to MITRE ATT&CK — built and debugged end to end.

**Repo:** https://github.com/AJahmadcyber/homelab-mdr

---

## Overview

A hands-on lab demonstrating detection engineering with open-source tools: collecting Windows and Linux telemetry into a SIEM, running a network IDS at the firewall, writing custom detection rules, mapping every detection to MITRE ATT&CK, and hardening the monitoring stack itself. Everything is version-controlled, with each build phase documented alongside its design rationale.

The lab is built in phases, infrastructure and visibility first, then detection content, then response automation. Phases 1–5 are implemented and working; Phases 6–7 are the planned roadmap.

---

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 1 — Foundation | VMs, network, Docker, Wazuh stack (Manager + Indexer + Dashboard) | ✅ Implemented |
| 2 — Hardening | UFW, fail2ban, SSH hardening, index retention | ✅ Implemented |
| 3 — Windows telemetry | Sysmon (sysmon-modular), PowerShell Script Block Logging (4104), ASR, Defender → Wazuh agent | ✅ Implemented |
| 4 — Network re-architecture | pfSense in-path gateway, LAN segmentation | ✅ Implemented |
| 4.5 — SIEM self-monitoring | Agent on the SIEM + auditd, tamper detection for the monitoring stack | ✅ Implemented |
| 5 — Network IDS | Suricata on pfSense + Suricata→Wazuh pipeline, MITRE-mapped alerts | ✅ Implemented |
| 6 — SOAR | TheHive 5 + Cassandra + Cortex + n8n, automated response with safety controls | ⏳ Roadmap |
| 7 — Threat simulation | Ransomware profile (T1486) run end to end against the stack | ⏳ Roadmap |

---

## Architecture

pfSense sits in-path as the gateway, so all routed traffic passes through it — the natural place for a network IDS. Endpoints report host telemetry to the SIEM; Suricata reports network detections. Detection is layered on purpose: no single sensor sees everything.

| VM | OS | RAM | Role | IP |
| --- | --- | --- | --- | --- |
| `siem` | Ubuntu Server 22.04 | 7 GB | Wazuh Manager + Indexer + Dashboard (Docker Compose) | 10.10.10.10 |
| `win-ep` | Windows 10 | 2 GB | Endpoint: Sysmon + ASR + Wazuh agent | 10.10.10.20 |
| `pfSense` | pfSense 2.7.2 | 2 GB | In-path gateway + Suricata IDS | 10.10.10.1 |
| Host | Windows + VirtualBox | 16 GB | Hypervisor | 10.10.10.2 |

Network: LAN `10.10.10.0/24`, pfSense in-path (WAN via NAT).

---

## Detection engineering

Every custom rule is mapped to a MITRE ATT&CK technique, with IDs namespaced by phase.

**Custom detections (rules I wrote):**

| Technique | Detection | Layer |
| --- | --- | --- |
| T1046 — Network Service Discovery | Custom Suricata SYN-scan signatures → Wazuh rules 100300–100303 | Network |
| T1059.001 — PowerShell | Script Block Logging (Event 4104) → Wazuh rules 100100–100102 | Endpoint |
| T1562.001 / T1611 / T1610 / T1548.003 / T1098 / T1543.002 / T1562.004 | SIEM self-monitoring (auditd) → Wazuh rules 100200–100205 | SIEM host |

**Extended by Wazuh's community ruleset** (enabled, not authored here): broad Sysmon/Windows coverage — process creation, image loads, file drops, LSASS access, WinRM/Invoke-Command lateral movement, scheduled tasks, and more.

### The Suricata → Wazuh pipeline (Phase 5)

```
Suricata eve.json (pfSense)
  → edge filter: event_type=alert only (protocol logs dropped at the sensor)
  → SSH stream, siem PULLs via a systemd service (Restart=always)
  → /var/log/suricata-pfsense/eve-alerts.json  (Docker bind-mount into Wazuh)
  → Wazuh JSON decoder → custom rules 100300–100303 → MITRE T1046
```

The collector runs as a systemd service on the SIEM (`Restart=always`), so it self-recovers from dropped connections, host suspend, or crashes — no manual watchdog.

---

## Key design decisions

- **Detection before response.** Phase 5 is IDS-only by design; automated blocking is reserved for the SOAR phase with safety controls (block TTL, RFC1918 allowlist, circuit breaker).
- **IDS, not inline IPS (for now).** Inline blocking is a single point of failure; start in detection, baseline, then promote high-confidence signatures. Blocking will run through the SOAR path — auditable and reversible.
- **North-south vs east-west.** Suricata sees routed traffic only; same-subnet lateral movement is covered host-side by Wazuh + Sysmon. Layered visibility, not one sensor.
- **Edge filtering.** Only actionable alerts are shipped to the SIEM; raw protocol logs stay at the sensor. Keeps the SIEM focused and storage bounded.
- **Monitor the monitor.** The SIEM is a high-value target, so tampering with the monitoring stack itself is detected (Phase 4.5).
- **Resilient collection.** systemd service supervision instead of a manual loop, so the pipeline survives suspend/disconnect.

Full rationale in [`docs/`](docs/).

---

## Repository layout

```
homelab-mdr/
├── README.md
├── homelab-mdr-session-log.md          # phase-by-phase build journal
├── detection/
│   ├── wazuh-rules/                     # custom Wazuh XML rules (100100–100303)
│   │   ├── 9997-suricata-mitre.xml
│   │   ├── 9998-siem-self-monitoring.xml
│   │   └── 9999-windows-powershell.xml
│   ├── suricata-rules/                  # custom Suricata signatures
│   │   ├── custom.rules                 # SID 1000001/1000002 (T1046)
│   │   └── disablesid.conf
│   └── pipeline/                        # Suricata → Wazuh collector
│       ├── suricata-collector.sh        # PULL collector (runs on siem)
│       └── suricata-collector.service   # systemd unit (Restart=always)
└── docs/
    ├── phase5-session2-pipeline.md
    ├── phase5-stream-stability-pull-model.md
    └── evidence/                        # screenshots per phase
```

---

## Roadmap

- **Phase 6 — SOAR:** TheHive 5 (case management) + Cortex (observable enrichment) + n8n (orchestration). Alert → auto-create case → enrich → score → automated containment via the pfSense API, gated by block TTL, an RFC1918 allowlist, and a circuit breaker.
- **Phase 7 — Threat simulation:** a ransomware profile (T1486 and the surrounding chain) run against the full stack to validate detections end to end.
- **Near-term:** protocol-log threat hunting (DNS tunneling, JA3-based C2), index retention policy, and promoting high-confidence signatures to inline IPS.

---

## License

MIT — see [`LICENSE`](LICENSE).
